//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	goRuntime "runtime"
	"syscall"
	"testing"
	"time"

	commonEBPF "github.com/MiChongs/sing-ebpf"
	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

const socketAssignTestListenerPort = 23457

var socketAssignTestDestination = netip.MustParseAddrPort("203.0.113.10:443")

// These tests drive real TCP connections through the TC socket-assignment
// paths. The consumer reads a TCP assignment once, when it accepts the
// connection, and removes it; the established packets that follow must still
// reach the accepted socket and must not recreate the consumed entry.

func TestTCSharedSocketAssignmentDeliversEstablishedTCP(t *testing.T) {
	enterTestNetworkNamespace(t)
	setLoopbackUp(t)
	backend := newSocketAssignTestBackend(t, false)
	listener := listenTransparentTCP(t, backend)

	router, peer := createTestVethPair(t, "sbsatcp0", "sbsatcp1")
	addTestAddress(t, router, "10.251.0.1/24")
	client := startTestNetworkNamespaceWorker(t)
	if err := netlink.LinkSetNsFd(peer, int(client.namespace.Fd())); err != nil {
		t.Fatalf("move %s into the client namespace: %v", peer.Attrs().Name, err)
	}
	clientMAC := peer.Attrs().HardwareAddr
	client.run(t, func() error {
		if err := setLinkUpByName("lo"); err != nil {
			return err
		}
		link, err := netlink.LinkByName("sbsatcp1")
		if err != nil {
			return err
		}
		if err = netlink.LinkSetUp(link); err != nil {
			return err
		}
		address, err := netlink.ParseAddr("10.251.0.2/24")
		if err != nil {
			return err
		}
		if err = netlink.AddrAdd(link, address); err != nil {
			return err
		}
		return netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        net.ParseIP("10.251.0.1"),
		})
	})

	attachSocketAssignTestInterface(t, backend, router, tcInterfaceRole{shared: true})
	startSocketAssignTestRouting(t, backend)

	var conn net.Conn
	client.run(t, func() error {
		var err error
		conn, err = (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp4", socketAssignTestDestination.String())
		return err
	})
	t.Cleanup(func() { _ = conn.Close() })
	accepted := acceptSocketAssignTestConnection(t, listener)

	source := netip.MustParseAddrPort(conn.LocalAddr().String())
	assignment, err := backend.LookupAssignment(commonEBPF.ProtocolTCP, source, socketAssignTestDestination, 0, true)
	if err != nil {
		t.Fatalf("look up the assignment recorded during connection setup: %v", err)
	}
	if assignment.Path != commonEBPF.TCPathShared || assignment.InterfaceIndex != uint32(router.Attrs().Index) ||
		assignment.SourceMACValid == 0 || !bytes.Equal(assignment.SourceMAC[:], clientMAC) {
		t.Fatalf("assignment = %+v, want the shared path on %s from %s", assignment, router.Attrs().Name, clientMAC)
	}

	exchangeSocketAssignTestMessages(t, conn, accepted)
	requireSocketAssignmentConsumed(t, backend, source)
	requireNoTCAssignmentFailures(t, backend)
}

func TestTCLocalSocketAssignmentDeliversEstablishedTCP(t *testing.T) {
	enterTestNetworkNamespace(t)
	setLoopbackUp(t)
	backend := newSocketAssignTestBackend(t, true)
	listener := listenTransparentTCP(t, backend)

	// The default interface has a gateway that answers no ARP; a permanent
	// neighbour entry lets the connection's packets reach TC egress.
	uplink, gateway := createTestVethPair(t, "sbsatcp2", "sbsatcp3")
	addTestAddress(t, uplink, "10.252.0.1/24")
	if err := netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    uplink.Attrs().Index,
		Family:       unix.AF_INET,
		State:        netlink.NUD_PERMANENT,
		IP:           net.ParseIP("10.252.0.2"),
		HardwareAddr: gateway.Attrs().HardwareAddr,
	}); err != nil {
		t.Fatalf("add the gateway neighbour: %v", err)
	}
	_, destinationNetwork, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: uplink.Attrs().Index,
		Dst:       destinationNetwork,
		Gw:        net.ParseIP("10.252.0.2"),
	}); err != nil {
		t.Fatalf("route the destination through %s: %v", uplink.Attrs().Name, err)
	}

	dataPlane := &tcDataPlane{backend: backend, priority: 2}
	delivery, err := dataPlane.createTCDeliveryLink()
	if err != nil {
		t.Fatalf("create the delivery link: %v", err)
	}
	t.Cleanup(func() { _ = delivery.Close() })
	attachSocketAssignTestInterface(t, backend, uplink, tcInterfaceRole{local: true})
	startSocketAssignTestRouting(t, backend)

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp4", socketAssignTestDestination.String())
	if err != nil {
		t.Fatalf("connect through the local path: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	accepted := acceptSocketAssignTestConnection(t, listener)

	source := netip.MustParseAddrPort(conn.LocalAddr().String())
	assignment, err := backend.LookupAssignment(commonEBPF.ProtocolTCP, source, socketAssignTestDestination, 0, true)
	if err != nil {
		t.Fatalf("look up the assignment recorded during connection setup: %v", err)
	}
	cookie := socketCookie(t, conn)
	if assignment.Path != commonEBPF.TCPathDelivery || assignment.SocketCookie != cookie ||
		assignment.InterfaceIndex != uint32(delivery.delivery.Attrs().Index) {
		t.Fatalf("assignment = %+v, want the delivery path on %s with socket cookie %#x",
			assignment, delivery.deliveryName, cookie)
	}

	exchangeSocketAssignTestMessages(t, conn, accepted)
	requireSocketAssignmentConsumed(t, backend, source)
	requireNoTCAssignmentFailures(t, backend)
}

func newSocketAssignTestBackend(t *testing.T, local bool) *commonEBPF.TCBackend {
	t.Helper()
	policy, err := commonEBPF.CompileActionPolicy(commonEBPF.ActionPolicy{
		EnableTCP: true,
		Local:     commonEBPF.ActionScope{Default: commonEBPF.DecisionIntercept},
		Shared:    commonEBPF.ActionScope{Default: commonEBPF.DecisionIntercept},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{
		ListenerPort: socketAssignTestListenerPort,
		EnableLocal:  local,
		EnableShared: !local,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
		TrackProcess: local,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

func listenTransparentTCP(t *testing.T, backend *commonEBPF.TCBackend) *net.TCPListener {
	t.Helper()
	config := net.ListenConfig{Control: func(_, _ string, conn syscall.RawConn) error {
		var socketErr error
		if err := conn.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		}); err != nil {
			return err
		}
		return socketErr
	}}
	// Go listeners default to MPTCP, and a SOCKMAP accepts only plain TCP.
	config.SetMultipathTCP(false)
	listener, err := config.Listen(context.Background(), "tcp4", fmt.Sprintf("0.0.0.0:%d", socketAssignTestListenerPort))
	if err != nil {
		t.Fatalf("listen on the transparent TCP socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	tcpListener := listener.(*net.TCPListener)
	rawConn, err := tcpListener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var registerErr error
	if err = rawConn.Control(func(fd uintptr) {
		registerErr = backend.RegisterTCPListener(false, int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	if registerErr != nil {
		t.Fatalf("register the transparent listener: %v", registerErr)
	}
	return tcpListener
}

func attachSocketAssignTestInterface(t *testing.T, backend *commonEBPF.TCBackend, link netlink.Link, role tcInterfaceRole) {
	t.Helper()
	name := link.Attrs().Name
	lock, err := acquireTCInterfaceLock(name, link.Attrs().Index)
	if err != nil {
		t.Fatalf("acquire the %s lock: %v", name, err)
	}
	attachment, err := attachTCInterfaceWithLock(
		netlink.LinkByName,
		backend,
		name,
		tcAttachmentState{index: link.Attrs().Index, framing: commonEBPF.TCLinkFramingEthernet, role: role},
		false,
		2,
		lock,
		true,
	)
	if err != nil {
		t.Fatalf("attach %s: %v", name, err)
	}
	t.Cleanup(func() { _ = attachment.Close() })
}

func startSocketAssignTestRouting(t *testing.T, backend *commonEBPF.TCBackend) {
	t.Helper()
	routing, err := startTCPolicyRouting(false)
	if err != nil {
		t.Fatalf("start policy routing: %v", err)
	}
	t.Cleanup(func() { _ = routing.Close() })
	if err = backend.SetRoutingMark(routing.mark); err != nil {
		t.Fatalf("set the routing mark: %v", err)
	}
	if err = backend.Enable(); err != nil {
		t.Fatalf("enable the backend: %v", err)
	}
}

func acceptSocketAssignTestConnection(t *testing.T, listener *net.TCPListener) net.Conn {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept the assigned connection: %v", err)
	}
	t.Cleanup(func() { _ = accepted.Close() })
	if local := netip.MustParseAddrPort(accepted.LocalAddr().String()); local != socketAssignTestDestination {
		t.Fatalf("accepted connection local address = %s, want the original destination %s", local, socketAssignTestDestination)
	}
	return accepted
}

// exchangeSocketAssignTestMessages sends enough established segments in both
// directions that a per-packet assignment refresh would recreate the entry.
func exchangeSocketAssignTestMessages(t *testing.T, conn, accepted net.Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	_ = conn.SetDeadline(deadline)
	_ = accepted.SetDeadline(deadline)
	echoErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(accepted, accepted)
		echoErr <- err
	}()
	reply := make([]byte, 64)
	for index := range 32 {
		message := []byte(fmt.Sprintf("established segment %02d", index))
		if _, err := conn.Write(message); err != nil {
			t.Fatalf("write segment %d: %v", index, err)
		}
		if _, err := io.ReadFull(conn, reply[:len(message)]); err != nil {
			t.Fatalf("read echo %d: %v", index, err)
		}
		if !bytes.Equal(reply[:len(message)], message) {
			t.Fatalf("echo %d = %q, want %q", index, reply[:len(message)], message)
		}
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := <-echoErr; err != nil {
		t.Fatalf("echo the established segments: %v", err)
	}
}

func requireSocketAssignmentConsumed(t *testing.T, backend *commonEBPF.TCBackend, source netip.AddrPort) {
	t.Helper()
	assignment, err := backend.LookupAssignment(commonEBPF.ProtocolTCP, source, socketAssignTestDestination, 0, false)
	if err == nil {
		t.Fatalf("established packets recreated the consumed assignment: %+v", assignment)
	}
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("look up the consumed assignment: %v", err)
	}
}

func requireNoTCAssignmentFailures(t *testing.T, backend *commonEBPF.TCBackend) {
	t.Helper()
	stats, err := backend.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.SocketLookupFailures != 0 || stats.SKAssignFailures != 0 || stats.AssignmentUpdateFailures != 0 {
		t.Fatalf("TC stats = %+v, want no socket-assignment failures", stats)
	}
}

func socketCookie(t *testing.T, conn net.Conn) uint64 {
	t.Helper()
	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cookie uint64
	var cookieErr error
	if err = rawConn.Control(func(fd uintptr) {
		cookie, cookieErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil {
		t.Fatal(err)
	}
	if cookieErr != nil {
		t.Fatalf("read the socket cookie: %v", cookieErr)
	}
	return cookie
}

func setLoopbackUp(t *testing.T) {
	t.Helper()
	if err := setLinkUpByName("lo"); err != nil {
		t.Fatalf("bring up lo: %v", err)
	}
}

func setLinkUpByName(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func addTestAddress(t *testing.T, link netlink.Link, cidr string) {
	t.Helper()
	address, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.AddrAdd(link, address); err != nil {
		t.Fatalf("add %s to %s: %v", cidr, link.Attrs().Name, err)
	}
}

// testNetworkNamespaceWorker runs functions on an OS thread that lives in its
// own network namespace. The thread is never unlocked, so it exits with the
// worker instead of returning to the scheduler in the wrong namespace.
type testNetworkNamespaceWorker struct {
	namespace *os.File
	requests  chan func()
}

func startTestNetworkNamespaceWorker(t *testing.T) *testNetworkNamespaceWorker {
	t.Helper()
	worker := &testNetworkNamespaceWorker{requests: make(chan func())}
	ready := make(chan error, 1)
	go func() {
		goRuntime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ready <- err
			return
		}
		namespace, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			ready <- err
			return
		}
		worker.namespace = namespace
		ready <- nil
		for request := range worker.requests {
			request()
		}
	}()
	if err := <-ready; err != nil {
		t.Skipf("cannot create a client network namespace: %v", err)
	}
	t.Cleanup(func() {
		close(worker.requests)
		_ = worker.namespace.Close()
	})
	return worker
}

func (w *testNetworkNamespaceWorker) run(t *testing.T, request func() error) {
	t.Helper()
	done := make(chan error, 1)
	w.requests <- func() { done <- request() }
	if err := <-done; err != nil {
		t.Fatalf("client namespace: %v", err)
	}
}
