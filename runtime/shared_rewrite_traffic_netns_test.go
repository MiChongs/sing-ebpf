//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	goRuntime "runtime"
	"testing"
	"time"
	"unsafe"

	commonEBPF "github.com/MiChongs/sing-ebpf"
	"github.com/sagernet/netlink"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const sharedRewriteTrafficListenerPort = 23459

var (
	sharedRewriteTrafficTCPDestination = netip.MustParseAddrPort("203.0.113.20:443")
	sharedRewriteTrafficUDPDestination = netip.MustParseAddrPort("203.0.113.20:4433")
	sharedRewriteTrafficTokenPrefix    = netip.MustParsePrefix("127.128.0.0/9")
)

// TestSharedPacketRewriteCarriesTraffic sends real TCP and UDP traffic through
// the shared packet-rewrite programs in both directions. With transmit
// checksum offload disabled on both veth ends, each receiving kernel verifies
// the rewritten checksums in software; with offload enabled the rewrite runs
// on CHECKSUM_PARTIAL packets instead. Both attachment mechanisms are covered.
func TestSharedPacketRewriteCarriesTraffic(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		offload bool
		clsact  bool
	}{
		{name: "tcx/software_checksums", offload: false},
		{name: "tcx/checksum_offload", offload: true},
		{name: "clsact/software_checksums", offload: false, clsact: true},
		{name: "clsact/checksum_offload", offload: true, clsact: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			enterTestNetworkNamespace(t)
			if testCase.clsact {
				forceTCClsact(t)
			}
			setLoopbackUp(t)
			backend := newSharedRewriteTrafficBackend(t)

			router, peer := createTestVethPair(t, "sbsrw0", "sbsrw1")
			addTestAddress(t, router, "10.253.0.1/24")
			client := startTestNetworkNamespaceWorker(t)
			if err := netlink.LinkSetNsFd(peer, int(client.namespace.Fd())); err != nil {
				t.Fatalf("move %s into the client namespace: %v", peer.Attrs().Name, err)
			}
			client.run(t, func() error {
				if err := setLinkUpByName("lo"); err != nil {
					return err
				}
				link, err := netlink.LinkByName("sbsrw1")
				if err != nil {
					return err
				}
				if err = netlink.LinkSetUp(link); err != nil {
					return err
				}
				address, err := netlink.ParseAddr("10.253.0.2/24")
				if err != nil {
					return err
				}
				if err = netlink.AddrAdd(link, address); err != nil {
					return err
				}
				if !testCase.offload {
					if err = setTransmitChecksumOffload("sbsrw1", false); err != nil {
						return err
					}
				}
				return netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: net.ParseIP("10.253.0.1")})
			})
			if !testCase.offload {
				if err := setTransmitChecksumOffload("sbsrw0", false); err != nil {
					t.Fatalf("disable transmit checksum offload: %v", err)
				}
			}
			if _, err := enableSharedRewriteLocalnet("sbsrw0"); err != nil {
				t.Fatal(err)
			}
			attachment := attachSharedRewriteOrSkip(t, router, backend, defaultTCPriority)
			t.Cleanup(func() { _ = attachment.Close() })
			if err := backend.Enable(); err != nil {
				t.Fatalf("enable the backend: %v", err)
			}

			exchangeSharedRewriteTCP(t, backend, client)
			exchangeSharedRewriteUDP(t, client)

			for name, read := range map[string]func() (uint64, error){
				"rewrite failures":           backend.RewriteFailures,
				"token reservation failures": backend.TokenReservationFailures,
			} {
				count, err := read()
				if err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("%s = %d, want 0", name, count)
				}
			}
		})
	}
}

func newSharedRewriteTrafficBackend(t *testing.T) *commonEBPF.SharedPacketRewriteBackend {
	t.Helper()
	policy, err := commonEBPF.CompileActionPolicy(commonEBPF.ActionPolicy{
		EnableTCP: true,
		EnableUDP: true,
		Local:     commonEBPF.ActionScope{Default: commonEBPF.DecisionIntercept},
		Shared:    commonEBPF.ActionScope{Default: commonEBPF.DecisionIntercept},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareSharedPacketRewrite(nil, commonEBPF.SharedPacketRewriteConfig{
		ListenerPort: sharedRewriteTrafficListenerPort,
		EnableTCP:    true,
		EnableUDP:    true,
		RedirectIPv4: sharedRewriteTrafficTokenPrefix,
		Policy:       policy,
		MapCapacity:  commonEBPF.DefaultSharedPacketRewriteMapCapacity(),
		UDPTimeout:   time.Minute,
	})
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

func exchangeSharedRewriteTCP(t *testing.T, backend *commonEBPF.SharedPacketRewriteBackend, client *testNetworkNamespaceWorker) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{Port: sharedRewriteTrafficListenerPort})
	if err != nil {
		t.Fatalf("listen on the token port: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var conn net.Conn
	client.run(t, func() error {
		conn, err = (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp4", sharedRewriteTrafficTCPDestination.String())
		return err
	})
	t.Cleanup(func() { _ = conn.Close() })
	if remote := netip.MustParseAddrPort(conn.RemoteAddr().String()); remote != sharedRewriteTrafficTCPDestination {
		t.Fatalf("client remote address = %s, want %s", remote, sharedRewriteTrafficTCPDestination)
	}
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept the rewritten connection: %v", err)
	}
	t.Cleanup(func() { _ = accepted.Close() })
	token := netip.MustParseAddrPort(accepted.LocalAddr().String())
	if !sharedRewriteTrafficTokenPrefix.Contains(token.Addr()) || token.Port() != sharedRewriteTrafficListenerPort {
		t.Fatalf("accepted local address = %s, want a token in %s on port %d", token, sharedRewriteTrafficTokenPrefix, sharedRewriteTrafficListenerPort)
	}
	original, _, err := backend.LookupFlow(commonEBPF.ProtocolTCP, netip.MustParseAddrPort(accepted.RemoteAddr().String()), token)
	if err != nil {
		t.Fatalf("look up the rewritten flow: %v", err)
	}
	if original.Destination != sharedRewriteTrafficTCPDestination {
		t.Fatalf("original destination = %s, want %s", original.Destination, sharedRewriteTrafficTCPDestination)
	}

	// Large writes exercise segmentation as well as small segments.
	payload := make([]byte, 1<<20)
	if _, err = rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	_ = conn.SetDeadline(deadline)
	_ = accepted.SetDeadline(deadline)
	echoErr := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(accepted, accepted)
		echoErr <- copyErr
	}()
	writeErr := make(chan error, 1)
	go func() {
		_, writeError := conn.Write(payload)
		writeErr <- writeError
	}()
	reply := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read the echoed stream: %v", err)
	}
	if err = <-writeErr; err != nil {
		t.Fatalf("write the stream: %v", err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatal("echoed stream differs from the payload")
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err = <-echoErr; err != nil {
		t.Fatalf("echo the stream: %v", err)
	}
}

func exchangeSharedRewriteUDP(t *testing.T, client *testNetworkNamespaceWorker) {
	t.Helper()
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: sharedRewriteTrafficListenerPort})
	if err != nil {
		t.Fatalf("listen on the token port: %v", err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	server := ipv4.NewPacketConn(packetConn)
	if err = server.SetControlMessage(ipv4.FlagDst, true); err != nil {
		t.Fatal(err)
	}

	var conn net.Conn
	client.run(t, func() error {
		conn, err = net.Dial("udp4", sharedRewriteTrafficUDPDestination.String())
		return err
	})
	t.Cleanup(func() { _ = conn.Close() })
	deadline := time.Now().Add(5 * time.Second)
	_ = conn.SetDeadline(deadline)
	_ = packetConn.SetDeadline(deadline)

	buffer := make([]byte, 2048)
	for index := range 8 {
		message := bytes.Repeat([]byte{byte('a' + index)}, 64+index*100)
		if _, err = conn.Write(message); err != nil {
			t.Fatalf("send datagram %d: %v", index, err)
		}
		n, controlMessage, source, readErr := server.ReadFrom(buffer)
		if readErr != nil {
			t.Fatalf("receive datagram %d: %v", index, readErr)
		}
		if !bytes.Equal(buffer[:n], message) {
			t.Fatalf("datagram %d payload differs", index)
		}
		token, _ := netip.AddrFromSlice(controlMessage.Dst.To4())
		if !sharedRewriteTrafficTokenPrefix.Contains(token) {
			t.Fatalf("datagram %d destination = %s, want a token in %s", index, token, sharedRewriteTrafficTokenPrefix)
		}
		if _, err = server.WriteTo(buffer[:n], &ipv4.ControlMessage{Src: controlMessage.Dst}, source); err != nil {
			t.Fatalf("reply to datagram %d: %v", index, err)
		}
		reply := make([]byte, len(message)+1)
		replyLength, replyErr := conn.Read(reply)
		if replyErr != nil {
			t.Fatalf("receive reply %d: %v", index, replyErr)
		}
		if !bytes.Equal(reply[:replyLength], message) {
			t.Fatalf("reply %d payload differs", index)
		}
	}
}

// setTransmitChecksumOffload toggles NETIF_F_HW_CSUM through the legacy
// ethtool ioctl in the calling thread's network namespace.
func setTransmitChecksumOffload(interfaceName string, enabled bool) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	const ethtoolSetTransmitChecksum = 0x00000017
	// Heap allocations do not move, so the address stored in the request
	// stays valid until the ioctl returns.
	value := new(struct{ cmd, data uint32 })
	value.cmd = ethtoolSetTransmitChecksum
	if enabled {
		value.data = 1
	}
	request := new([unix.IFNAMSIZ + 24]byte)
	copy(request[:unix.IFNAMSIZ-1], interfaceName)
	*(*uintptr)(unsafe.Pointer(&request[unix.IFNAMSIZ])) = uintptr(unsafe.Pointer(value))
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(request)))
	goRuntime.KeepAlive(value)
	if errno != 0 {
		return errno
	}
	return nil
}
