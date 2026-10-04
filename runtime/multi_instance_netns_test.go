//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	commonEBPF "github.com/MiChongs/sing-ebpf"
	core "github.com/MiChongs/sing-ebpf/internal/core"
	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

// newPassThroughTCProgram loads a classifier that hands every packet to the
// next program or filter.
func newPassThroughTCProgram(t *testing.T, name string) *CiliumEBPF.Program {
	t.Helper()
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         name,
		Type:         CiliumEBPF.SchedCLS,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()},
	})
	if err != nil {
		t.Skipf("cannot load a classifier program in this environment: %v", err)
	}
	t.Cleanup(func() { _ = program.Close() })
	return program
}

func tcProgramID(t *testing.T, program *CiliumEBPF.Program) CiliumEBPF.ProgramID {
	t.Helper()
	info, err := program.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	return id
}

// TestTCXOrderedAttachFollowsPriority covers the order several runtimes share
// on one TCX hook: lower priorities run first, equal priorities keep their
// attach order, and a program without a priority marker is left where it is.
func TestTCXOrderedAttachFollowsPriority(t *testing.T) {
	enterTestNetworkNamespace(t)
	self, _ := createTestVethPair(t, "sbtcxo0", "sbtcxo1")
	index := self.Attrs().Index
	attach := func(name string, priority uint16) CiliumEBPF.ProgramID {
		program := newPassThroughTCProgram(t, name)
		attached, err := coreAttachTCXOrdered(index, CiliumEBPF.AttachTCXIngress, program, priority)
		if err != nil {
			if tcxUnsupportedError(err) {
				requireOrSkipTCX(t, "clsact")
			}
			t.Fatalf("attach %s: %v", name, err)
		}
		t.Cleanup(func() { _ = attached.Close() })
		return tcProgramID(t, program)
	}
	priority5 := attach("sb_test_p5", 5)
	foreignProgram := newPassThroughTCProgram(t, "foreign_tail")
	foreign, err := link.AttachTCX(link.TCXOptions{Interface: index, Program: foreignProgram, Attach: CiliumEBPF.AttachTCXIngress})
	if err != nil {
		t.Fatalf("attach a foreign program: %v", err)
	}
	t.Cleanup(func() { _ = foreign.Close() })
	priority1 := attach("sb_test_p1a", 1)
	priority3 := attach("sb_test_p3", 3)
	priority1Later := attach("sb_test_p1b", 1)

	result, err := link.QueryPrograms(link.QueryOptions{Target: index, Attach: CiliumEBPF.AttachTCXIngress})
	if err != nil {
		t.Fatal(err)
	}
	var order []CiliumEBPF.ProgramID
	for _, attached := range result.Programs {
		order = append(order, attached.ID)
	}
	want := []CiliumEBPF.ProgramID{priority1, priority1Later, priority3, priority5, tcProgramID(t, foreignProgram)}
	if !slices.Equal(order, want) {
		t.Fatalf("TCX order = %v, want %v (p1, p1 attached later, p3, p5, unmarked foreign program)", order, want)
	}
}

// newICMPEchoReplyTCBackend prepares a TC backend whose ForceIntercept ICMP
// responder answers for prefix only.
func newICMPEchoReplyTCBackend(t *testing.T, prefix netip.Prefix, listenerPort uint16) *commonEBPF.TCBackend {
	t.Helper()
	scope := commonEBPF.ActionScope{
		Default:         commonEBPF.DecisionIntercept,
		DestinationCIDR: []commonEBPF.CIDRDecision{{Prefix: prefix, Action: commonEBPF.DecisionIntercept}},
	}
	policy, err := commonEBPF.CompileActionPolicy(commonEBPF.ActionPolicy{EnableTCP: true, Local: scope, Shared: scope})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{
		ListenerPort:  listenerPort,
		EnableLocal:   true,
		EnableShared:  true,
		EnableIPv4:    true,
		EnableTCP:     true,
		Policy:        policy,
		ICMPEchoReply: true,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

// pingThroughSharedAttachment sends an echo request for target into the
// shared interface self from its peer and waits for the answer.
func pingThroughSharedAttachment(t *testing.T, self, peer netlink.Link, target string, sequence uint16) {
	t.Helper()
	client := "10.250.1.8"
	payload := []byte(t.Name())
	request := buildEthernetIPv4EchoRequest(
		self.Attrs().HardwareAddr, peer.Attrs().HardwareAddr,
		net.ParseIP(client), net.ParseIP(target), 0x5a5a, sequence, payload,
	)
	socket := openRawLinkLayerSocket(t, peer.Attrs().Index, unix.ETH_P_IP, 5*time.Second)
	if _, err := unix.Write(socket, request); err != nil {
		t.Fatalf("transmit the echo request: %v", err)
	}
	reply, replyLength := readICMPEchoReplyFrame(t, socket, 8, parseEthernetIPv4ICMP)
	assertICMPEchoReply(
		t, reply, replyLength, len(request), 0, 0x5a5a, sequence, payload, target, client,
		peer.Attrs().HardwareAddr, self.Attrs().HardwareAddr, true,
	)
}

// TestTCRuntimesChainOnOneInterface covers two runtimes on one interface. Each
// holds its own slot, a packet the first one passes reaches the second, and
// closing the first leaves the second attached.
func TestTCRuntimesChainOnOneInterface(t *testing.T) {
	for _, clsact := range []bool{false, true} {
		name := "tcx"
		if clsact {
			name = "clsact"
		}
		t.Run(name, func(t *testing.T) {
			enterTestNetworkNamespace(t)
			if clsact {
				forceTCClsact(t)
			}
			self, peer := createTestVethPair(t, "sbchain0", "sbchain1")
			first := newICMPEchoReplyTCBackend(t, netip.MustParsePrefix("198.18.0.0/16"), 23460)
			second := newICMPEchoReplyTCBackend(t, netip.MustParsePrefix("198.19.0.0/16"), 23461)
			role := tcInterfaceRole{shared: true}
			firstAttachment := attachICMPEchoReplyOrSkip(t, first, "sbchain0", self.Attrs().Index, role, defaultTCPriority)
			t.Cleanup(func() { _ = firstAttachment.Close() })
			secondAttachment := attachICMPEchoReplyOrSkip(t, second, "sbchain0", self.Attrs().Index, role, defaultTCPriority)
			t.Cleanup(func() { _ = secondAttachment.Close() })
			if firstAttachment.slot != 0 || secondAttachment.slot != 1 {
				t.Fatalf("slots = %d, %d; want 0, 1", firstAttachment.slot, secondAttachment.slot)
			}
			if clsact && secondAttachment.sharedFilter.Name != "sb_tc_shared.1" {
				t.Fatalf("second runtime's filter = %q, want its slot's name", secondAttachment.sharedFilter.Name)
			}

			firstBefore, secondBefore := icmpEchoReplyCount(t, first), icmpEchoReplyCount(t, second)
			pingThroughSharedAttachment(t, self, peer, "198.19.0.1", 1)
			requireOneICMPEchoReply(t, second, secondBefore)
			if icmpEchoReplyCount(t, first) != firstBefore {
				t.Fatal("the first runtime answered a request outside its prefix")
			}
			pingThroughSharedAttachment(t, self, peer, "198.18.0.1", 2)
			requireOneICMPEchoReply(t, first, firstBefore)

			if err := firstAttachment.Close(); err != nil {
				t.Fatalf("close the first runtime's attachment: %v", err)
			}
			attached, err := secondAttachment.filtersAttached(defaultTCPriority, second)
			if err != nil || !attached {
				t.Fatalf("closing the first runtime detached the second: attached=%v err=%v", attached, err)
			}
			secondBefore = icmpEchoReplyCount(t, second)
			pingThroughSharedAttachment(t, self, peer, "198.19.0.2", 3)
			requireOneICMPEchoReply(t, second, secondBefore)
		})
	}
}

func bpfFilterNames(t *testing.T, device netlink.Link, parent uint32) []string {
	t.Helper()
	filters, err := netlink.FilterList(device, parent)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, filter := range filters {
		if bpfFilter, isBPF := filter.(*netlink.BpfFilter); isBPF {
			names = append(names, bpfFilter.Name)
		}
	}
	slices.Sort(names)
	return names
}

// TestTCInterfaceSlotReclaimsOnlyItsOwnFilters covers startup cleanup with
// other runtimes alive: taking a slot removes the filters a dead holder of that
// slot left behind and nothing else.
func TestTCInterfaceSlotReclaimsOnlyItsOwnFilters(t *testing.T) {
	enterTestNetworkNamespace(t)
	self, _ := createTestVethPair(t, "sbreclaim0", "sbreclaim1")
	if err := ensureTCClsact(self); err != nil {
		t.Fatal(err)
	}
	program := newPassThroughTCProgram(t, "sb_test_stale")
	plant := func(name string, handle uint16) {
		if _, err := attachTCFilter(self, netlink.HANDLE_MIN_INGRESS, program.FD(), name, handle, 1); err != nil {
			t.Fatalf("plant %s: %v", name, err)
		}
	}
	slot0 := tcSlotFilter(0, 0, tcFilterRoleShared)
	slot1 := tcSlotFilter(1, 0, tcFilterRoleShared)
	slot1Replacement := tcSlotFilter(1, 1, tcFilterRoleRewriteIngress)
	slot2 := tcSlotFilter(2, 0, tcFilterRoleShared)
	plant(slot0.name, slot0.handle)
	plant(slot1.name, slot1.handle)
	plant(slot1Replacement.name, slot1Replacement.handle)
	plant(slot2.name, slot2.handle)
	plant("sbi7", 0x5349+7)

	// A live runtime holds slot 0 before anything is reclaimed; this is the
	// only acquisition that, with slot 0 free, reclaims slot 0's leftovers.
	live, err := core.AcquireInstanceSlot(func(slot int) string {
		return core.InstanceSlotName("@sing-ebpf-tc-"+strconv.Itoa(self.Attrs().Index), slot)
	})
	if err != nil || live.Index() != 0 {
		t.Fatalf("hold slot 0 for a live runtime: slot=%d err=%v", live.Index(), err)
	}
	t.Cleanup(func() { _ = live.Close() })
	lock, err := acquireTCInterfaceLock("sbreclaim0", self.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	if lock.Index() != 1 {
		t.Fatalf("acquired slot %d, want 1", lock.Index())
	}
	want := []string{"sb_tc_shared", "sb_tc_shared.2", "sbi7"}
	if got := bpfFilterNames(t, self, netlink.HANDLE_MIN_INGRESS); !slices.Equal(got, want) {
		t.Fatalf("filters after taking slot 1 = %v, want %v", got, want)
	}

	if err = live.Close(); err != nil {
		t.Fatal(err)
	}
	reclaimer, err := acquireTCInterfaceLock("sbreclaim0", self.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reclaimer.Close() })
	if reclaimer.Index() != 0 {
		t.Fatalf("acquired slot %d, want the released slot 0", reclaimer.Index())
	}
	want = []string{"sb_tc_shared.2"}
	if got := bpfFilterNames(t, self, netlink.HANDLE_MIN_INGRESS); !slices.Equal(got, want) {
		t.Fatalf("filters after taking slot 0 = %v, want %v", got, want)
	}
}

// TestTCPolicyRoutingRuntimesCoexist covers two runtimes in one network
// namespace: each owns its own routing identifiers, and closing one leaves the
// other's rules and routes in place.
func TestTCPolicyRoutingRuntimesCoexist(t *testing.T) {
	enterTestNetworkNamespace(t)
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	first, err := startTCPolicyRouting(true)
	if err != nil {
		t.Fatalf("start the first policy routing: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := startTCPolicyRouting(true)
	if err != nil {
		t.Fatalf("start the second policy routing: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if first.slot == second.slot || first.mark == second.mark ||
		first.table == second.table || first.priority == second.priority {
		t.Fatalf("policy routing identifiers overlap: first=%+v second=%+v", *first, *second)
	}
	for _, routing := range []*tcPolicyRouting{first, second} {
		if changed, err := routing.ensure(); err != nil || changed {
			t.Fatalf("a healthy policy routing reported changed=%v err=%v", changed, err)
		}
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if changed, err := second.ensure(); err != nil || changed {
		t.Fatalf("closing one runtime's policy routing disturbed the other: changed=%v err=%v", changed, err)
	}
}

func readRouteLocalnet(t *testing.T, interfaceName string) string {
	t.Helper()
	value, err := os.ReadFile(sharedRewriteLocalnetPath(interfaceName))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(value))
}

// TestSharedRewriteRuntimesShareRouteLocalnet covers two packet-rewrite
// runtimes on one interface: route_localnet stays enabled until the last of
// them is gone.
func TestSharedRewriteRuntimesShareRouteLocalnet(t *testing.T) {
	enterTestNetworkNamespace(t)
	forceTCClsact(t)
	self, _ := createTestVethPair(t, "sbrwshare0", "sbrwshare1")
	if value := readRouteLocalnet(t, "sbrwshare0"); value != "0" {
		t.Fatalf("route_localnet = %q before any runtime, want 0", value)
	}
	firstBackend := newRealICMPEchoSharedPacketRewriteBackend(t)
	t.Cleanup(func() { _ = firstBackend.Close() })
	secondBackend := newRealICMPEchoSharedPacketRewriteBackend(t)
	t.Cleanup(func() { _ = secondBackend.Close() })
	first, err := attachSharedRewriteInterface(self, firstBackend, defaultTCPriority)
	if err != nil {
		t.Fatalf("attach the first runtime: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := attachSharedRewriteInterface(self, secondBackend, defaultTCPriority)
	if err != nil {
		t.Fatalf("attach the second runtime: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if first.slot == second.slot || first.ingressName == second.ingressName {
		t.Fatalf("runtimes share an identity: first=%d/%s second=%d/%s", first.slot, first.ingressName, second.slot, second.ingressName)
	}
	if value := readRouteLocalnet(t, "sbrwshare0"); value != "1" {
		t.Fatalf("route_localnet = %q with two runtimes, want 1", value)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if value := readRouteLocalnet(t, "sbrwshare0"); value != "1" {
		t.Fatal("the first runtime to leave disabled route_localnet under the second")
	}
	healthy, err := second.healthy(self, defaultTCPriority, secondBackend.ICMPEchoReplyEnabled())
	if err != nil || !healthy {
		t.Fatalf("closing the first runtime detached the second: healthy=%v err=%v", healthy, err)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
	if value := readRouteLocalnet(t, "sbrwshare0"); value != "0" {
		t.Fatalf("route_localnet = %q after the last runtime, want 0", value)
	}
}

// TestTCPolicyRoutingSlotReclaimsAnInterruptedHolder covers a runtime that
// died without removing its rule and routes while another runtime runs: the
// next holder of its slot reuses exactly that state, and the live runtime keeps
// its own.
func TestTCPolicyRoutingSlotReclaimsAnInterruptedHolder(t *testing.T) {
	enterTestNetworkNamespace(t)
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	live, err := startTCPolicyRouting(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Close() })
	interrupted, err := startTCPolicyRouting(true)
	if err != nil {
		t.Fatal(err)
	}
	if interrupted.slot != 1 || interrupted.table != tcPreferredPolicyIdentifiers(1).table {
		t.Fatalf("second runtime: slot %d table %d, want slot 1 and its preferred table", interrupted.slot, interrupted.table)
	}
	// Dying releases the slot and nothing else.
	if err = interrupted.lock.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := startTCPolicyRouting(true)
	if err != nil {
		t.Fatalf("take the interrupted runtime's slot: %v", err)
	}
	t.Cleanup(func() { _ = next.Close() })
	if next.slot != 1 || next.mark != interrupted.mark || next.table != interrupted.table || next.priority != interrupted.priority {
		t.Fatalf("next holder of slot 1 = %+v, want the interrupted runtime's identifiers %+v", *next, *interrupted)
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		entries, err := listTCPolicyRules(family, *tcPolicyRuleFor(family, next.mark, next.table, next.priority))
		if err != nil {
			t.Fatal(err)
		}
		owned := 0
		for _, entry := range entries {
			if entry.owned {
				owned++
			}
		}
		if owned != 1 {
			t.Fatalf("family %d has %d rules for the reclaimed slot, want exactly 1", family, owned)
		}
	}
	if changed, err := live.ensure(); err != nil || changed {
		t.Fatalf("reclaiming slot 1 disturbed slot 0: changed=%v err=%v", changed, err)
	}
}
