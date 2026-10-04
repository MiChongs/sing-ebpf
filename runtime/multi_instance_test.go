//go:build with_ebpf && (linux || android)

package runtime

import (
	"os"
	"testing"

	"github.com/sagernet/netlink"
)

// TestTCSlotFilterIdentities covers what lets several runtimes share an
// interface: slot 0 keeps the single-instance identities, and no two slots,
// generations or roles share a filter name or handle on one parent.
func TestTCSlotFilterIdentities(t *testing.T) {
	for role := range tcFilterRoleCount {
		if got := tcSlotFilter(0, 0, role); got != tcLegacyFilterIdentities[role] {
			t.Errorf("slot 0 role %d = %+v, want the single-instance identity %+v", role, got, tcLegacyFilterIdentities[role])
		}
	}
	names := make(map[string]bool)
	handles := map[uint32]map[uint16]string{
		netlink.HANDLE_MIN_INGRESS: {tcDeliveryFilterHandle: "delivery"},
		netlink.HANDLE_MIN_EGRESS:  {},
	}
	for slot := range 16 {
		for generation := range tcFilterGenerations {
			for role := range tcFilterRoleCount {
				identity := tcSlotFilter(slot, generation, role)
				if _, used := names[identity.name]; used {
					t.Fatalf("slot %d generation %d role %d reuses name %q", slot, generation, role, identity.name)
				}
				names[identity.name] = true
				if previous, used := handles[identity.parent][identity.handle]; used {
					t.Fatalf("%s reuses handle %#x of %s", identity.name, identity.handle, previous)
				}
				handles[identity.parent][identity.handle] = identity.name
				if slot != 0 || generation != 0 {
					// Single-instance builds gave make-before-break filters handles
					// up to 0x6348; a slot handle must stay out of that range.
					if identity.handle <= 0x6348 {
						t.Fatalf("%s handle %#x overlaps handles of single-instance builds", identity.name, identity.handle)
					}
				}
				for other := range 16 {
					if got := tcSlotOwnsFilter(other, identity.name); got != (other == slot) {
						t.Fatalf("slot %d owns %q = %v", other, identity.name, got)
					}
				}
			}
		}
	}
	for _, name := range []string{"sbi1", "sbofff", "sbc2a"} {
		if !tcSlotOwnsFilter(0, name) || tcSlotOwnsFilter(1, name) {
			t.Errorf("a single-instance replacement filter %q is not owned by slot 0 alone", name)
		}
	}
	for _, name := range []string{"sbx1", "sbi", "sbi12345", "sbig", "cilium"} {
		if tcSlotOwnsFilter(0, name) {
			t.Errorf("slot 0 claims the unrelated filter %q", name)
		}
	}
}

// TestAggregateRPFilterLeaseOutlivesTheFirstDelivery covers two TC runtimes
// whose delivery interfaces both need conf.all.rp_filter lowered. Whichever
// leaves first must leave it lowered, and the last one restores the value it
// had before either started.
func TestAggregateRPFilterLeaseOutlivesTheFirstDelivery(t *testing.T) {
	for _, firstLeaves := range []bool{true, false} {
		name := "the runtime that lowered it leaves first"
		if !firstLeaves {
			name = "the runtime that inherited it leaves first"
		}
		t.Run(name, func(t *testing.T) {
			newTestSysctlRoot(t, map[string]string{
				"all":         "2",
				"wlan0":       "0",
				"sbd00010001": "0",
				"sbd00010002": "0",
			})
			first := &tcDeliveryLink{deliveryName: "sbd00010001"}
			second := &tcDeliveryLink{deliveryName: "sbd00010002"}
			for _, delivery := range []*tcDeliveryLink{first, second} {
				if _, err := delivery.claimAggregateRPFilter(); err != nil {
					t.Fatalf("claim for %s: %v", delivery.deliveryName, err)
				}
				t.Cleanup(func() { _ = delivery.releaseAggregateRPFilter() })
			}
			assertSysctl(t, "all", "0")
			assertSysctl(t, "wlan0", "2")
			// Pinning keeps every other interface's effective filter, but a
			// delivery interface of another runtime has to stay unfiltered.
			assertSysctl(t, "sbd00010001", "0")
			assertSysctl(t, "sbd00010002", "0")
			if first.globalLease == nil || second.globalLease == nil {
				t.Fatal("a delivery interface that depends on the lowered filter holds no lease")
			}
			if second.globalLease.Value() != "2" {
				t.Fatalf("the inherited lease restores %q, want the original 2", second.globalLease.Value())
			}
			leaving, staying := first, second
			if !firstLeaves {
				leaving, staying = second, first
			}
			if err := leaving.releaseAggregateRPFilter(); err != nil {
				t.Fatal(err)
			}
			assertSysctl(t, "all", "0")
			if !leaving.IsClosed() {
				t.Fatalf("the leaving delivery kept its restore state: %+v", leaving)
			}
			if err := staying.releaseAggregateRPFilter(); err != nil {
				t.Fatal(err)
			}
			assertSysctl(t, "all", "2")
			if !staying.IsClosed() {
				t.Fatalf("the last delivery kept its restore state: %+v", staying)
			}
		})
	}
}

// TestReplacedDeliveryKeepsTheAggregateFilterLowered covers a delivery
// interface replaced within one runtime. The replacement is created while the
// previous one still holds its lease, so it takes a lease of its own, receives
// the previous one's restore state, and the previous one leaves without
// restoring anything.
func TestReplacedDeliveryKeepsTheAggregateFilterLowered(t *testing.T) {
	newTestSysctlRoot(t, map[string]string{"all": "1", "wlan0": "0", "sbd00010001": "0", "sbd00010002": "0"})
	previous := &tcDeliveryLink{deliveryName: "sbd00010001"}
	if _, err := previous.claimAggregateRPFilter(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = previous.releaseAggregateRPFilter() })
	next := &tcDeliveryLink{deliveryName: "sbd00010002"}
	if _, err := next.claimAggregateRPFilter(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.releaseAggregateRPFilter() })
	handoffTCGlobalSysctls(previous, next)
	if next.globalLease == nil || next.globalLease.Value() != "1" {
		t.Fatalf("the replacement holds lease %v, want one restoring 1", next.globalLease)
	}
	if err := previous.releaseAggregateRPFilter(); err != nil {
		t.Fatal(err)
	}
	assertSysctl(t, "all", "0")
	assertSysctl(t, "wlan0", "1")
	if err := next.releaseAggregateRPFilter(); err != nil {
		t.Fatal(err)
	}
	assertSysctl(t, "all", "1")
	assertSysctl(t, "wlan0", "0")
}

// TestAggregateRPFilterLeaseWithoutRestoreDuty covers runtimes that found the
// aggregate filter already lowered. They hold leases that restore nothing, so
// none of them raises the filter when it leaves; a runtime that lowers it again
// after an administrator raised it takes over restoring it.
func TestAggregateRPFilterLeaseWithoutRestoreDuty(t *testing.T) {
	newTestSysctlRoot(t, map[string]string{"all": "0", "sbd00010001": "0", "sbd00010002": "0"})
	first := &tcDeliveryLink{deliveryName: "sbd00010001"}
	second := &tcDeliveryLink{deliveryName: "sbd00010002"}
	for _, delivery := range []*tcDeliveryLink{first, second} {
		if changed, err := delivery.claimAggregateRPFilter(); err != nil || changed {
			t.Fatalf("claim for %s: changed=%v err=%v", delivery.deliveryName, changed, err)
		}
		t.Cleanup(func() { _ = delivery.releaseAggregateRPFilter() })
		if delivery.globalLease == nil || delivery.globalLease.Value() != tcSysctlLeaseNoRestore {
			t.Fatalf("%s holds lease %v, want one that restores nothing", delivery.deliveryName, delivery.globalLease)
		}
	}
	if err := os.WriteFile(tcInterfaceSysctlPath("all", "rp_filter"), []byte("2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, err := first.claimAggregateRPFilter(); err != nil || !changed {
		t.Fatalf("repair after the filter was raised: changed=%v err=%v", changed, err)
	}
	if first.globalLease.Value() != "2" {
		t.Fatalf("the repairing runtime restores %q, want 2", first.globalLease.Value())
	}
	if err := second.releaseAggregateRPFilter(); err != nil {
		t.Fatal(err)
	}
	assertSysctl(t, "all", "0")
	if err := first.releaseAggregateRPFilter(); err != nil {
		t.Fatal(err)
	}
	assertSysctl(t, "all", "2")
}

// TestSharedTCInterfaceLockOutlivesEveryHolder covers a make-before-break
// replacement and the attachment it replaced holding one interface slot: the
// slot stays held until the last of them closes.
func TestSharedTCInterfaceLockOutlivesEveryHolder(t *testing.T) {
	slot, err := acquireTCInterfaceLock("shared", testTCInterfaceLockIndex+0x50)
	if err != nil {
		t.Fatal(err)
	}
	previous := newSharedTCInterfaceLock(slot)
	replacement := previous.share()
	if err = previous.Close(); err != nil {
		t.Fatal(err)
	}
	if err = previous.Close(); err != nil {
		t.Fatalf("a second close of one holder: %v", err)
	}
	if !tcLockHeld(t, testTCInterfaceLockIndex+0x50) {
		t.Fatal("the slot was released while the replacement still holds it")
	}
	if err = replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if tcLockHeld(t, testTCInterfaceLockIndex+0x50) {
		t.Fatal("the slot outlived its last holder")
	}
}

// TestReplacementGenerationAvoidsRetainedAttachments covers a replacement made
// while an earlier attachment of the same slot could not detach: it must not
// reuse that attachment's filter names and handles.
func TestReplacementGenerationAvoidsRetainedAttachments(t *testing.T) {
	retained := &sharedRewriteAttachment{interfaceName: "wlan0", interfaceIndex: 7, slot: 2, generation: 0,
		ingressFilter: &netlink.BpfFilter{}}
	otherSlot := &sharedRewriteAttachment{interfaceName: "wlan0", interfaceIndex: 7, slot: 3, generation: 2,
		ingressFilter: &netlink.BpfFilter{}}
	dataPlane := &sharedRewriteDataPlane{retiredAttachments: []*sharedRewriteAttachment{retained, otherSlot}}
	previous := &sharedRewriteAttachment{interfaceName: "wlan0", interfaceIndex: 7, slot: 2, generation: 1}
	generation, err := dataPlane.replacementGenerationLocked(previous)
	if err != nil {
		t.Fatal(err)
	}
	if generation != 2 {
		t.Fatalf("replacement generation = %d, want 2 (0 is retained, 1 is being replaced)", generation)
	}
	for used := range tcFilterGenerations {
		dataPlane.retiredAttachments = append(dataPlane.retiredAttachments, &sharedRewriteAttachment{
			interfaceIndex: 7, slot: 2, generation: used, ingressFilter: &netlink.BpfFilter{},
		})
	}
	if _, err = dataPlane.replacementGenerationLocked(previous); err == nil {
		t.Fatal("a generation was handed out although every one is held")
	}
}
