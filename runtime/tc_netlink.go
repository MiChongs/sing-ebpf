//go:build with_ebpf && (linux || android)

package runtime

import (
	"errors"
	"io"
	"strconv"
	"strings"

	commonEBPF "github.com/MiChongs/sing-ebpf"
	core "github.com/MiChongs/sing-ebpf/internal/core"
	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// acquireTCInterfaceLock takes one of the interface's instance slots and
// reclaims the clsact filters a dead holder of the same slot left behind. Slot 0
// keeps the historical lock name so extracted, in-tree and pre-multi-instance
// builds, which all use it exclusively, never share their filter names with a
// slot of this build.
func acquireTCInterfaceLock(interfaceName string, interfaceIndex int) (*core.InstanceSlot, error) {
	slot, err := core.AcquireInstanceSlot(func(slot int) string {
		return core.InstanceSlotName("@sing-ebpf-tc-"+strconv.Itoa(interfaceIndex), slot)
	})
	if err != nil {
		if errors.Is(err, core.ErrInstanceSlotsExhausted) {
			return nil, E.New("interface ", interfaceName, " is already managed by ", core.MaxInstanceSlots, " sing-ebpf runtimes")
		}
		return nil, E.Cause(err, "lock TC eBPF interface ", interfaceName)
	}
	if err = reclaimTCSlotFilters(interfaceIndex, slot.Index()); err != nil {
		return nil, E.Errors(E.Cause(err, "reclaim stale TC filters on interface ", interfaceName), slot.Close())
	}
	return slot, nil
}

// tcLockSlot is the instance slot an interface lock holds. Test doubles that
// are not slots behave as slot 0.
func tcLockSlot(lock io.Closer) int {
	slot, loaded := lock.(interface{ Index() int })
	if !loaded || slot == nil {
		return 0
	}
	return slot.Index()
}

type tcFilterRole uint8

const (
	tcFilterRoleLocal tcFilterRole = iota
	tcFilterRoleShared
	tcFilterRoleLocalICMP
	tcFilterRoleSharedICMP
	tcFilterRoleRewriteIngress
	tcFilterRoleRewriteEgress
	tcFilterRoleRewriteICMP
	tcFilterRoleCount
)

// tcFilterIdentity is the kernel identity of one sing-ebpf clsact filter.
type tcFilterIdentity struct {
	parent uint32
	name   string
	handle uint16
}

// tcLegacyFilterIdentities are the names and handles of slot 0, generation 0.
// They are the ones single-instance builds used, so a slot-0 owner reclaims and
// health-checks exactly what such a build leaves behind.
var tcLegacyFilterIdentities = [tcFilterRoleCount]tcFilterIdentity{
	tcFilterRoleLocal:          {netlink.HANDLE_MIN_EGRESS, "sb_tc_local", tcLocalFilterHandle},
	tcFilterRoleShared:         {netlink.HANDLE_MIN_INGRESS, "sb_tc_shared", tcSharedFilterHandle},
	tcFilterRoleLocalICMP:      {netlink.HANDLE_MIN_EGRESS, "sb_icmp_local", tcLocalICMPReplyFilterHandle},
	tcFilterRoleSharedICMP:     {netlink.HANDLE_MIN_INGRESS, "sb_icmp_shared", tcSharedICMPReplyFilterHandle},
	tcFilterRoleRewriteIngress: {netlink.HANDLE_MIN_INGRESS, "sb_share_in", sharedRewriteIngressFilterHandle},
	tcFilterRoleRewriteEgress:  {netlink.HANDLE_MIN_EGRESS, "sb_share_out", sharedRewriteEgressFilterHandle},
	tcFilterRoleRewriteICMP:    {netlink.HANDLE_MIN_INGRESS, "sb_icmp_share", sharedRewriteICMPFilterHandle},
}

// tcSlotFilterHandleBase starts the handle range of every other slot and
// generation. Older builds gave make-before-break packet-rewrite filters
// handles of up to 0x6348, so the range starts above that.
const tcSlotFilterHandleBase = 0x7000

// tcFilterGenerations bounds the make-before-break generations of one slot.
const tcFilterGenerations = 16

// tcSlotFilter names a filter by the interface slot that owns it, the
// generation of a make-before-break replacement, and its role. Two instances
// on one interface hold different slots and therefore never touch each other's
// filters, and two attachments of one slot that have filters at the same time
// use different generations.
func tcSlotFilter(slot int, generation int, role tcFilterRole) tcFilterIdentity {
	identity := tcLegacyFilterIdentities[role]
	if slot == 0 && generation == 0 {
		return identity
	}
	identity.name += "." + strconv.FormatUint(uint64(slot), 16)
	if generation != 0 {
		identity.name += "g" + strconv.FormatUint(uint64(generation), 16)
	}
	identity.handle = uint16(tcSlotFilterHandleBase | slot<<8 | generation<<4 | int(role))
	return identity
}

// tcSlotOwnsFilter reports whether a filter name belongs to slot. A slot-0
// owner also owns the make-before-break names of single-instance builds
// ("sbi", "sbo" or "sbc" and up to three hex digits): those builds held the
// slot-0 lock while they existed.
func tcSlotOwnsFilter(slot int, name string) bool {
	for role := range tcFilterRoleCount {
		for generation := range tcFilterGenerations {
			if tcSlotFilter(slot, generation, role).name == name {
				return true
			}
		}
	}
	return slot == 0 && legacyTemporaryTCFilterName(name)
}

func legacyTemporaryTCFilterName(name string) bool {
	if len(name) < 4 || len(name) > 6 || !strings.HasPrefix(name, "sb") {
		return false
	}
	switch name[2] {
	case 'i', 'o', 'c':
	default:
		return false
	}
	_, err := strconv.ParseUint(name[3:], 16, 16)
	return err == nil
}

// reclaimTCSlotFilters removes the clsact filters a previous holder of slot
// left on the interface. The caller holds the slot, so no live instance owns
// them.
func reclaimTCSlotFilters(interfaceIndex int, slot int) error {
	device, err := netlink.LinkByIndex(interfaceIndex)
	if err != nil {
		if tcLinkNotFound(err) {
			return nil
		}
		return err
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(device, parent)
		if err != nil {
			if tcFilterListAbsent(err) {
				continue
			}
			return err
		}
		for _, filter := range filters {
			bpfFilter, isBPF := filter.(*netlink.BpfFilter)
			if !isBPF || !tcSlotOwnsFilter(slot, bpfFilter.Name) {
				continue
			}
			if err = netlink.FilterDel(filter); err != nil && !tcFilterListAbsent(err) {
				return err
			}
		}
	}
	return nil
}

// tcFilterListAbsent covers a filter, qdisc or interface that is already gone.
func tcFilterListAbsent(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EINVAL)
}

func attachTCFilter(
	link netlink.Link,
	parent uint32,
	programFD int,
	programName string,
	handle uint16,
	priority uint16,
) (*netlink.BpfFilter, error) {
	if programFD < 0 {
		return nil, E.New("TC eBPF program is unavailable")
	}
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if isBPF && bpfFilter.Name == programName {
			if err = netlink.FilterDel(existing); err != nil && !errors.Is(err, unix.ENOENT) {
				return nil, err
			}
			continue
		}
		if existing.Attrs().Handle == filterHandle {
			return nil, E.New("TC filter handle conflict on ", link.Attrs().Name)
		}
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    filterHandle,
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           programFD,
		Name:         programName,
		DirectAction: true,
	}
	if err = netlink.FilterAdd(filter); err != nil {
		return nil, err
	}
	return filter, nil
}

func tcFilterAttached(
	link netlink.Link,
	parent uint32,
	programName string,
	handle uint16,
	priority uint16,
) (bool, error) {
	filters, err := netlink.FilterList(link, parent)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if !isBPF {
			continue
		}
		attributes := bpfFilter.Attrs()
		if attributes.Handle == filterHandle &&
			attributes.Priority == priority &&
			bpfFilter.Name == programName &&
			bpfFilter.DirectAction {
			return true, nil
		}
	}
	return false, nil
}

func detachTCFilter(filter *netlink.BpfFilter) error {
	if filter == nil {
		return nil
	}
	err := netlink.FilterDel(filter)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if errors.Is(err, unix.EINVAL) {
		// The kernel returns EINVAL instead of ENOENT when the parent clsact
		// qdisc is already gone (netd flushes it on interface refreshes).
		// The filter cannot survive its qdisc, so treat the deletion as done
		// once a fresh filter listing confirms it is absent.
		link, linkErr := netlink.LinkByIndex(filter.LinkIndex)
		if linkErr != nil {
			return nil
		}
		attached, checkErr := tcFilterAttached(link, filter.Parent, filter.Name, uint16(filter.Handle&0xffff), filter.Priority)
		if checkErr != nil || !attached {
			return nil
		}
	}
	return err
}

func ensureTCClsact(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err = netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func tcLinkNotFound(err error) bool {
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
		return true
	}
	var linkNotFoundError netlink.LinkNotFoundError
	return errors.As(err, &linkNotFoundError)
}

func tcLinkFraming(link netlink.Link) (commonEBPF.TCLinkFraming, error) {
	if link == nil || link.Attrs() == nil {
		return commonEBPF.TCLinkFramingUnsupported, E.New("invalid TC eBPF interface")
	}
	attributes := link.Attrs()
	framing := commonEBPF.ClassifyTCLinkFraming(attributes.EncapType, len(attributes.HardwareAddr))
	if framing == commonEBPF.TCLinkFramingUnsupported {
		return framing, E.New(
			"TC eBPF interface ", attributes.Name,
			" has unsupported link encapsulation ", attributes.EncapType,
		)
	}
	return framing, nil
}
