//go:build with_ebpf && (linux || android)

package runtime

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	commonEBPF "github.com/MiChongs/sing-ebpf"
	core "github.com/MiChongs/sing-ebpf/internal/core"
	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	sharedRewriteIngressFilterHandle = 0x5342
	sharedRewriteEgressFilterHandle  = 0x5343
	sharedRewriteICMPFilterHandle    = 0x5349
)

// sharedRewriteAttachmentOptions selects the identity of a new attachment. A
// replacement on the same interface index shares the slot of the attachment
// it replaces and takes a filter generation no attachment of that slot still
// uses, so both sets of filters can be attached while the replacement is made
// before the previous one is broken. Without a lock, the attachment takes a
// slot of its own.
type sharedRewriteAttachmentOptions struct {
	lock       *sharedTCInterfaceLock
	generation int
}

// sharedTCInterfaceLock is an interface slot that several attachments hold at
// once: a make-before-break replacement holds it together with the attachment
// it replaces, and a replaced attachment that could not detach keeps holding
// it. The slot is released when the last holder closes, so no other runtime
// can take the slot while filters remain under its names.
type sharedTCInterfaceLock struct {
	holders *sharedTCInterfaceLockHolders
}

type sharedTCInterfaceLockHolders struct {
	slot  *core.InstanceSlot
	count int
}

func newSharedTCInterfaceLock(slot *core.InstanceSlot) *sharedTCInterfaceLock {
	return &sharedTCInterfaceLock{holders: &sharedTCInterfaceLockHolders{slot: slot, count: 1}}
}

// share returns another holder of the same slot.
func (l *sharedTCInterfaceLock) share() *sharedTCInterfaceLock {
	l.holders.count++
	return &sharedTCInterfaceLock{holders: l.holders}
}

func (l *sharedTCInterfaceLock) Index() int {
	if l == nil || l.holders == nil {
		return 0
	}
	return l.holders.slot.Index()
}

func (l *sharedTCInterfaceLock) Close() error {
	if l == nil || l.holders == nil {
		return nil
	}
	if l.holders.count == 1 {
		if err := l.holders.slot.Close(); err != nil {
			return err
		}
	}
	l.holders.count--
	l.holders = nil
	return nil
}

// replacementGenerationLocked picks the filter generation of a replacement for
// previous: one that neither previous nor any retained attachment of the same
// interface slot still uses.
func (d *sharedRewriteDataPlane) replacementGenerationLocked(previous *sharedRewriteAttachment) (int, error) {
	used := make([]bool, tcFilterGenerations)
	used[previous.generation] = true
	for _, retired := range d.retiredAttachments {
		if retired.interfaceIndex == previous.interfaceIndex && retired.slot == previous.slot && !retired.IsClosed() {
			used[retired.generation] = true
		}
	}
	for generation, inUse := range used {
		if !inUse {
			return generation, nil
		}
	}
	return 0, E.New("every filter generation of interface ", previous.interfaceName, " is held by an attachment that could not detach")
}

type sharedRewriteDataPlane struct {
	access             sync.Mutex
	hooks              SharedPacketRewriteHooks
	backend            *commonEBPF.SharedPacketRewriteBackend
	attachments        map[string]*sharedRewriteAttachment
	retiredAttachments []*sharedRewriteAttachment
	hostAddresses      []netip.Addr
	priority           uint16
	enabled            bool
	ready              bool
	closed             bool
}

const maxRetiredSharedRewriteAttachments = 16

func (d *sharedRewriteDataPlane) retainRetiredAttachment(attachment *sharedRewriteAttachment) {
	if d == nil || attachment == nil || attachment.IsClosed() {
		return
	}
	if len(d.retiredAttachments) >= maxRetiredSharedRewriteAttachments {
		d.retiredAttachments = append(d.retiredAttachments[:0], d.retiredAttachments[1:]...)
	}
	d.retiredAttachments = append(d.retiredAttachments, attachment)
}

type sharedRewriteCallbackKind uint8

const (
	sharedRewriteCallbackPurgeUserspaceFlow sharedRewriteCallbackKind = iota
	sharedRewriteCallbackReady
	sharedRewriteCallbackWarnFlowPurge
)

type sharedRewriteCallbackEvent struct {
	kind          sharedRewriteCallbackKind
	attachments   []string
	interfaceName string
	err           error
}

type sharedRewriteCallbackEvents []sharedRewriteCallbackEvent

func (e *sharedRewriteCallbackEvents) purgeUserspaceFlow() {
	*e = append(*e, sharedRewriteCallbackEvent{kind: sharedRewriteCallbackPurgeUserspaceFlow})
}

func (e *sharedRewriteCallbackEvents) ready(attachments []string) {
	*e = append(*e, sharedRewriteCallbackEvent{
		kind:        sharedRewriteCallbackReady,
		attachments: attachments,
	})
}

func (e *sharedRewriteCallbackEvents) warnFlowPurge(interfaceName string, err error) {
	*e = append(*e, sharedRewriteCallbackEvent{
		kind:          sharedRewriteCallbackWarnFlowPurge,
		interfaceName: interfaceName,
		err:           err,
	})
}

func (e sharedRewriteCallbackEvents) dispatch(hooks SharedPacketRewriteHooks) {
	for _, event := range e {
		switch event.kind {
		case sharedRewriteCallbackPurgeUserspaceFlow:
			if hooks.PurgeUserspaceFlow != nil {
				hooks.PurgeUserspaceFlow()
			}
		case sharedRewriteCallbackReady:
			if hooks.Ready != nil {
				hooks.Ready(event.attachments)
			}
		case sharedRewriteCallbackWarnFlowPurge:
			if hooks.WarnFlowPurge != nil {
				hooks.WarnFlowPurge(event.interfaceName, event.err)
			}
		}
	}
}

type sharedRewriteAttachment struct {
	interfaceName  string
	interfaceIndex int
	slot           int
	generation     int
	// lock is a *sharedTCInterfaceLock in production.
	lock          io.Closer
	ingressFilter *netlink.BpfFilter
	egressFilter  *netlink.BpfFilter
	ingressName   string
	egressName    string
	icmpName      string
	ingressHandle uint16
	egressHandle  uint16
	icmpHandle    uint16
	ingressLink   link.Link
	egressLink    link.Link
	// localnet is this attachment's lease on the interface's route_localnet,
	// which other runtimes on the same interface may share.
	localnet       *core.InstanceLease
	attachmentType string
	// icmpFilter/icmpLink are the icmp_echo_reply shared-reply filter, attached
	// alongside ingressFilter/ingressLink (same interface, same direction)
	// only when backend.ICMPEchoReplyEnabled(); nil whenever that feature is
	// off, the same as every other field here is nil when it does not apply.
	icmpFilter *netlink.BpfFilter
	icmpLink   link.Link
	// detachFilter is nil in production; tests inject detach failures to prove
	// that ownership is retained for a later cleanup retry.
	detachFilter func(*netlink.BpfFilter) error
}

func newSharedRewriteDataPlane(hooks SharedPacketRewriteHooks, priority uint16) *sharedRewriteDataPlane {
	return &sharedRewriteDataPlane{
		hooks:       hooks,
		attachments: make(map[string]*sharedRewriteAttachment),
		priority:    priority,
	}
}

func (d *sharedRewriteDataPlane) reconcile(interfaceNames []string, hostAddresses []netip.Addr) (reconcileErr error) {
	if d == nil {
		return nil
	}
	var callbackEvents sharedRewriteCallbackEvents
	d.access.Lock()
	defer func() {
		d.access.Unlock()
		callbackEvents.dispatch(d.hooks)
	}()
	if d.closed {
		return E.New("shared packet-rewrite runtime is closed")
	}
	defer func() {
		reconcileErr = E.Errors(reconcileErr, d.closeRetiredLocked(&callbackEvents))
	}()
	changed := false
	// Queue this on every return, including an early error exit, so a rollback
	// that already detached something never leaves stale NAT entries behind
	// just because reconcile gave up partway. Delivery happens after unlock.
	defer func() {
		if changed {
			callbackEvents.purgeUserspaceFlow()
		}
	}()

	desired := make(map[string]netlink.Link, len(interfaceNames))
	for _, interfaceName := range interfaceNames {
		device, err := netlink.LinkByName(interfaceName)
		if tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return E.Cause(err, "find shared packet-rewrite interface ", interfaceName)
		}
		framing, err := tcLinkFraming(device)
		if err != nil {
			return err
		}
		if framing != commonEBPF.TCLinkFramingEthernet {
			return E.New("shared packet-rewrite interface ", interfaceName, " must use Ethernet framing")
		}
		desired[interfaceName] = device
	}

	backend := d.backend
	newBackend := false
	if len(desired) > 0 && backend == nil {
		var err error
		if d.hooks.PrepareBackend == nil {
			return E.New("shared packet-rewrite backend factory is unavailable")
		}
		backend, err = d.hooks.PrepareBackend()
		if err != nil {
			return E.Cause(err, "initialize shared packet-rewrite backend")
		}
		newBackend = true
	}
	hostChanged := backend != nil && !slices.Equal(d.hostAddresses, hostAddresses)
	if hostChanged {
		if err := backend.UpdateHostAddresses(hostAddresses); err != nil {
			if newBackend {
				return E.Errors(
					E.Cause(err, "update shared packet-rewrite host addresses"),
					backend.Close(),
				)
			}
			return E.Cause(err, "update shared packet-rewrite host addresses")
		}
	}

	current := make(map[string]*sharedRewriteAttachment, len(d.attachments))
	for name, attachment := range d.attachments {
		current[name] = attachment
	}
	candidate := make(map[string]*sharedRewriteAttachment, len(desired))
	created := make([]*sharedRewriteAttachment, 0, len(desired))
	retired := make([]*sharedRewriteAttachment, 0, len(d.attachments))
	changed = hostChanged
	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	slices.Sort(names)

	cleanupCandidates := func(cause error) error {
		for _, attachment := range slices.Backward(created) {
			cause = E.Errors(cause, attachment.Close())
			if !attachment.IsClosed() {
				d.retainRetiredAttachment(attachment)
			}
		}
		if hostChanged {
			rollbackErr := backend.UpdateHostAddresses(d.hostAddresses)
			if rollbackErr != nil {
				cause = E.Errors(cause, E.Cause(rollbackErr, "rollback shared packet-rewrite host addresses"))
			}
		}
		if newBackend && len(d.retiredAttachments) == 0 {
			cause = E.Errors(cause, backend.Close())
		} else if newBackend {
			// A filter or TCX link still references this backend's programs. Keep
			// the backend reachable until a later cleanup retry detaches it.
			d.backend = backend
		}
		return cause
	}

	for _, name := range names {
		device := desired[name]
		previous := current[name]
		if previous != nil && device.Attrs().Index == previous.interfaceIndex {
			if err := claimSharedRewriteLocalnet(name, &previous.localnet); err != nil {
				return cleanupCandidates(E.Cause(err, "repair route_localnet for ", name))
			}
			healthy, err := previous.healthy(device, d.priority, backend.ICMPEchoReplyEnabled())
			if err != nil {
				return cleanupCandidates(E.Cause(err, "inspect shared packet-rewrite attachment on ", name))
			}
			if healthy {
				candidate[name] = previous
				delete(current, name)
				continue
			}
		}
		if previous != nil {
			retired = append(retired, previous)
		}
		options := sharedRewriteAttachmentOptions{}
		if previous != nil && device.Attrs().Index == previous.interfaceIndex {
			if lock, shared := previous.lock.(*sharedTCInterfaceLock); shared && lock.holders != nil {
				generation, err := d.replacementGenerationLocked(previous)
				if err != nil {
					return cleanupCandidates(E.Cause(err, "replace shared packet-rewrite interface ", name))
				}
				options = sharedRewriteAttachmentOptions{lock: lock, generation: generation}
			}
		}
		attachment, err := attachSharedRewriteInterfaceWithOptions(device, backend, d.priority, options)
		if err != nil {
			return cleanupCandidates(E.Cause(err, "attach shared packet-rewrite interface ", name))
		}
		candidate[name] = attachment
		created = append(created, attachment)
		changed = true
	}
	for _, previous := range current {
		retired = append(retired, previous)
		changed = true
	}

	wantEnabled := len(candidate) > 0
	if wantEnabled != d.enabled {
		var err error
		if wantEnabled {
			err = backend.Enable()
		} else if backend != nil {
			err = backend.Disable()
		}
		if err != nil {
			return cleanupCandidates(err)
		}
		changed = true
	}

	var closeErr error
	for _, previous := range retired {
		replacement := candidate[previous.interfaceName]
		if replacement != nil && replacement.interfaceIndex == previous.interfaceIndex {
			if replacement.localnet == nil {
				replacement.localnet, previous.localnet = previous.localnet, nil
			}
			// Each holds the slot, so a previous attachment that cannot detach
			// keeps it, and with it the names its filters still carry.
			if err := d.detachLocked(previous, &callbackEvents); err != nil {
				// The candidate is already active. Keep it as the committed state
				// and report the old attachment cleanup failure to the caller.
				closeErr = E.Errors(closeErr, E.Cause(err, "detach shared packet-rewrite interface ", previous.interfaceName))
				changed = true
				if !previous.IsClosed() {
					d.retainRetiredAttachment(previous)
				}
			}
		} else {
			if err := d.detachLocked(previous, &callbackEvents); err != nil {
				// Continue committing the candidate topology so a stale attachment
				// cannot prevent a newly discovered interface from being used.
				closeErr = E.Errors(closeErr, E.Cause(err, "detach shared packet-rewrite interface ", previous.interfaceName))
				changed = true
				if !previous.IsClosed() {
					d.retainRetiredAttachment(previous)
				}
			}
		}
	}

	d.backend = backend
	d.attachments = candidate
	d.hostAddresses = slices.Clone(hostAddresses)
	d.enabled = wantEnabled
	if wantEnabled && !d.ready {
		d.ready = true
		callbackEvents.ready(d.attachmentDescriptionsLocked())
	}

	return closeErr
}

// healthCheck is the read-only first stage of the periodic watchdog. It avoids
// backend creation, map updates, flow purges, sysctl writes and attachment
// transactions while the already-owned topology is healthy.
func (d *sharedRewriteDataPlane) healthCheck(interfaceNames []string, hostAddresses []netip.Addr) (bool, error) {
	if d == nil {
		return true, nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	if d.closed || len(d.retiredAttachments) != 0 {
		return false, nil
	}
	desired := make(map[string]netlink.Link, len(interfaceNames))
	for _, interfaceName := range interfaceNames {
		device, err := netlink.LinkByName(interfaceName)
		if tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		framing, err := tcLinkFraming(device)
		if err != nil {
			return false, err
		}
		if framing != commonEBPF.TCLinkFramingEthernet {
			return false, nil
		}
		desired[interfaceName] = device
	}
	wantEnabled := len(desired) > 0
	if d.enabled != wantEnabled || len(d.attachments) != len(desired) {
		return false, nil
	}
	if wantEnabled {
		if d.backend == nil || d.backend.IsClosed() || d.backend.RequiresRebuild() ||
			!slices.Equal(d.hostAddresses, hostAddresses) {
			return false, nil
		}
	}
	for name, device := range desired {
		attachment := d.attachments[name]
		if attachment == nil || attachment.interfaceIndex != device.Attrs().Index {
			return false, nil
		}
		localnet, err := os.ReadFile(sharedRewriteLocalnetPath(name))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
		if strings.TrimSpace(string(localnet)) != "1" {
			return false, nil
		}
		healthy, err := attachment.healthy(device, d.priority, d.backend.ICMPEchoReplyEnabled())
		if err != nil || !healthy {
			return false, err
		}
	}
	return true, nil
}

func (d *sharedRewriteDataPlane) detachLocked(attachment *sharedRewriteAttachment, callbackEvents *sharedRewriteCallbackEvents) error {
	if d.backend != nil {
		if _, _, err := d.backend.PurgeInterfaceFlows(uint32(attachment.interfaceIndex), d.backend.MapCapacity().Proxy); err != nil {
			callbackEvents.warnFlowPurge(attachment.interfaceName, err)
		}
	}
	return attachment.Close()
}

func (d *sharedRewriteDataPlane) isEnabled() bool {
	if d == nil {
		return false
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.enabled
}

func (d *sharedRewriteDataPlane) attachmentDescriptions() []string {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.attachmentDescriptionsLocked()
}

func (d *sharedRewriteDataPlane) attachmentDescriptionsLocked() []string {
	descriptions := make([]string, 0, len(d.attachments))
	for _, attachment := range d.attachments {
		descriptions = append(descriptions, attachment.interfaceName+"("+attachment.attachmentType+")")
	}
	slices.Sort(descriptions)
	return descriptions
}

// attachmentDiagnostics returns the structured attachment snapshot. Shared
// packet-rewrite accepts only Ethernet-framed interfaces.
func (d *sharedRewriteDataPlane) attachmentDiagnostics() []commonEBPF.AttachmentInfo {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	diagnostics := make([]commonEBPF.AttachmentInfo, 0, len(d.attachments))
	for _, attachment := range d.attachments {
		diagnostics = append(diagnostics, commonEBPF.AttachmentInfo{
			InterfaceName:  attachment.interfaceName,
			InterfaceIndex: attachment.interfaceIndex,
			Role:           "shared",
			Framing:        "ethernet",
			Mechanism:      attachment.attachmentType,
			ICMPEchoReply:  attachment.icmpFilter != nil || attachment.icmpLink != nil,
			Slot:           attachment.slot,
		})
	}
	slices.SortFunc(diagnostics, func(a, b commonEBPF.AttachmentInfo) int {
		return strings.Compare(a.InterfaceName, b.InterfaceName)
	})
	return diagnostics
}

func (d *sharedRewriteDataPlane) Close() error {
	if d == nil {
		return nil
	}
	var callbackEvents sharedRewriteCallbackEvents
	d.access.Lock()
	defer func() {
		d.access.Unlock()
		callbackEvents.dispatch(d.hooks)
	}()
	if d.closed {
		return nil
	}
	var closeErr error
	if d.enabled && d.backend != nil {
		closeErr = d.backend.Disable()
		d.enabled = false
	}
	for name, attachment := range d.attachments {
		closeErr = E.Errors(closeErr, d.detachLocked(attachment, &callbackEvents))
		if attachment.IsClosed() {
			delete(d.attachments, name)
		}
	}
	closeErr = E.Errors(closeErr, d.closeRetiredLocked(&callbackEvents))
	if len(d.attachments) != 0 || len(d.retiredAttachments) != 0 {
		return closeErr
	}
	if d.backend != nil {
		closeErr = E.Errors(closeErr, d.backend.Close())
		if d.backend.IsClosed() {
			d.backend = nil
		}
	}
	if d.backend == nil {
		d.closed = true
	}
	return closeErr
}

func (d *sharedRewriteDataPlane) closeRetiredLocked(callbackEvents *sharedRewriteCallbackEvents) error {
	var closeErr error
	for _, attachment := range d.retiredAttachments {
		closeErr = E.Errors(closeErr, d.detachLocked(attachment, callbackEvents))
	}
	d.retiredAttachments = openSharedRewriteAttachments(d.retiredAttachments)
	return closeErr
}

func openSharedRewriteAttachments(attachments []*sharedRewriteAttachment) []*sharedRewriteAttachment {
	attachments = slices.DeleteFunc(attachments, (*sharedRewriteAttachment).IsClosed)
	if len(attachments) == 0 {
		return nil
	}
	return attachments
}

func attachSharedRewriteInterface(
	device netlink.Link,
	backend *commonEBPF.SharedPacketRewriteBackend,
	priority uint16,
) (*sharedRewriteAttachment, error) {
	return attachSharedRewriteInterfaceWithOptions(device, backend, priority, sharedRewriteAttachmentOptions{})
}

func attachSharedRewriteInterfaceWithOptions(
	device netlink.Link,
	backend *commonEBPF.SharedPacketRewriteBackend,
	priority uint16,
	options sharedRewriteAttachmentOptions,
) (*sharedRewriteAttachment, error) {
	name := device.Attrs().Name
	attachment := &sharedRewriteAttachment{interfaceName: name, interfaceIndex: device.Attrs().Index}
	var err error
	cleanup := func(err error) (*sharedRewriteAttachment, error) {
		return nil, E.Errors(err, attachment.Close())
	}
	var lock *sharedTCInterfaceLock
	if options.lock != nil {
		lock = options.lock.share()
		attachment.generation = options.generation
	} else {
		slot, err := acquireTCInterfaceLock(name, device.Attrs().Index)
		if err != nil {
			return nil, err
		}
		lock = newSharedTCInterfaceLock(slot)
	}
	attachment.lock = lock
	attachment.slot = lock.Index()
	ingress := tcSlotFilter(attachment.slot, attachment.generation, tcFilterRoleRewriteIngress)
	egress := tcSlotFilter(attachment.slot, attachment.generation, tcFilterRoleRewriteEgress)
	icmp := tcSlotFilter(attachment.slot, attachment.generation, tcFilterRoleRewriteICMP)
	attachment.ingressName, attachment.ingressHandle = ingress.name, ingress.handle
	attachment.egressName, attachment.egressHandle = egress.name, egress.handle
	attachment.icmpName, attachment.icmpHandle = icmp.name, icmp.handle
	if err = claimSharedRewriteLocalnet(name, &attachment.localnet); err != nil {
		return cleanup(err)
	}
	// TCX keeps the priority contract through the ordered attach.
	if tcxSupport.Load() != tcxSupportUnavailable {
		attachment.egressLink, err = coreAttachTCXOrdered(
			device.Attrs().Index,
			CiliumEBPF.AttachTCXEgress,
			rawSharedPacketRewriteBackend(backend).EgressProgram(),
			priority,
		)
		if err == nil {
			attachment.ingressLink, err = coreAttachTCXOrdered(
				device.Attrs().Index,
				CiliumEBPF.AttachTCXIngress,
				rawSharedPacketRewriteBackend(backend).IngressProgram(),
				priority,
			)
		}
		if err == nil && backend.ICMPEchoReplyEnabled() {
			attachment.icmpLink, err = coreAttachTCXOrdered(
				device.Attrs().Index,
				CiliumEBPF.AttachTCXIngress,
				rawSharedPacketRewriteBackend(backend).ICMPEchoSharedReplyProgram(commonEBPF.TCLinkFramingEthernet),
				priority,
			)
		}
		if err == nil {
			tcxSupport.Store(tcxSupportAvailable)
			attachment.attachmentType = "tcx"
			return attachment, nil
		}
		_ = attachment.closeLinks()
		// Without a known TCX order, clsact still honors the priority.
		if !tcxUnsupportedError(err) && !errors.Is(err, core.ErrTCXOrderUnavailable) {
			return cleanup(err)
		}
		if tcxUnsupportedError(err) {
			tcxSupport.CompareAndSwap(tcxSupportUnknown, tcxSupportUnavailable)
		}
	}
	if err = ensureTCClsact(device); err != nil {
		return cleanup(err)
	}
	attachment.egressFilter, err = attachTCFilter(device, netlink.HANDLE_MIN_EGRESS, rawSharedPacketRewriteBackend(backend).EgressProgramFD(), attachment.egressName, attachment.egressHandle, priority)
	if err != nil {
		return cleanup(err)
	}
	attachment.ingressFilter, err = attachTCFilter(device, netlink.HANDLE_MIN_INGRESS, rawSharedPacketRewriteBackend(backend).IngressProgramFD(), attachment.ingressName, attachment.ingressHandle, priority)
	if err != nil {
		return cleanup(err)
	}
	if backend.ICMPEchoReplyEnabled() {
		attachment.icmpFilter, err = attachTCFilter(
			device,
			netlink.HANDLE_MIN_INGRESS,
			rawSharedPacketRewriteBackend(backend).ICMPEchoSharedReplyProgramFD(commonEBPF.TCLinkFramingEthernet),
			attachment.icmpName,
			attachment.icmpHandle,
			priority,
		)
		if err != nil {
			return cleanup(err)
		}
	}
	attachment.attachmentType = "clsact"
	return attachment, nil
}

func (a *sharedRewriteAttachment) healthy(device netlink.Link, priority uint16, icmpEchoReplyEnabled bool) (bool, error) {
	if a.ingressLink != nil || a.egressLink != nil {
		ingress, err := tcxLinkAttached(a.ingressLink, a.interfaceIndex, CiliumEBPF.AttachTCXIngress)
		if err != nil || !ingress {
			return false, err
		}
		egress, err := tcxLinkAttached(a.egressLink, a.interfaceIndex, CiliumEBPF.AttachTCXEgress)
		if err != nil || !egress || !icmpEchoReplyEnabled {
			return egress, err
		}
		return tcxLinkAttached(a.icmpLink, a.interfaceIndex, CiliumEBPF.AttachTCXIngress)
	}
	ingress, err := tcFilterAttached(device, netlink.HANDLE_MIN_INGRESS, a.ingressName, a.ingressHandle, priority)
	if err != nil || !ingress {
		return false, err
	}
	egress, err := tcFilterAttached(device, netlink.HANDLE_MIN_EGRESS, a.egressName, a.egressHandle, priority)
	if err != nil || !egress || !icmpEchoReplyEnabled {
		return egress, err
	}
	return tcFilterAttached(device, netlink.HANDLE_MIN_INGRESS, a.icmpName, a.icmpHandle, priority)
}

func (a *sharedRewriteAttachment) closeLinks() error {
	var closeErr error
	if a.ingressLink != nil {
		closeErr = closeOwned(&a.ingressLink)
	}
	if a.egressLink != nil {
		closeErr = E.Errors(closeErr, closeOwned(&a.egressLink))
	}
	if a.icmpLink != nil {
		closeErr = E.Errors(closeErr, closeOwned(&a.icmpLink))
	}
	return closeErr
}

func (a *sharedRewriteAttachment) IsClosed() bool {
	return a == nil || a.ingressFilter == nil && a.egressFilter == nil && a.icmpFilter == nil &&
		a.ingressLink == nil && a.egressLink == nil && a.icmpLink == nil &&
		a.localnet == nil && a.lock == nil
}

func (a *sharedRewriteAttachment) Close() error {
	if a == nil {
		return nil
	}
	detach := a.detachFilter
	if detach == nil {
		detach = detachTCFilter
	}
	closeErr := E.Errors(a.closeLinks(),
		detachTCFilterOwnedWith(&a.ingressFilter, detach),
		detachTCFilterOwnedWith(&a.egressFilter, detach),
		detachTCFilterOwnedWith(&a.icmpFilter, detach),
	)
	if a.ingressFilter != nil || a.egressFilter != nil || a.icmpFilter != nil ||
		a.ingressLink != nil || a.egressLink != nil || a.icmpLink != nil {
		return closeErr
	}
	if err := releaseSharedRewriteLocalnet(a.interfaceName, &a.localnet); err != nil {
		return E.Errors(closeErr, err)
	}
	if a.lock != nil {
		closeErr = E.Errors(closeErr, closeOwned(&a.lock))
	}
	return closeErr
}

func sharedRewriteLocalnetPath(interfaceName string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/route_localnet"
}

func enableSharedRewriteLocalnet(interfaceName string) (bool, error) {
	return ensureSharedRewriteLocalnet(interfaceName)
}

func ensureSharedRewriteLocalnet(interfaceName string) (bool, error) {
	value, err := os.ReadFile(sharedRewriteLocalnetPath(interfaceName))
	if err != nil {
		return false, E.Cause(err, "read route_localnet for ", interfaceName)
	}
	switch strings.TrimSpace(string(value)) {
	case "1":
		return false, nil
	case "0":
		if err = os.WriteFile(sharedRewriteLocalnetPath(interfaceName), []byte("1"), 0o644); err != nil {
			return false, E.Cause(err, "enable route_localnet for ", interfaceName)
		}
		return true, nil
	default:
		return false, E.New("unexpected route_localnet value for ", interfaceName)
	}
}

func restoreSharedRewriteLocalnet(interfaceName string) error {
	path := sharedRewriteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return nil
	}
	if err = os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return E.Cause(err, "restore route_localnet for ", interfaceName)
	}
	return nil
}

// backendStateLocked reports the two conditions that make another attach
// pointless. A backend that has not been built yet is neither: the next attempt
// may manage to build it.
func (d *sharedRewriteDataPlane) backendStateLocked() (closed bool, requiresRebuild bool) {
	if d.backend == nil {
		return false, false
	}
	return d.backend.IsClosed(), d.backend.RequiresRebuild()
}
