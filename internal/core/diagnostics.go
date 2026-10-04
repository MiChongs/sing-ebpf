//go:build with_ebpf && (linux || android)

package core

// AttachmentInfo describes one active kernel attachment without exposing the
// loader's map, program, link, or file-descriptor representation.
type AttachmentInfo struct {
	InterfaceName  string `json:"interface_name"`
	InterfaceIndex int    `json:"interface_index,omitempty"`
	Role           string `json:"role"`
	Framing        string `json:"framing"`
	Mechanism      string `json:"mechanism"`
	ICMPEchoReply  bool   `json:"icmp_echo_reply"`
	// Slot is the interface instance slot this runtime holds. Several
	// sing-ebpf runtimes can attach to one interface; each holds its own slot,
	// which keys its clsact filter names and handles.
	Slot int `json:"slot"`
}

// TCNetworkInfo is the stable userspace-visible part of a TC runtime's
// delivery and policy-routing state. It intentionally omits netlink objects,
// routes, rules, sysctl ownership records, and file descriptors.
type TCNetworkInfo struct {
	DeliveryInterface      string
	DeliveryInterfaceIndex int
	RoutingMark            uint32
	RoutingTable           int
	RoutingPriority        int
	// RoutingSlot is the policy-routing instance slot of this runtime. Slot 0
	// is the one single-instance builds used.
	RoutingSlot int
}

// TCDiagnostics is a value-only snapshot of the effective TC runtime. It
// deliberately exposes neither kernel object handles nor loader internals;
// callers can use it to answer which attachment and delivery path is active
// without taking ownership of the runtime or scanning maps.
type TCDiagnostics struct {
	NetworkInfo            TCNetworkInfo
	ListenerLookupMode     string
	AttachmentMode         string
	AttachmentCount        int
	RetiredAttachmentCount int
	RetiredDeliveryCount   int
	Priority               uint16
	RequiresRebuild        bool
}
