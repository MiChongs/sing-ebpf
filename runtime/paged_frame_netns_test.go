//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

// An AF_PACKET send of a frame that does not fit in a page keeps only the
// link-layer header in the skb's linear area. A veth hands that skb to its
// peer as is, so the peer's TC ingress sees the layout a driver that builds
// packets in page fragments produces when GRO is off: the IP and transport
// headers are outside the range direct packet access can read.
const (
	pagedFrameMTU           = 9000
	pagedFramePayloadLength = 6000
)

// sendPagedFrame raises the MTU on both ends of a veth pair and transmits
// frame from the client end, named clientLink in the client namespace.
func sendPagedFrame(
	t *testing.T,
	router netlink.Link,
	client *testNetworkNamespaceWorker,
	clientLink string,
	frame func(clientMAC net.HardwareAddr) []byte,
) {
	t.Helper()
	if err := netlink.LinkSetMTU(router, pagedFrameMTU); err != nil {
		t.Fatalf("raise the MTU of %s: %v", router.Attrs().Name, err)
	}
	client.run(t, func() error {
		link, err := netlink.LinkByName(clientLink)
		if err != nil {
			return err
		}
		if err = netlink.LinkSetMTU(link, pagedFrameMTU); err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		destination := &unix.SockaddrLinklayer{Ifindex: link.Attrs().Index, Halen: 6}
		copy(destination.Addr[:], router.Attrs().HardwareAddr)
		return unix.Sendto(fd, frame(link.Attrs().HardwareAddr), 0, destination)
	})
}

func putEthernetIPv4Header(frame []byte, dstMAC, srcMAC net.HardwareAddr, protocol uint8, source, destination netip.Addr) []byte {
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IP)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = protocol
	source4, destination4 := source.As4(), destination.As4()
	copy(ip[12:16], source4[:])
	copy(ip[16:20], destination4[:])
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip[:20], 10))
	return ip[20:]
}

// buildEthernetIPv4UDP builds a UDP datagram. Without checksummed it carries
// no checksum, which IPv4 allows and a rewrite must keep.
func buildEthernetIPv4UDP(dstMAC, srcMAC net.HardwareAddr, source, destination netip.AddrPort, payload []byte, checksummed bool) []byte {
	frame := make([]byte, 14+20+8+len(payload))
	udp := putEthernetIPv4Header(frame, dstMAC, srcMAC, unix.IPPROTO_UDP, source.Addr(), destination.Addr())
	binary.BigEndian.PutUint16(udp[0:2], source.Port())
	binary.BigEndian.PutUint16(udp[2:4], destination.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	if checksummed {
		checksum := ipv4TransportChecksum(source.Addr(), destination.Addr(), unix.IPPROTO_UDP, udp, 6)
		if checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(udp[6:8], checksum)
	}
	return frame
}

// buildEthernetIPv4TCPSYN builds a checksummed SYN that carries payload.
func buildEthernetIPv4TCPSYN(dstMAC, srcMAC net.HardwareAddr, source, destination netip.AddrPort, payload []byte) []byte {
	frame := make([]byte, 14+20+20+len(payload))
	tcp := putEthernetIPv4Header(frame, dstMAC, srcMAC, unix.IPPROTO_TCP, source.Addr(), destination.Addr())
	binary.BigEndian.PutUint16(tcp[0:2], source.Port())
	binary.BigEndian.PutUint16(tcp[2:4], destination.Port())
	binary.BigEndian.PutUint32(tcp[4:8], 0x5eb6c0de)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], ipv4TransportChecksum(source.Addr(), destination.Addr(), unix.IPPROTO_TCP, tcp, 16))
	return frame
}

// ipv4TransportChecksum sums the IPv4 pseudo-header and segment, skipping the
// checksum field at checksumOffset within segment.
func ipv4TransportChecksum(source, destination netip.Addr, protocol uint8, segment []byte, checksumOffset int) uint16 {
	pseudo := make([]byte, 12+len(segment))
	source4, destination4 := source.As4(), destination.As4()
	copy(pseudo[0:4], source4[:])
	copy(pseudo[4:8], destination4[:])
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	return internetChecksum(pseudo, 12+checksumOffset)
}
