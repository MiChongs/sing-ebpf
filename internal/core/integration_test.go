//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

const (
	integrationTestEnv = "SING_EBPF_INTEGRATION"
	testTCActShot      = uint32(2)
	testTCActUnspec    = ^uint32(0)
)

func requireEBPFIntegration(t testing.TB, action string) {
	t.Helper()
	if os.Getenv(integrationTestEnv) != "1" {
		t.Skip("set " + integrationTestEnv + "=1 to " + action)
	}
	if os.Geteuid() != 0 {
		t.Fatal("eBPF integration test requires root")
	}
}

// requireTCSocketAssignment skips tests of the TC socket-assignment object on
// kernels without its socket helpers (Linux 5.7 and later have them). The
// probe does not load the object, so a verifier regression still fails.
func requireTCSocketAssignment(t testing.TB) {
	t.Helper()
	for _, helper := range []asm.BuiltinFunc{asm.FnSkcLookupTcp, asm.FnSkAssign} {
		err := features.HaveProgramHelper(CiliumEBPF.SchedCLS, helper)
		if errors.Is(err, CiliumEBPF.ErrNotSupported) {
			t.Skipf("kernel lacks %s for TC socket assignment", helper)
		}
		if err != nil {
			t.Fatalf("probe %s: %v", helper, err)
		}
	}
}

func runTCProgram(t *testing.T, program *CiliumEBPF.Program, packet []byte) (uint32, []byte) {
	t.Helper()
	output := make([]byte, len(packet)+256)
	options := &CiliumEBPF.RunOptions{Data: packet, DataOut: output, Repeat: 1}
	action, err := program.Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.DataOut) < len(packet) {
		t.Fatalf("short program output: %d < %d", len(options.DataOut), len(packet))
	}
	return action, options.DataOut[:len(packet)]
}

func testIPv4TCPPacket(source, destination netip.Addr, sourcePort, destinationPort uint16) []byte {
	const ethernetHeaderLength = 14
	const ipv4HeaderLength = 20
	const tcpHeaderLength = 20
	packet := make([]byte, ethernetHeaderLength+ipv4HeaderLength+tcpHeaderLength)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
	ip := packet[ethernetHeaderLength:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], ipv4HeaderLength+tcpHeaderLength)
	ip[8] = 64
	ip[9] = unix.IPPROTO_TCP
	source4 := source.As4()
	destination4 := destination.As4()
	copy(ip[12:16], source4[:])
	copy(ip[16:20], destination4[:])
	tcp := ip[ipv4HeaderLength:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	return packet
}

func testIPv6TCPPacket(source, destination netip.Addr, sourcePort, destinationPort uint16, fragment *uint16) []byte {
	const ethernetHeaderLength = 14
	const ipv6HeaderLength = 40
	const fragmentHeaderLength = 8
	const tcpHeaderLength = 20
	transportOffset := ethernetHeaderLength + ipv6HeaderLength
	payloadLength := tcpHeaderLength
	if fragment != nil {
		transportOffset += fragmentHeaderLength
		payloadLength += fragmentHeaderLength
	}
	packet := make([]byte, ethernetHeaderLength+ipv6HeaderLength+payloadLength)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IPV6)
	ip := packet[ethernetHeaderLength:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLength))
	ip[6] = unix.IPPROTO_TCP
	ip[7] = 64
	if fragment != nil {
		ip[6] = unix.IPPROTO_FRAGMENT
		fragmentHeader := ip[ipv6HeaderLength:]
		fragmentHeader[0] = unix.IPPROTO_TCP
		binary.BigEndian.PutUint16(fragmentHeader[2:4], *fragment)
		binary.BigEndian.PutUint32(fragmentHeader[4:8], 0x42424242)
	}
	source6 := source.As16()
	destination6 := destination.As16()
	copy(ip[8:24], source6[:])
	copy(ip[24:40], destination6[:])
	tcp := packet[transportOffset:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	return packet
}
