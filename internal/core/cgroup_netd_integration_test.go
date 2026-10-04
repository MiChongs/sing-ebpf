//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// emulateNetdDevice makes the backend see an Android netd device whose pins
// live in a private bpffs directory, so that tests never touch a real
// /sys/fs/bpf/netd_shared.
func emulateNetdDevice(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("sing-ebpf-test-netd-%d-%s", os.Getpid(), t.Name()))
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Skipf("cannot create a bpffs pin directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	originalRoots := netdPinnedProgramRoots
	originalPresent := netdPresent
	netdPinnedProgramRoots = []string{dir}
	netdPresent = func() bool { return true }
	t.Cleanup(func() {
		netdPinnedProgramRoots = originalRoots
		netdPresent = originalPresent
	})
	return dir
}

// pinNetdProgram pins program where netd pins its connect4 program.
func pinNetdProgram(t *testing.T, dir string, program *CiliumEBPF.Program) {
	t.Helper()
	pin := filepath.Join(dir, "prog_netd_connect4_inet4_connect")
	if err := program.Pin(pin); err != nil {
		t.Skipf("cannot pin into bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })
}

// attachLikeNetd attaches program exclusively, as netd does on Android 15+,
// and returns its ID.
func attachLikeNetd(t *testing.T, cgroupFile *os.File, program *CiliumEBPF.Program) CiliumEBPF.ProgramID {
	t.Helper()
	err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  int(cgroupFile.Fd()),
		Program: program,
		Attach:  CiliumEBPF.AttachCGroupInet4Connect,
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := program.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	t.Cleanup(func() {
		for _, owner := range connect4ProgramIDs(t, cgroupFile) {
			if leftover, openErr := CiliumEBPF.NewProgramFromID(owner); openErr == nil {
				_ = rawDetachProgram(int(cgroupFile.Fd()), leftover, CiliumEBPF.AttachCGroupInet4Connect)
				_ = leftover.Close()
			}
		}
	})
	return id
}

func requireSingleProgramHook(t *testing.T, cgroupFile *os.File, context string) {
	t.Helper()
	flags, err := queryCgroupHookFlags(int(cgroupFile.Fd()), CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	if flags != 0 {
		t.Fatalf("%s: hook flags = %#x, want the single-program mode netd expects", context, flags)
	}
}

func requireConnect4Owners(t *testing.T, cgroupFile *os.File, want []CiliumEBPF.ProgramID, context string) {
	t.Helper()
	if ids := connect4ProgramIDs(t, cgroupFile); !slices.Equal(ids, want) {
		t.Fatalf("%s: connect4 programs = %v, want %v", context, ids, want)
	}
	requireSingleProgramHook(t, cgroupFile, context)
}

func requireConnect4Names(t *testing.T, cgroupFile *os.File, want []string, context string) {
	t.Helper()
	if names := connect4ProgramNames(t, cgroupFile); !slices.Equal(names, want) {
		t.Fatalf("%s: connect4 programs = %v, want %v", context, names, want)
	}
	requireSingleProgramHook(t, cgroupFile, context)
}

func requireTakeoverAndRestore(t *testing.T, path string, cgroupFile *os.File, port uint16, ownerID CiliumEBPF.ProgramID) {
	t.Helper()
	backend, err := attachTCPCgroupBackend(t, path, port)
	if err != nil {
		t.Fatalf("attach over a pass-through owner: %v", err)
	}
	if mode := backend.AttachModes()[kernelProgramNameCgroupConnect4]; mode != cgroupAttachModeNetdReplace {
		t.Fatalf("connect4 attach mode = %q, want %q", mode, cgroupAttachModeNetdReplace)
	}
	requireConnect4Names(t, cgroupFile, []string{kernelProgramNameCgroupConnect4}, "while attached")
	if err = backend.Close(); err != nil {
		t.Fatal(err)
	}
	requireConnect4Owners(t, cgroupFile, []CiliumEBPF.ProgramID{ownerID}, "after close")
}

// AOSP netd: the placeholder is pinned under netd_shared.
func TestCgroupBackendTakesOverPinnedNetdPlaceholderIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 94)
	dir := emulateNetdDevice(t)
	placeholder := newHookOwnerTestProgram(t, "connect4_inet4_")
	t.Cleanup(func() { _ = placeholder.Close() })
	pinNetdProgram(t, dir, placeholder)
	netdID := attachLikeNetd(t, cgroupFile, placeholder)
	requireTakeoverAndRestore(t, path, cgroupFile, 41094, netdID)
}

// Vendor and custom-ROM netd builds name and pin their programs differently,
// as on the device that reported "id=33 name=connect4_inet4_connect_4_19_v".
// The owner's instructions alone must be enough.
func TestCgroupBackendTakesOverUnpinnedPassThroughOwnerIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 97)
	emulateNetdDevice(t)
	placeholder := newHookOwnerTestProgram(t, "connect4_inet4_")
	t.Cleanup(func() { _ = placeholder.Close() })
	ownerID := attachLikeNetd(t, cgroupFile, placeholder)
	verdict := inspectPassThrough(placeholder.FD())
	if !verdict.known {
		t.Skip("this kernel withholds translated instructions")
	}
	requireTakeoverAndRestore(t, path, cgroupFile, 41097, ownerID)
}

// A backend that exited without restoring the placeholder leaves its own
// program as the single-program owner. Startup reclaim must give the hook
// back to netd's pinned program before taking it over again.
func TestCgroupBackendReclaimRestoresPinnedNetdPlaceholderIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 95)
	dir := emulateNetdDevice(t)
	placeholder := newHookOwnerTestProgram(t, "connect4_inet4_")
	t.Cleanup(func() { _ = placeholder.Close() })
	pinNetdProgram(t, dir, placeholder)
	netdID := attachLikeNetd(t, cgroupFile, placeholder)
	// The crashed backend's program replaced netd's and outlived its process.
	staleID := attachExclusiveTestProgram(t, cgroupFile, kernelProgramNameCgroupConnect4)
	requireConnect4Owners(t, cgroupFile, []CiliumEBPF.ProgramID{staleID}, "before start")
	requireTakeoverAndRestore(t, path, cgroupFile, 41095, netdID)
}

// Without netd's pin at hand, reclaim must still not empty the hook: an empty
// hook would end up in multi-program mode, which makes a restarting netd
// abort. A pass-through of our own keeps it as netd keeps it.
func TestCgroupBackendReclaimKeepsNetdHookSingleProgramIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 98)
	emulateNetdDevice(t)
	attachExclusiveTestProgram(t, cgroupFile, kernelProgramNameCgroupConnect4)
	// The placeholder stays attached after close, as it must on a device.
	t.Cleanup(func() {
		for _, owner := range connect4ProgramIDs(t, cgroupFile) {
			if leftover, openErr := CiliumEBPF.NewProgramFromID(owner); openErr == nil {
				_ = rawDetachProgram(int(cgroupFile.Fd()), leftover, CiliumEBPF.AttachCGroupInet4Connect)
				_ = leftover.Close()
			}
		}
	})
	backend, err := attachTCPCgroupBackend(t, path, 41098)
	if err != nil {
		t.Fatalf("attach with a stale takeover: %v", err)
	}
	if mode := backend.AttachModes()[kernelProgramNameCgroupConnect4]; mode != cgroupAttachModeNetdReplace {
		t.Fatalf("connect4 attach mode = %q, want %q", mode, cgroupAttachModeNetdReplace)
	}
	requireConnect4Names(t, cgroupFile, []string{kernelProgramNameCgroupConnect4}, "while attached")
	if err = backend.Close(); err != nil {
		t.Fatal(err)
	}
	requireConnect4Names(t, cgroupFile, []string{kernelProgramNameHookPlaceholder}, "after close")
}

// A program that does more than "return 1" stays, even when netd pinned it.
func TestCgroupBackendKeepsNetdProgramWithLogicIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 96)
	dir := emulateNetdDevice(t)
	program := newHookOwnerTestProgramWith(t, "connect4_inet4_", effectfulHookOwnerInstructions)
	t.Cleanup(func() { _ = program.Close() })
	pinNetdProgram(t, dir, program)
	netdID := attachLikeNetd(t, cgroupFile, program)
	if verdict := inspectPassThrough(program.FD()); !verdict.known {
		t.Skip("this kernel withholds translated instructions")
	}
	_, err := attachTCPCgroupBackend(t, path, 41096)
	if !errors.Is(err, ErrCgroupHookOccupied) || !errors.Is(err, errCgroupOwnerHasEffect) {
		t.Fatalf("attach error = %v, want ErrCgroupHookOccupied explained by errCgroupOwnerHasEffect", err)
	}
	requireConnect4Owners(t, cgroupFile, []CiliumEBPF.ProgramID{netdID}, "after refusal")
}

func TestInspectPassThroughIntegration(t *testing.T) {
	requireEBPFIntegration(t, "read translated instructions")
	passThrough := newHookOwnerTestProgram(t, "pass_through")
	t.Cleanup(func() { _ = passThrough.Close() })
	effectful := newHookOwnerTestProgramWith(t, "effectful", effectfulHookOwnerInstructions)
	t.Cleanup(func() { _ = effectful.Close() })
	verdict := inspectPassThrough(passThrough.FD())
	if !verdict.known {
		t.Skip("this kernel withholds translated instructions")
	}
	if !verdict.passThrough {
		t.Fatalf("return 1 judged %+v, want a pass-through", verdict)
	}
	if verdict = inspectPassThrough(effectful.FD()); !verdict.known || verdict.passThrough {
		t.Fatalf("context load judged %+v, want a known program with effect", verdict)
	}
}
