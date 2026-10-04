//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func dedicatedHookOwnerCgroup(t *testing.T, index int) (string, *os.File) {
	t.Helper()
	requireEBPFIntegration(t, "test cgroup hook ownership")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, root, index)
	if !dedicated {
		t.Skip("a dedicated test cgroup is required")
	}
	cgroupFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cgroupFile.Close() })
	return path, cgroupFile
}

func newHookOwnerTestProgram(t *testing.T, name string) *CiliumEBPF.Program {
	t.Helper()
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         name,
		Type:         CiliumEBPF.CGroupSockAddr,
		AttachType:   CiliumEBPF.AttachCGroupInet4Connect,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
	})
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup sock_addr programs are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	return program
}

// attachExclusiveTestProgram reproduces an unflagged legacy BPF_PROG_ATTACH.
// The returned ID stays attached after the program FD is closed, exactly like
// an attachment left behind by a process that has exited.
func attachExclusiveTestProgram(t *testing.T, cgroupFile *os.File, name string) CiliumEBPF.ProgramID {
	t.Helper()
	program := newHookOwnerTestProgram(t, name)
	defer program.Close()
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
		if leftover, openErr := CiliumEBPF.NewProgramFromID(id); openErr == nil {
			_ = rawDetachProgram(int(cgroupFile.Fd()), leftover, CiliumEBPF.AttachCGroupInet4Connect)
			_ = leftover.Close()
		}
	})
	return id
}

func connect4ProgramIDs(t *testing.T, cgroupFile *os.File) []CiliumEBPF.ProgramID {
	t.Helper()
	ids, err := queryCgroupProgramIDs(int(cgroupFile.Fd()), CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func connect4ProgramNames(t *testing.T, cgroupFile *os.File) []string {
	t.Helper()
	var names []string
	for _, id := range connect4ProgramIDs(t, cgroupFile) {
		program, err := CiliumEBPF.NewProgramFromID(id)
		if err != nil {
			t.Fatal(err)
		}
		info, err := program.Info()
		_ = program.Close()
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, info.Name)
	}
	return names
}

func attachTCPCgroupBackend(t *testing.T, path string, port uint16) (*CgroupBackend, error) {
	t.Helper()
	backend, err := prepareCgroupIntegrationBackend(path, true, false, false)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.LoadPrograms(port); err != nil {
		t.Fatal(err)
	}
	return backend, backend.Attach()
}

func TestQueryCgroupHookFlagsIntegration(t *testing.T) {
	_, cgroupFile := dedicatedHookOwnerCgroup(t, 90)
	attachExclusiveTestProgram(t, cgroupFile, "foreign_conn4")
	flags, err := queryCgroupHookFlags(int(cgroupFile.Fd()), CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	if flags != 0 {
		t.Fatalf("exclusive hook flags = %#x, want 0", flags)
	}
	flags, err = queryCgroupHookFlags(int(cgroupFile.Fd()), CiliumEBPF.AttachCGroupUDP4Sendmsg)
	if err != nil {
		t.Fatal(err)
	}
	if flags != 0 {
		t.Fatalf("empty hook flags = %#x, want 0", flags)
	}
}

// A process tracker attachment left in single-program mode by an earlier
// build used to make the backend fail with "sb_ebpf_conn4: refusing to replace
// existing cgroup program owner". Startup must reclaim it.
func TestCgroupBackendReclaimsStaleExclusiveProcessTrackerIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 91)
	staleID := attachExclusiveTestProgram(t, cgroupFile, kernelProgramNameProcessConnect4)
	if _, err := attachTCPCgroupBackend(t, path, 41091); err != nil {
		t.Fatalf("attach with a stale exclusive tracker: %v", err)
	}
	ids := connect4ProgramIDs(t, cgroupFile)
	if slices.Contains(ids, staleID) {
		t.Fatalf("stale tracker program %d is still attached: %v", staleID, ids)
	}
	if names := connect4ProgramNames(t, cgroupFile); !slices.Equal(names, []string{kernelProgramNameCgroupConnect4}) {
		t.Fatalf("connect4 programs = %v, want only the interception backend", names)
	}
}

// A foreign single-program owner must survive and be named in the error.
func TestCgroupBackendPreservesForeignExclusiveOwnerIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 92)
	foreignID := attachExclusiveTestProgram(t, cgroupFile, "foreign_conn4")
	_, err := attachTCPCgroupBackend(t, path, 41092)
	if !errors.Is(err, ErrCgroupHookOccupied) {
		t.Fatalf("attach error = %v, want ErrCgroupHookOccupied", err)
	}
	if !strings.Contains(err.Error(), "name=foreign_conn4") {
		t.Fatalf("attach error %q does not name the foreign owner", err)
	}
	if ids := connect4ProgramIDs(t, cgroupFile); !slices.Equal(ids, []CiliumEBPF.ProgramID{foreignID}) {
		t.Fatalf("connect4 programs after refusal = %v, want only foreign %d", ids, foreignID)
	}
}

// The tracker's shared attachment keeps the hook in multi-program mode, so the
// backend attaches beside it and startup reclaim leaves it alone.
func TestCgroupBackendCoexistsWithLiveSharedProcessTrackerIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 93)
	tracker := newHookOwnerTestProgram(t, kernelProgramNameProcessConnect4)
	t.Cleanup(func() { _ = tracker.Close() })
	trackerLink, err := attachCgroupProgramShared(path, tracker, CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trackerLink.Close() })
	flags, err := queryCgroupHookFlags(int(cgroupFile.Fd()), CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.BPF_F_ALLOW_MULTI == 0 {
		t.Fatalf("shared tracker left hook flags %#x, want BPF_F_ALLOW_MULTI", flags)
	}
	if _, err = attachTCPCgroupBackend(t, path, 41093); err != nil {
		t.Fatalf("attach beside a live tracker: %v", err)
	}
	names := connect4ProgramNames(t, cgroupFile)
	slices.Sort(names)
	want := []string{kernelProgramNameCgroupConnect4, kernelProgramNameProcessConnect4}
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("connect4 programs = %v, want %v", names, want)
	}
}
