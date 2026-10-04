//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestLegacyCgroupProgramLinkRetainsTargetAfterDetachFailure(t *testing.T) {
	cgroupFile, err := os.Create(filepath.Join(t.TempDir(), "cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	programLink := &legacyCgroupProgramLink{
		cgroupFile: cgroupFile,
		detachProgram: func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error {
			attempts++
			if attempts == 1 {
				return unix.EBUSY
			}
			return nil
		},
	}
	if err = programLink.Close(); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("unexpected first close error: %v", err)
	}
	if programLink.IsClosed() {
		t.Fatal("legacy cgroup target was discarded after a failed detach")
	}
	if _, err = cgroupFile.Stat(); err != nil {
		t.Fatalf("legacy cgroup target was closed after a failed detach: %v", err)
	}
	if err = programLink.Close(); err != nil {
		t.Fatalf("retry legacy cgroup detach: %v", err)
	}
	if !programLink.IsClosed() {
		t.Fatal("legacy cgroup target remained open after a successful detach")
	}
}

type retryableTestCgroupProgramLink struct {
	failures int
	closed   bool
}

func (l *retryableTestCgroupProgramLink) Close() error {
	if l.closed {
		return nil
	}
	if l.failures > 0 {
		l.failures--
		return unix.EBUSY
	}
	l.closed = true
	return nil
}

func (l *retryableTestCgroupProgramLink) IsClosed() bool { return l.closed }

func replaceCgroupAttachOperations(
	t *testing.T,
	linkErr error,
	rawAttach func(link.RawAttachProgramOptions) error,
) {
	t.Helper()
	originalAttachRawLink := attachRawLink
	originalRawAttachProgram := rawAttachProgram
	originalQuery := queryCgroupPrograms
	t.Cleanup(func() {
		attachRawLink = originalAttachRawLink
		rawAttachProgram = originalRawAttachProgram
		queryCgroupPrograms = originalQuery
	})
	attachRawLink = func(link.RawLinkOptions) (*link.RawLink, error) {
		return nil, linkErr
	}
	rawAttachProgram = rawAttach
	// An empty hook: the only state in which the exclusive fallback would
	// otherwise be attempted.
	queryCgroupPrograms = func(link.QueryOptions) (*link.QueryResult, error) {
		return &link.QueryResult{}, nil
	}
}

// The process tracker shares the cgroup v2 root with the interception
// backend. If it could fall back to an unflagged attach, the root hook would
// enter single-program mode and the kernel would then reject the backend's
// own attachment with EPERM, which surfaced as "refusing to replace existing
// cgroup program owner" for sb_ebpf_conn4.
func TestSharedCgroupAttachNeverUsesExclusiveFallback(t *testing.T) {
	var flags []uint32
	replaceCgroupAttachOperations(t, unix.EPERM, func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EPERM
		}
		return nil
	})
	programLink, err := attachCgroupProgramShared(t.TempDir(), nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err == nil {
		_ = programLink.Close()
		t.Fatal("shared cgroup attach succeeded through an exclusive attachment")
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("shared cgroup attach error = %v, want EPERM", err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
		t.Fatalf("flags=%v, want only BPF_F_ALLOW_MULTI", flags)
	}
}

func TestSharedCgroupAttachUsesLegacyMulti(t *testing.T) {
	var flags []uint32
	replaceCgroupAttachOperations(t, unix.EINVAL, func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		return nil
	})
	programLink, err := attachCgroupProgramShared(t.TempDir(), nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	legacyLink, loaded := programLink.(*legacyCgroupProgramLink)
	if !loaded {
		t.Fatalf("link type = %T, want legacy cgroup link", programLink)
	}
	legacyLink.detachProgram = func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error { return nil }
	if err = legacyLink.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
		t.Fatalf("flags=%v, want only BPF_F_ALLOW_MULTI", flags)
	}
}

func TestExclusiveCgroupAttachKeepsLegacyFallbackOnEmptyHook(t *testing.T) {
	var flags []uint32
	replaceCgroupAttachOperations(t, unix.EINVAL, func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EINVAL
		}
		return nil
	})
	programLink, err := attachCgroupProgram(t.TempDir(), nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	legacyLink := programLink.(*legacyCgroupProgramLink)
	legacyLink.detachProgram = func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error { return nil }
	if err = legacyLink.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI, 0}) {
		t.Fatalf("flags=%v, want [ALLOW_MULTI, 0]", flags)
	}
}

func TestReclaimableCgroupProgram(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		flags    uint32
		count    int
		reclaim  bool
		scenario string
	}{
		{kernelProgramNameCgroupConnect4, unix.BPF_F_ALLOW_MULTI, 2, true, "stale backend program in multi mode"},
		{kernelProgramNameCgroupConnect4, 0, 1, true, "stale backend program in exclusive mode"},
		{kernelProgramNameProcessConnect4, 0, 1, true, "stale exclusive tracker blocks the hook"},
		{kernelProgramNameProcessConnect4, unix.BPF_F_ALLOW_OVERRIDE, 1, true, "stale override tracker blocks the hook"},
		{kernelProgramNameProcessConnect4, unix.BPF_F_ALLOW_MULTI, 1, false, "live multi tracker of this or another process"},
		{kernelProgramNameProcessRelease, unix.BPF_F_ALLOW_MULTI, 3, false, "multi tracker beside other owners"},
		{kernelProgramNameSelfConnect4, 0, 1, false, "self-bypass belongs to a process cgroup"},
		{"inet4_connect", 0, 1, false, "foreign owner"},
		{"", 0, 1, false, "unnamed foreign owner"},
	} {
		if got := reclaimableCgroupProgram(testCase.name, testCase.flags, testCase.count); got != testCase.reclaim {
			t.Errorf("%s: reclaimable(%q, %#x, %d) = %v, want %v",
				testCase.scenario, testCase.name, testCase.flags, testCase.count, got, testCase.reclaim)
		}
	}
}

func TestCgroupProgramNamePrefixes(t *testing.T) {
	for _, definition := range cgroupProgramDefinitions {
		if !strings.HasPrefix(definition.kernelProgramName, kernelProgramPrefixCgroup) {
			t.Errorf("interception program %q lacks prefix %q", definition.kernelProgramName, kernelProgramPrefixCgroup)
		}
	}
	for _, name := range []string{
		kernelProgramNameProcessConnect4,
		kernelProgramNameProcessConnect6,
		kernelProgramNameProcessSendmsg4,
		kernelProgramNameProcessSendmsg6,
		kernelProgramNameProcessRelease,
	} {
		if !strings.HasPrefix(name, kernelProgramPrefixProcessTracker) {
			t.Errorf("process tracker program %q lacks prefix %q", name, kernelProgramPrefixProcessTracker)
		}
		if strings.HasPrefix(name, kernelProgramPrefixCgroup) {
			t.Errorf("process tracker program %q would be reclaimed as an interception program", name)
		}
	}
}
