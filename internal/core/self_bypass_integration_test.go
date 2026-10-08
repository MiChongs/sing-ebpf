//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const selfBypassHelperEnv = "SING_EBPF_SELF_BYPASS_HELPER"

// TestSelfBypassHelperProcess is the child process of the self-bypass
// integration tests, not a test of its own. For every input line it creates a
// UDP socket, connects it to the loopback discard port when the line is
// "connect", and prints the socket cookie. Sockets stay open until exit.
func TestSelfBypassHelperProcess(t *testing.T) {
	if os.Getenv(selfBypassHelperEnv) != "1" {
		return
	}
	var sockets []int
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cookie, fd, err := selfBypassTestSocket(scanner.Text() == "connect")
		if err != nil {
			fmt.Println("error:", err)
			continue
		}
		sockets = append(sockets, fd)
		fmt.Println(cookie)
	}
	for _, fd := range sockets {
		_ = unix.Close(fd)
	}
	os.Exit(0)
}

func selfBypassTestSocket(connect bool) (uint64, int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, -1, err
	}
	if connect {
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: selfBypassProbePort, Addr: [4]byte{127, 0, 0, 1}})
	}
	var cookie uint64
	if err == nil {
		cookie, err = unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	}
	if err != nil {
		_ = unix.Close(fd)
		return 0, -1, err
	}
	return cookie, fd, nil
}

type selfBypassTestHelper struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
}

// startSelfBypassTestHelper starts a child process that inherits the cgroup
// of the test process, like the sessions of an SSH server embedded in the
// consumer.
func startSelfBypassTestHelper(t *testing.T) *selfBypassTestHelper {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestSelfBypassHelperProcess$")
	command.Env = append(os.Environ(), selfBypassHelperEnv+"=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	helper := &selfBypassTestHelper{command: command, input: input, output: bufio.NewScanner(output)}
	t.Cleanup(func() {
		_ = helper.input.Close()
		_ = helper.command.Wait()
	})
	return helper
}

func (h *selfBypassTestHelper) cookie(t *testing.T, connect bool) uint64 {
	t.Helper()
	request := "socket\n"
	if connect {
		request = "connect\n"
	}
	if _, err := io.WriteString(h.input, request); err != nil {
		t.Fatal(err)
	}
	if !h.output.Scan() {
		t.Fatalf("self-bypass helper exited: %v", h.output.Err())
	}
	line := strings.TrimSpace(h.output.Text())
	cookie, err := strconv.ParseUint(line, 10, 64)
	if err != nil {
		t.Fatalf("self-bypass helper: %s", line)
	}
	return cookie
}

func moveTestProcessToCgroup(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Skipf("cannot move the test process into %s: %v", path, err)
	}
}

func selfBypassMarked(t *testing.T, bypass *SelfBypass, cookie uint64) bool {
	t.Helper()
	var metadata uint32
	if err := bypass.sockets.Lookup(&cookie, &metadata); err != nil {
		return false
	}
	return metadata&SocketMetadataSelfBypass != 0
}

// TestSelfBypassCgroupMarksOnlyOwnerProcess reproduces a consumer that owns
// an exclusive cgroup and later starts child processes there. The hooks must
// keep excluding the consumer's own sockets while the children's sockets stay
// unmarked, so local interception still applies to them.
func TestSelfBypassCgroupMarksOnlyOwnerProcess(t *testing.T) {
	requireEBPFIntegration(t, "attach self-bypass hooks to an exclusive process cgroup")
	if _, err := selfBypassOwnerTGID(); err != nil {
		t.Skipf("automatic self-bypass marking is unavailable: %v", err)
	}
	enterDedicatedSelfBypassCgroup(t, 300)

	bypass, err := NewSelfBypassWithCapacity(64)
	if err != nil {
		t.Fatal(err)
	}
	defer bypass.Close()
	attachErr := bypass.AttachCgroup(SelfBypassCgroupConfig{EnableTCP: true, EnableUDP: true, EnableIPv6: true})
	if !bypass.CgroupAttached() {
		t.Fatalf("self-bypass hooks were not attached to the exclusive cgroup (mode %s): %v", bypass.Mode(), attachErr)
	}

	ownCookie, ownFD, err := selfBypassTestSocket(true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ownFD)
	if !selfBypassMarked(t, bypass, ownCookie) {
		t.Fatalf("socket of the owner process was not marked (mode %s)", bypass.Mode())
	}

	helper := startSelfBypassTestHelper(t)
	for _, connect := range []bool{false, true} {
		if cookie := helper.cookie(t, connect); selfBypassMarked(t, bypass, cookie) {
			t.Fatalf("socket of a child process in the owner cgroup was marked (mode %s, connect %v)", bypass.Mode(), connect)
		}
	}
}

// TestSelfBypassSocketAddrHooksMarkOnlyOwnerProcess covers the connect/sendmsg
// fallback used on kernels without socket create/release hooks.
func TestSelfBypassSocketAddrHooksMarkOnlyOwnerProcess(t *testing.T) {
	requireEBPFIntegration(t, "attach self-bypass socket-address hooks")
	owner, err := selfBypassOwnerTGID()
	if err != nil {
		t.Skipf("automatic self-bypass marking is unavailable: %v", err)
	}
	path := enterDedicatedSelfBypassCgroup(t, 301)
	bypass, err := NewSelfBypassWithCapacity(64)
	if err != nil {
		t.Fatal(err)
	}
	defer bypass.Close()
	if _, err = bypass.PreparedMap(); err != nil {
		t.Fatal(err)
	}
	for _, config := range []SelfBypassCgroupConfig{
		{EnableTCP: true, EnableUDP: true, EnableIPv6: true},
		{EnableUDP: true},
	} {
		if err = bypass.attachCgroupSocketAddr(path, config, owner); err != nil {
			t.Fatalf("attach socket-address hooks %+v: %v", config, err)
		}
		if err = bypass.verifyOwnerMarking(true, config); err != nil {
			t.Fatalf("socket-address hooks %+v did not mark the owner: %v", config, err)
		}
		helper := startSelfBypassTestHelper(t)
		if config.EnableTCP {
			if cookie := helper.cookie(t, true); selfBypassMarked(t, bypass, cookie) {
				t.Fatalf("connect of a child process was marked with %+v", config)
			}
		}
		if err = bypass.closeHooks(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSelfBypassFallsBackWhenHooksMarkNothing forces the owner check to
// reject this process. Hooks that would leave the consumer's own sockets
// unmarked must be removed so that userspace registration takes over.
func TestSelfBypassFallsBackWhenHooksMarkNothing(t *testing.T) {
	requireEBPFIntegration(t, "verify the self-bypass probe fallback")
	owner, err := selfBypassOwnerTGID()
	if err != nil {
		t.Skipf("automatic self-bypass marking is unavailable: %v", err)
	}
	enterDedicatedSelfBypassCgroup(t, 302)
	previous := selfBypassOwner
	selfBypassOwner = func() (uint32, error) { return owner + 1, nil }
	t.Cleanup(func() { selfBypassOwner = previous })

	bypass, err := NewSelfBypassWithCapacity(64)
	if err != nil {
		t.Fatal(err)
	}
	defer bypass.Close()
	attachErr := bypass.AttachCgroup(SelfBypassCgroupConfig{EnableTCP: true, EnableUDP: true})
	// A successful release-only fallback returns no error, like any other
	// unavailable marking path; the effective mode is the diagnostic.
	if mode := bypass.Mode(); bypass.CgroupAttached() || (mode != SelfBypassUserspaceRelease && mode != SelfBypassUserspace) {
		t.Fatalf("hooks that mark nothing were kept (mode %s): %v", mode, attachErr)
	}
	cookie, fd, err := selfBypassTestSocket(true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if selfBypassMarked(t, bypass, cookie) {
		t.Fatal("a removed hook still marked a socket")
	}
}

func enterDedicatedSelfBypassCgroup(t *testing.T, index int) string {
	t.Helper()
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	original, err := DetectProcessCgroup2Path()
	if err != nil {
		t.Skipf("process cgroup v2 path is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, root, index)
	if !dedicated {
		t.Skip("cannot create a dedicated cgroup")
	}
	moveTestProcessToCgroup(t, path)
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(original, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644)
	})
	return path
}
