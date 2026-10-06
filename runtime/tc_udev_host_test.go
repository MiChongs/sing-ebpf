//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"os"
	goRuntime "runtime"
	"testing"
	"time"

	"github.com/sagernet/netlink"
)

// TestTCDeliveryLinkSurvivesUdev creates a delivery link in the host's own
// network namespace, where udevd configures every new interface: systemd's
// default link policy replaces kernel-generated MAC addresses and its sysctl
// rule rewrites rp_filter. Once creation returns, udev must have nothing left
// to change: the address programmed into the backend and the delivery
// interface's sysctls stay what the runtime set.
//
// The netns tests cannot cover this, because udevd never sees the devices of
// another network namespace. It changes the host's interfaces and
// conf.all.rp_filter while it runs, so it only runs on request.
func TestTCDeliveryLinkSurvivesUdev(t *testing.T) {
	if os.Getenv("SING_EBPF_HOST_UDEV") != "1" {
		t.Skip("set SING_EBPF_HOST_UDEV=1 to create links in the host network namespace")
	}
	goRuntime.LockOSThread()
	defer goRuntime.UnlockOSThread()
	if !tcUdevManagesNetworkNamespace() {
		t.Skip("udevd does not manage this network namespace")
	}
	backend := newSocketAssignTestBackend(t, true)
	const priority = 2
	dataPlane := &tcDataPlane{backend: backend, priority: priority}
	delivery, err := dataPlane.createTCDeliveryLink()
	if err != nil {
		t.Fatalf("create the delivery link: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := delivery.Close(); closeErr != nil {
			t.Errorf("close the delivery link: %v", closeErr)
		}
	})
	// udevd is done with the pair; a writer it started late would land well
	// within this.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		healthy, healthErr := delivery.healthy(priority)
		if healthErr != nil {
			t.Fatalf("check the delivery link: %v", healthErr)
		}
		if !healthy {
			var address []byte
			if current, linkErr := netlink.LinkByName(delivery.deliveryName); linkErr == nil {
				address = current.Attrs().HardwareAddr
			}
			rpFilter, _ := os.ReadFile(tcInterfaceSysctlPath(delivery.deliveryName, "rp_filter"))
			t.Fatalf("udev changed the delivery link after creation: interface address %x, programmed %x, rp_filter %q",
				address, delivery.deliveryMAC, rpFilter)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
