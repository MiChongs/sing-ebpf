//go:build with_ebpf && (linux || android)

package runtime

import (
	"errors"
	"hash/fnv"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	core "github.com/MiChongs/sing-ebpf/internal/core"
	E "github.com/sagernet/sing/common/exceptions"
)

// conf.all.rp_filter and an interface's route_localnet are single values that
// every sing-ebpf runtime in the network namespace depending on them shares.
// Every runtime that depends on such a value holds a lease on it for as long as
// it does. The lease carries the value to restore once nobody depends on the
// setting any more: the original the holder found when it changed the setting,
// a value inherited from the lease of the runtime that did, or
// tcSysctlLeaseNoRestore. A runtime that leaves while another lease exists
// leaves the setting in place, and the last one to leave restores it.
//
// A value to restore can only be inherited when a runtime claims the setting.
// If the setting is changed again while several runtimes run and the one that
// changed it leaves first, the value to restore is lost and the setting stays
// as the runtimes left it: never pulled from under a running runtime.
//
// Leases are enumerated through /proc/net/unix. If that listing cannot be read,
// a runtime inherits nothing and restores nothing: a setting left changed is
// the failure that cannot break a running runtime.

// tcSysctlLeaseNoRestore is the value of a lease whose holder depends on a
// setting it found in place, so that leaving restores nothing.
const tcSysctlLeaseNoRestore = "-"

func tcSysctlLeaseKey(path string) string {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(path))
	return "sysctl-" + strconv.FormatUint(hash.Sum64(), 16)
}

// lockTCSysctlLease serializes the read-modify-write of a shared setting with
// the lease bookkeeping of every other runtime.
func lockTCSysctlLease(key string) (io.Closer, error) {
	return core.AcquireInstanceMutex("lease/"+key, core.DefaultInstanceMutexTimeout)
}

// otherTCSysctlLeases lists the values of the other runtimes' leases on key.
// It reports false if they cannot be listed.
func otherTCSysctlLeases(key string, own *core.InstanceLease) ([]string, bool) {
	values, err := core.InstanceLeaseValues(key, own)
	return values, err == nil
}

// lastTCSysctlLease reports whether own is known to be the only lease on key.
func lastTCSysctlLease(key string, own *core.InstanceLease) bool {
	values, listed := otherTCSysctlLeases(key, own)
	return listed && len(values) == 0
}

// inheritedTCSysctlRestore is the value to restore that another runtime's lease
// carries, if any.
func inheritedTCSysctlRestore(key string) string {
	values, _ := otherTCSysctlLeases(key, nil)
	for _, value := range values {
		if value != tcSysctlLeaseNoRestore {
			return value
		}
	}
	return tcSysctlLeaseNoRestore
}

// renewTCSysctlLease makes *lease carry restore.
func renewTCSysctlLease(key string, lease **core.InstanceLease, restore string) error {
	if *lease != nil && (*lease).Value() == restore {
		return nil
	}
	next, err := core.AcquireInstanceLease(key, restore)
	if err != nil {
		return err
	}
	if err = closeOwned(lease); err != nil {
		return E.Errors(err, next.Close())
	}
	*lease = next
	return nil
}

// readTCSysctl reads a setting the way the kernel prints it.
func readTCSysctl(path string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(value)), nil
}

// claimAggregateRPFilter lowers conf.all.rp_filter for this delivery interface
// and holds a lease on the lowered value. It reports whether it changed any
// setting.
func (d *tcDeliveryLink) claimAggregateRPFilter() (bool, error) {
	path := tcInterfaceSysctlPath("all", "rp_filter")
	key := tcSysctlLeaseKey(path)
	if d.globalLease != nil {
		// The lease keeps every other runtime from restoring the aggregate
		// filter, so a repair round only has work when it was raised again.
		value, err := readTCSysctl(path)
		if errors.Is(err, os.ErrNotExist) || err == nil && value == "0" {
			return false, nil
		}
	}
	mutex, err := lockTCSysctlLease(key)
	if err != nil {
		return false, err
	}
	defer mutex.Close()
	inherit := d.globalLease == nil
	states, err := clearTCAggregateRPFilter(d.deliveryName)
	d.globalSysctls = appendTCSysctlStates(d.globalSysctls, states)
	changed := len(states) > 0
	if err != nil {
		return changed, err
	}
	var restore string
	if index := slices.IndexFunc(d.globalSysctls, func(state tcSysctlState) bool {
		return state.path == path
	}); index >= 0 {
		restore = d.globalSysctls[index].original
	} else if !inherit {
		restore = d.globalLease.Value()
	} else {
		restore = inheritedTCSysctlRestore(key)
	}
	return changed, renewTCSysctlLease(key, &d.globalLease, restore)
}

// releaseAggregateRPFilter gives up this delivery interface's claim on the
// lowered aggregate reverse-path filter.
func (d *tcDeliveryLink) releaseAggregateRPFilter() error {
	if len(d.globalSysctls) == 0 && d.globalLease == nil {
		return nil
	}
	path := tcInterfaceSysctlPath("all", "rp_filter")
	key := tcSysctlLeaseKey(path)
	mutex, err := lockTCSysctlLease(key)
	if err != nil {
		return err
	}
	defer mutex.Close()
	if !lastTCSysctlLease(key, d.globalLease) {
		// A running runtime may still need the aggregate filter lowered. The
		// interfaces pinned here keep the previous aggregate value, which is
		// the effective filter they had before it was lowered and have again
		// once the last runtime restores it.
		d.globalSysctls = nil
		return closeOwned(&d.globalLease)
	}
	recorded := slices.ContainsFunc(d.globalSysctls, func(state tcSysctlState) bool {
		return state.path == path
	})
	if err = restoreTCSysctlStatesOwned(&d.globalSysctls); err != nil {
		return err
	}
	if !recorded && d.globalLease != nil && d.globalLease.Value() != tcSysctlLeaseNoRestore {
		// Inherited from a runtime that left while this one was running.
		if err = restoreTCSysctlStates([]tcSysctlState{{
			path:     path,
			original: d.globalLease.Value(),
			applied:  "0",
		}}); err != nil {
			return err
		}
	}
	return closeOwned(&d.globalLease)
}

// claimSharedRewriteLocalnet enables route_localnet on the interface and holds
// a lease on it.
func claimSharedRewriteLocalnet(interfaceName string, lease **core.InstanceLease) error {
	path := sharedRewriteLocalnetPath(interfaceName)
	key := tcSysctlLeaseKey(path)
	if *lease != nil {
		// As for the aggregate filter, the lease keeps it enabled for this
		// runtime unless something else disabled it.
		if value, err := readTCSysctl(path); err == nil && value == "1" {
			return nil
		}
	}
	mutex, err := lockTCSysctlLease(key)
	if err != nil {
		return err
	}
	defer mutex.Close()
	changed, err := ensureSharedRewriteLocalnet(interfaceName)
	if err != nil {
		return err
	}
	var restore string
	switch {
	case changed:
		restore = "0"
	case *lease != nil:
		restore = (*lease).Value()
	default:
		restore = inheritedTCSysctlRestore(key)
	}
	if err = renewTCSysctlLease(key, lease, restore); err != nil {
		if changed && *lease == nil {
			return E.Errors(err, restoreSharedRewriteLocalnet(interfaceName))
		}
		return err
	}
	return nil
}

// releaseSharedRewriteLocalnet gives up a route_localnet lease. The last
// holder disables the setting again if a holder had enabled it.
func releaseSharedRewriteLocalnet(interfaceName string, lease **core.InstanceLease) error {
	if *lease == nil {
		return nil
	}
	key := tcSysctlLeaseKey(sharedRewriteLocalnetPath(interfaceName))
	mutex, err := lockTCSysctlLease(key)
	if err != nil {
		return err
	}
	defer mutex.Close()
	if (*lease).Value() != tcSysctlLeaseNoRestore && lastTCSysctlLease(key, *lease) {
		if err = restoreSharedRewriteLocalnet(interfaceName); err != nil {
			return err
		}
	}
	return closeOwned(lease)
}
