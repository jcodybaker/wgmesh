// +build linux integration

package interfaces

import (
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
)

func testInNetworkNamespace(f func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, _ := netns.Get()
	defer origns.Close()

	newns, _ := netns.New()
	defer newns.Close()

	defer netns.Set(origns)

	f()
}

func TestAddWireguardInterface(t *testing.T) {
	testInNetworkNamespace(func() {
		defer func() {
			out, err := exec.Command("ip", "link", "delete", "wg0").CombinedOutput()
			if err != nil {
				t.Logf("failed: ip link delete wg0: %s", string(out))
			}
		}()
		addWireguardInterface("wg0")
		out, err := exec.Command("ip", "link", "show", "wg0").CombinedOutput()
		require.NoErrorf(t, err, "failed: ip link get wg0: %s", string(out))
		require.Contains(t)
	})
}
