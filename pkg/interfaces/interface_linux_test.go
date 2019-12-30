// +build linux

package interfaces

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
)

func testInNetworkNamespace(t *testing.T, f func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, _ := netns.Get()
	defer origns.Close()

	newns, _ := netns.New()
	defer newns.Close()

	defer netns.Set(origns)

	f()
}

func TestWaitForInterface(t *testing.T) {
	tcs := []struct {
		name           string
		cmd            string
		contextTimeout time.Duration
		expectError    string
		expectIface    bool
		expectMaxWait  time.Duration
		expectMinWait  time.Duration
	}{
		{
			name:           "success",
			cmd:            "ip link add dev dummy type dummy",
			expectIface:    true,
			expectMaxWait:  5 * time.Second,
			contextTimeout: time.Minute,
		},
		{
			name:           "eventual success",
			cmd:            "sleep 5 && ip link add dev dummy type dummy",
			expectIface:    true,
			expectMinWait:  5 * time.Second,
			expectMaxWait:  8 * time.Second,
			contextTimeout: time.Minute,
		},
		{
			name:           "timeout",
			cmd:            "sleep 15 && ip link add dev dummy type dummy",
			expectIface:    false,
			expectError:    "timeout",
			expectMinWait:  9 * time.Second,
			expectMaxWait:  12 * time.Second,
			contextTimeout: time.Minute,
		},
		{
			name:           "context deadline exceeded",
			cmd:            "sleep 15",
			expectIface:    false,
			expectError:    "context deadline exceeded",
			expectMinWait:  4 * time.Second,
			expectMaxWait:  7 * time.Second,
			contextTimeout: 5 * time.Second,
		},
		{
			name:           "driver exits",
			cmd:            "false",
			expectIface:    false,
			expectError:    "userspace driver exited 1",
			expectMaxWait:  5 * time.Second,
			contextTimeout: time.Minute,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			testInNetworkNamespace(t, func() {
				defer func() {
					out, err := exec.Command("ip", "link", "delete", "dummy").CombinedOutput()
					if err != nil && !strings.Contains(string(out), "Cannot find device") {
						panic(fmt.Errorf("failed: ip link delete dummy: %w - %s", err, string(out)))
					}
				}()

				ctx, cancel := context.WithTimeout(context.Background(), tc.contextTimeout)
				defer cancel()

				cmd := exec.CommandContext(ctx, "sh", "-c", tc.cmd)
				before := time.Now()
				cmd.Start()
				exit := cmdExit(cmd)

				iface, err := waitForInterface(ctx, exit, "dummy")
				after := time.Now()
				if tc.expectError == "" {
					require.NoError(t, err)
					require.NotNil(t, iface)
					require.Equal(t, "dummy", iface.GetName())
				} else {
					require.EqualError(t, err, tc.expectError)
				}

				duration := after.Sub(before)
				require.Less(t, duration.Seconds(), tc.expectMaxWait.Seconds())
				require.GreaterOrEqual(t, duration.Seconds(), tc.expectMinWait.Seconds())

				cancel()
				// Wait for process to exit.
				<-exit

				out, err := exec.Command("ip", "link", "show", "dummy").CombinedOutput()
				if tc.expectIface {
					require.NoErrorf(t, err, "failed: ip link get dummy: %s", string(out))
				} else {
					require.Contains(t, string(out), "does not exist")
				}
			})
		})
	}

}

func TestGetAllInterfaces(t *testing.T) {
	testInNetworkNamespace(t, func() {
		defer func() {
			out, err := exec.Command("ip", "link", "delete", "dummy").CombinedOutput()
			if err != nil && !strings.Contains(string(out), "Cannot find device") {
				panic(fmt.Errorf("failed: ip link delete dummy: %w - %s", err, string(out)))
			}
			out, err = exec.Command("ip", "link", "delete", "wg0").CombinedOutput()
			if err != nil && !strings.Contains(string(out), "Cannot find device") {
				panic(fmt.Errorf("failed: ip link delete wg0: %w - %s", err, string(out)))
			}
		}()

		out, err := exec.Command("ip", "link", "add", "dev", "dummy", "type", "dummy").CombinedOutput()
		if err != nil {
			panic(fmt.Errorf("failed: ip link add dev dummy type dummy: %w - %s", err, string(out)))
		}

		out, err = exec.Command("ip", "link", "add", "dev", "wg0", "type", "dummy").CombinedOutput()
		if err != nil {
			panic(fmt.Errorf("failed: ip link add dev wg0 type dummy: %w - %s", err, string(out)))
		}

		found, err := getAllInterfaces("wg+")
		require.NoError(t, err)

		expected := map[string]struct{}{
			"wg0": struct{}{},
		}
		require.Equal(t, expected, found)
	})
}

func TestNewInterface(t *testing.T) {
	testInNetworkNamespace(t, func() {
		defer func() {
			out, err := exec.Command("ip", "link", "delete", "dummy").CombinedOutput()
			if err != nil && !strings.Contains(string(out), "Cannot find device") {
				panic(fmt.Errorf("failed: ip link delete dummy: %w - %s", err, string(out)))
			}
		}()

		out, err := exec.Command("ip", "link", "add", "dev", "dummy", "type", "dummy").CombinedOutput()
		if err != nil {
			panic(fmt.Errorf("failed: ip link add dev dummy type dummy: %w - %s", err, string(out)))
		}

		iface, err := newInterface("dummy")
		require.NoError(t, err)
		require.Equal(t, "dummy", iface.GetName())
		linuxIface, ok := iface.(*linuxInterface)
		require.True(t, ok)
		require.Equal(t, "dummy", linuxIface.name)
		require.NotNil(t, linuxIface.link)
		attr := linuxIface.link.Attrs()
		require.NotNil(t, attr)
		require.Equal(t, "dummy", attr.Name)
	})
}

func TestInterfaceEnsureUp(t *testing.T) {
	tcs := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{
			name: "success",
		},
		{
			name: "already up",
			setup: func(t *testing.T) {
				out, err := exec.Command("ip", "link", "set", "dev", "dummy", "up").CombinedOutput()
				require.NoErrorf(t, err, string(out))
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			testInNetworkNamespace(t, func() {
				defer func() {
					out, err := exec.Command("ip", "link", "delete", "dummy").CombinedOutput()
					if err != nil && !strings.Contains(string(out), "Cannot find device") {
						panic(fmt.Errorf("failed: ip link delete dummy: %w - %s", err, string(out)))
					}
				}()

				out, err := exec.Command("ip", "link", "add", "dev", "dummy", "type", "dummy").CombinedOutput()
				if err != nil {
					panic(fmt.Errorf("failed: ip link add dev dummy type dummy: %w - %s", err, string(out)))
				}

				iface, err := newInterface("dummy")
				require.NoError(t, err)
				err = iface.EnsureUp()
				require.NoError(t, err)

				out, err = exec.Command("ip", "link", "show", "dummy").CombinedOutput()
				require.NoError(t, err)
				flagRe := regexp.MustCompile(`<[_A-Z0-9,]+>`)
				found := flagRe.Find(out)
				require.Greaterf(t, len(found), 2, "link status match is too short")
				foundSplit := strings.Split(string(found[1:len(found)-1]), ",")
				require.Contains(t, foundSplit, "UP")
			})
		})
	}
}

func TestInterfaceEnsureIP(t *testing.T) {
	tcs := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{
			name: "success",
		},
		{
			name: "already added",
			setup: func(t *testing.T) {
				out, err := exec.Command("ip", "addr", "add", "192.168.1.1/24", "dev", "dummy").CombinedOutput()
				require.NoErrorf(t, err, string(out))
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			testInNetworkNamespace(t, func() {
				defer func() {
					out, err := exec.Command("ip", "link", "delete", "dummy").CombinedOutput()
					if err != nil && !strings.Contains(string(out), "Cannot find device") {
						panic(fmt.Errorf("failed: ip link delete dummy: %w - %s", err, string(out)))
					}
				}()

				out, err := exec.Command("ip", "link", "add", "dev", "dummy", "type", "dummy").CombinedOutput()
				if err != nil {
					panic(fmt.Errorf("failed: ip link add dev dummy type dummy: %w - %s", err, string(out)))
				}

				out, err = exec.Command("ip", "addr", "add", "192.168.1.1/24", "dev", "dummy").CombinedOutput()
				if err != nil {
					panic(fmt.Errorf("failed: ip addr add 192.168.1.1/24 dev dummy: %w - %s", err, string(out)))
				}

				iface, err := newInterface("dummy")
				require.NoError(t, err)
				addr := net.IPNet{
					IP:   net.IPv4(192, 168, 1, 1),
					Mask: net.CIDRMask(24, 32),
				}
				err = iface.EnsureIP(&addr)
				require.NoError(t, err)

				out, err = exec.Command("ip", "addr", "show", "dummy").CombinedOutput()
				require.NoError(t, err)
				require.Contains(t, string(out), "192.168.1.1/24")
			})
		})
	}
}

func TestInterfaceGetIPs(t *testing.T) {
	testInNetworkNamespace(t, func() {
		defer func() {
			out, err := exec.Command("ip", "link", "delete", "dummy").CombinedOutput()
			if err != nil && !strings.Contains(string(out), "Cannot find device") {
				panic(fmt.Errorf("failed: ip link delete dummy: %w - %s", err, string(out)))
			}
		}()

		out, err := exec.Command("ip", "link", "add", "dev", "dummy", "type", "dummy").CombinedOutput()
		if err != nil {
			panic(fmt.Errorf("failed: ip link add dev dummy type dummy: %w - %s", err, string(out)))
		}

		out, err = exec.Command("ip", "addr", "add", "192.168.1.1/24", "dev", "dummy").CombinedOutput()
		if err != nil {
			panic(fmt.Errorf("failed: ip addr add 192.168.1.1/24 dev dummy: %w - %s", err, string(out)))
		}
		out, err = exec.Command("ip", "addr", "add", "192.168.2.1/24", "dev", "dummy").CombinedOutput()
		if err != nil {
			panic(fmt.Errorf("failed: ip addr add 192.168.2.1/24 dev dummy: %w - %s", err, string(out)))
		}

		iface, err := newInterface("dummy")
		require.NoError(t, err)

		ips, err := iface.GetIPs()
		require.NoError(t, err)

		require.ElementsMatch(t, []string{"192.168.1.1/24", "192.168.2.1/24"}, ips)
	})
}

func TestInterfaceClose(t *testing.T) {
	tcs := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{
			name: "success",
		},
		{
			name: "already closed",
			setup: func(t *testing.T) {
				out, err := exec.Command("ip", "link", "delete", "dummy").CombinedOutput()
				require.NoErrorf(t, err, "failed to delete device: %w - %q", err, string(out))
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			testInNetworkNamespace(t, func() {
				defer func() {
					out, err := exec.Command("ip", "link", "delete", "dummy").CombinedOutput()
					if err != nil && !strings.Contains(string(out), "Cannot find device") {
						panic(fmt.Errorf("failed: ip link delete dummy: %w - %s", err, string(out)))
					}
				}()

				out, err := exec.Command("ip", "link", "add", "dev", "dummy", "type", "dummy").CombinedOutput()
				require.NoErrorf(t, err, "failed to add device: %w - %q", err, string(out))

				iface, err := newInterface("dummy")
				require.NoError(t, err)

				if tc.setup != nil {
					tc.setup(t)
				}

				err = iface.Close()
				require.NoError(t, err)

				out, err = exec.Command("ip", "addr", "show", "dummy").CombinedOutput()
				require.NotNil(t, err)
				require.Contains(t, string(out), "does not exist")
			})
		})
	}
}
