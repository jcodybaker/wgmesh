// +build linux integration

package interfaces

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func TestCreateWGKernelInterface(t *testing.T) {
	tcs := []struct {
		name          string
		setup         func(t *testing.T)
		moduleLoaded  bool
		validateError func(t *testing.T, err error)
		expectIface   bool
	}{
		{
			name:         "success",
			moduleLoaded: true,
			expectIface:  true,
		},
		{
			name:         "already exist",
			moduleLoaded: true,
			expectIface:  true,
			setup: func(t *testing.T) {
				out, err := exec.Command("ip", "link", "add", "wg0", "type", "wireguard").CombinedOutput()
				require.NoErrorf(t, err, "manually creating wg interface: %w - %q", err, string(out))
			},
			validateError: func(t *testing.T, err error) {
				require.True(t, os.IsExist(errors.Unwrap(err)))
			},
		},
		{
			name:         "no module",
			moduleLoaded: false,
			expectIface:  false,
			validateError: func(t *testing.T, err error) {
				require.Equal(t, errDriverNotFound, errors.Unwrap(err))
			},
		},
	}

	haveMod := haveWireGuardMod(t)
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.moduleLoaded && !haveMod {
				t.Skip("wireguard kernel module required")
			} else if !tc.moduleLoaded && haveMod {
				t.Skip("test requires an environment without the wireguard kernel module")
			}
			testInNetworkNamespace(t, func() {
				wgClient, err := wgctrl.New()
				require.NoErrorf(t, err, "failed: creating wgctrl.Client")
				defer wgClient.Close()
				defer func() {
					out, err := exec.Command("ip", "link", "delete", "wg0").CombinedOutput()
					if err != nil && !strings.Contains(string(out), "Cannot find device") {
						panic(fmt.Errorf("failed: ip link delete wg0: %w - %s", err, string(out)))
					}
				}()

				if tc.setup != nil {
					tc.setup(t)
				}

				iface, err := createWGKernelInterface(wgClient, "wg0")
				if tc.validateError == nil {
					require.NoErrorf(t, err, "failed: createWGKernelInterface")
					require.NotNil(t, iface)
					defer iface.Close()
					require.Equal(t, "wg0", iface.GetName())
				} else {
					tc.validateError(t, err)
				}

				out, err := exec.Command("ip", "link", "show", "wg0").CombinedOutput()
				if tc.expectIface {
					require.NoErrorf(t, err, "failed: ip link get wg0: %s", string(out))
				} else {
					require.Contains(t, string(out), "does not exist")
				}
			})
		})
	}

}

func TestIsWireGuardInterfaceNameValid(t *testing.T) {
	tcs := []struct {
		testName    string
		ifaceName   string
		expectError string
	}{
		{
			testName:  "success",
			ifaceName: "wg0",
		},
		{
			testName:  "success wildcard",
			ifaceName: "wg+",
		},
		{
			testName:    "empty",
			ifaceName:   "",
			expectError: "interface name is empty",
		},
		{
			testName:    "slash",
			ifaceName:   "some/dev",
			expectError: `interface name "some/dev" is invalid: contains / character`,
		},
		{
			testName:    "space",
			ifaceName:   "some dev",
			expectError: `interface name "some dev" is invalid: contains whitespace`,
		},
		{
			testName:    "too long",
			ifaceName:   strings.Repeat("w", unix.IFNAMSIZ),
			expectError: fmt.Sprintf(`interface name may be at most %d characters; got %d`, unix.IFNAMSIZ-1, unix.IFNAMSIZ),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.testName, func(t *testing.T) {
			err := IsWireGuardInterfaceNameValid(tc.ifaceName)
			if tc.expectError == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.expectError)
		})
	}
}

func haveWireGuardMod(t *testing.T) bool {
	var found bool
	testInNetworkNamespace(t, func() {
		defer func() {
			out, err := exec.Command("ip", "link", "delete", "wg0").CombinedOutput()
			if err != nil && !strings.Contains(string(out), "Cannot find device") {
				panic(fmt.Errorf("failed: ip link delete wg0: %w - %s", err, string(out)))
			}
		}()
		out, err := exec.Command("ip", "link", "add", "dev", "wg0", "type", "wireguard").CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "Operation not supported") {
				return
			}
			panic(fmt.Errorf("determining if wireguard module exists: %w - output %q", err, string(out)))
		}
		found = true
	})
	return found
}

func TestNextInterfaceName(t *testing.T) {
	// This test is in wireguard_linux_test.go because nextInterfaceName depends on
	// IsWireGuardInterfaceNameValid which is platform specific.
	tcs := []struct {
		name          string
		desired       string
		last          string
		expectedNext  string
		expectedError string
	}{
		{
			name:         "static - first invocation",
			desired:      "wg0",
			expectedNext: "wg0",
		},
		{
			name:          "static - already called",
			desired:       "wg0",
			last:          "wg0",
			expectedError: `interface "wg0" exists`,
		},
		{
			name:         "wildcard",
			desired:      "wg+",
			last:         "wg0",
			expectedNext: "wg1",
		},
		{
			name:         "wildcard multiple digits",
			desired:      "wg+",
			last:         "wg10",
			expectedNext: "wg11",
		},
		{
			name:          "becomes too long",
			desired:       "w+",
			last:          fmt.Sprintf("w%s", strings.Repeat("9", unix.IFNAMSIZ-2)),
			expectedError: fmt.Sprintf(`interface name may be at most %d characters; got %d`, unix.IFNAMSIZ-1, unix.IFNAMSIZ),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			next, err := nextInterfaceName(tc.desired, tc.last)
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectedNext, next)
		})
	}
}

func TestCreateWGBoringTunInterface(t *testing.T) {
	_, err := exec.LookPath("boringtun")
	if exec.ErrNotFound == errors.Unwrap(err) {
		t.Skip("no boringtun userspace daemon found")
	}
	require.NoError(t, err)
	tcs := []struct {
		name        string
		setup       func(t *testing.T)
		expectError string
		expectIface bool
		options     *WireGuardInterfaceOptions
	}{
		{
			name:    "success",
			options: &WireGuardInterfaceOptions{},
		},
		// {
		// 	name: "already exists",
		// },
		// {
		// 	name: "path doesn't exists",
		// },
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			testInNetworkNamespace(t, func() {
				defer func() {
					out, err := exec.Command("ip", "link", "delete", "wg0").CombinedOutput()
					if err != nil {
						if !tc.expectIface {
							require.Contains(t, string(out), "Cannot find device")
							return
						}
						require.NoError(t, err)
					} else {
						require.Truef(t, tc.expectIface, "%w - %s", err, string(out))
					}
				}()
				if tc.setup != nil {
					tc.setup(t)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()

				wgClient, err := wgctrl.New()
				require.NoErrorf(t, err, "failed: creating wgctrl.Client")
				defer wgClient.Close()

				iface, err := createWGBoringTunInterface(ctx, wgClient, tc.options, "wg0")
				if tc.expectError == "" {
					require.NoError(t, err)
					require.NotNil(t, iface)
					require.Equal(t, "wg0", iface.GetName())
					err := iface.Close()
					require.NoError(t, err)
					return
				}
				require.EqualError(t, err, tc.expectError)
			})
		})
	}
}
