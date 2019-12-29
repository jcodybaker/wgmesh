// +build !linux

package interfaces

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
)

func createKernelInterface(wgClient *wgctrl.Client, iface string) (WireGuardInterface, error) {
	return nil, fmt.Errorf("createKernelInterface: %w", errUnimplemented)
}
