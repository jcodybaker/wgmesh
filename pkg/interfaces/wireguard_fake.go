// +build !linux

package interfaces

import (
	"errors"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// This file facilitates development on non-linux platforms.

// EnsureWireguardInterface verifies the specified interface exists and is of
// the "wireguard" type.  If the interface does not exist, it will be created.
func EnsureWireguardInterface(wgClient *wgctrl.Client, iface string) error {
	return errors.New("wireguard.EnsureWireguardInterface is unimplemented")
}

// SetInterfaceUp sets the interface up.
func SetInterfaceUp(iface string) error {
	return errors.New("wireguard.SetInterfaceUp is unimplemented")
}
