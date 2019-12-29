// +build darwin

package interfaces

import (
	"fmt"
	"regexp"
)

// DefaultWireGuardInterfaceName provides a reasonable default interface name
// for this platform.
const DefaultWireGuardInterfaceName = "tun+"

var validWireGuardInterfaceName = regexp.MustCompile(`^tun([0-9]+|\+)$`)

// IsWireGuardInterfaceNameValid returns an error if the name is invalid.
func IsWireGuardInterfaceNameValid(name string) error {
	// https://git.zx2c4.com/wireguard-go/about/#openbsd
	if !validWireGuardInterfaceName.MatchString(name) {
		return fmt.Errorf("invalid interface name %q; BSD must use tun[0-9]+ format", name)
	}
	return nil
}
