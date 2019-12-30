// +build freebsd openbsd

package interfaces

import (
	"fmt"
	"regexp"

	"golang.org/x/sys/unix"
)

// DefaultWireGuardInterfaceName provides a reasonable default interface name
// for this platform.
const DefaultWireGuardInterfaceName = "utun+"

var validWireGuardInterfaceName = regexp.MustCompile(`^utun([0-9]+|\+)$`)

// IsWireGuardInterfaceNameValid returns an error if the name is invalid.
func IsWireGuardInterfaceNameValid(name string) error {
	// https://git.zx2c4.com/wireguard-go/about/#macos
	if !validWireGuardInterfaceName.MatchString(name) {
		return fmt.Errorf("invalid interface name %q; macOS must use utun[0-9]+ format", name)
	}
	if len(name) >= unix.IFNAMSIZ {
		return fmt.Errorf("interface name may be at most %d characters; got %d", unix.IFNAMSIZ-1, len(name))
	}
	return nil
}
