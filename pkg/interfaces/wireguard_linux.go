// +build linux

package interfaces

import (
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// DefaultWireGuardInterfaceName provides a reasonable default interface name
// for this platform.
const DefaultWireGuardInterfaceName = "wg+"

func createWGKernelInterface(wgClient *wgctrl.Client, name string) (WireGuardInterface, error) {
	wgLink := netlink.GenericLink{
		LinkType:  "wireguard",
		LinkAttrs: netlink.NewLinkAttrs(),
	}
	wgLink.LinkAttrs.Name = name

	err := netlink.LinkAdd(&wgLink)
	syscallErr, ok := err.(syscall.Errno)
	if ok && syscallErr == syscall.EOPNOTSUPP {
		return nil, fmt.Errorf(`%w: "operation not supported" creating WireGuard interface with kernel driver`, errDriverNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("adding net link %q: %w", name, err)
	}
	return newWGInterface(wgClient, name)
}

// IsWireGuardInterfaceNameValid returns an error if the name is invalid.
func IsWireGuardInterfaceNameValid(name string) error {
	// https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/lib/utils.c?id=1f420318bda3cc62156e89e1b56d60cc744b48ad#n827
	switch {
	case name == "":
		return errors.New("interface name is empty")
	case len(name) >= unix.IFNAMSIZ:
		return fmt.Errorf("interface name may be at most %d characters; got %d", unix.IFNAMSIZ-1, len(name))
	case len(strings.Fields(name)) > 1:
		return fmt.Errorf("interface name %q is invalid: contains whitespace", name)
	case strings.Contains(name, "/"):
		return fmt.Errorf("interface name %q is invalid: contains / character", name)
	}
	return nil
}
