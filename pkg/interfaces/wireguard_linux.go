// +build linux

package interfaces

import (
	"fmt"
	"os"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// EnsureWireguardInterface verifies the specified interface exists and is of
// the "wireguard" type.  If the interface does not exist, it will be created.
func EnsureWireguardInterface(wgClient *wgctrl.Client, iface string) error {
	_, err := wgClient.Device(iface)
	switch {
	case os.IsNotExist(err):
		err = addWireguardInterface(iface)
		if err != nil {
			return err
		}
		_, err = wgClient.Device(iface)
		if err != nil {
			return fmt.Errorf("verifying new wireguard device %q: %w", iface, err)
		}
	case err == nil: // success
		return nil
	default:
		return fmt.Errorf("verifying wireguard device %q: %w", iface, err)
	}
}

func addWireguardInterface(iface string) error {
	link := &wgLink{name: iface}
	err := netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("adding net link %q: %w", iface, err)
	}
	return nil
}

type wgLink struct {
	name string
}

// Type implementes netlink.Link interface
func (w *wgLink) Type() string {
	return "wireguard"
}

// Attrs implementes netlink.Link interface
func (w *wgLink) Attrs() *netlink.LinkAttrs {
	attr := netlink.NewLinkAttrs()
	attr.Name = w.name
	return attr
}
