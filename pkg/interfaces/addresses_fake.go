// +build !linux

package interfaces

import (
	"errors"

	"github.com/vishvananda/netlink"
)

// SetIP ...
func SetIP(iface string, ip *netlink.Addr) error {
	return errors.New("wireguard.SetIP is unimplemented")
}
