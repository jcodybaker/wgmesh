// +build linux

package interfaces

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"
)

// GetLocalSourceIP returns a source IP.
func GetLocalSourceIP(dest string) (string, error) {
	rs, err := netlink.RouteGet(net.ParseIP(dest))
	if err != nil {
		return "", err
	}
	if len(rs) == 0 {
		return "", errors.New("unable to determine default route")
	}
	return rs[0].Src.String(), nil
}
