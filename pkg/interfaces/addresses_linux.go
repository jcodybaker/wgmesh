// +build linux

package interfaces

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func GetIPs(iface string) ([]string, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("finding interface %q: %w", iface, err)
	}
	// TODO - IPv6
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("listing %q addresses: %w", iface, err)
	}
	var out []string
	for _, addr := range addrs {
		out = append(out, addr.IPNet.String())
	}
	return out, nil
}

// GetLocalSourceIP returns a source IP.
func GetLocalSourceIP(dest string) (string, error) {
	rs, err := netlink.RouteGet(net.Parse("8.8.8.8"))
	if err != nil {
		return "", err
	}
	if len(rs) == 0 {
		return "", errors.New("unable to determine default route")
	}
	return rs[0].Src.String(), nil
}
