// +build linux

package interfaces

func GetIPs(iface string) ([]string, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("finding interface %q: %w", iface, err)
	}
	// TODO - IPv6
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("listing %q addresses: %w", iface, err)
	}
	var out []string
	for _, addr := range addrs {
		out = append(out, addr.IPNet.String())
	}
	return out, nil
}
