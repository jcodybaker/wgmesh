// +build darwin freebsd openbsd

// TODO: Theoretically this should work on FreeBSD/OpenBSD, but it's untested.

package interfaces

import (
	"context"
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
)

type bsdInterface struct {
	name string
}

func newInterface(name string) (Interface, error) {
	return &bsdInterface{
		name: name,
	}, nil
}

func waitForInterface(ctx context.Context, exit <-chan error, name string) (Interface, error) {
	return nil, fmt.Errorf("interface.waitForInterface: %w", errUnimplemented)
}

// EnsureUp sets the interface to the "UP" state if it is not currently up.
func (i *bsdInterface) GetName() string {
	return i.name
}

// EnsureUp sets the interface to the "UP" state if it is not currently up.
func (i *bsdInterface) EnsureUp() error {
	return fmt.Errorf("WireGuardInterface.EnsureUp: %w", errUnimplemented)
}

// GetIPs returns a list of IP addresses currently active on the interface.
func (i *bsdInterface) GetIPs() ([]string, error) {
	return nil, fmt.Errorf("WireGuardInterface.GetIPs: %w", errUnimplemented)
}

// EnsureIP adds the specified IPNet to the interface, if it is not already added.
func (i *bsdInterface) EnsureIP(ip *net.IPNet) error {
	return fmt.Errorf("WireGuardInterface.EnsureIP: %w", errUnimplemented)
}

func (i *bsdInterface) Close() error {
	return fmt.Errorf("WireGuardInterface.Close: %w", errUnimplemented)
}

func getAllInterfaces(desired string) (map[string]struct{}, error) {
	return nil, fmt.Errorf("interfaces.getAllInterfaces: %w", errUnimplemented)
}

func createWGKernelInterface(wgClient *wgctrl.Client, options *WireGuardInterfaceOptions, name string) (WireGuardInterface, error) {
	return nil, fmt.Errorf("createWGKernelInterface: %w", errUnimplemented)
}
