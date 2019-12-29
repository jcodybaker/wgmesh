// +build !linux

package interfaces

import (
	"context"
	"fmt"
	"net"
	"os/exec"

	"golang.zx2c4.com/wireguard/wgctrl"
)

func createKernelInterface(wgClient *wgctrl.Client, iface string) (WireGuardInterface, error) {
	return nil, fmt.Errorf("createKernelInterface: %w", errUnimplemented)
}

func startWGUserspaceInterface(
	ctx context.Context,
	wgClient *wgctrl.Client,
	name string,
	cmd *exec.Cmd,
) (WireGuardInterface, error) {
	return nil, fmt.Errorf("startWGUserspaceInterface: %w", errUnimplemented)
}

type fakeWGInterface struct{}

func (*fakeWGInterface) EnsureUp() error {
	return fmt.Errorf("WireGuardInterface.EnsureUp: %w", errUnimplemented)
}

func (*fakeWGInterface) EnsureIP(ip *net.IPNet) error {
	return fmt.Errorf("WireGuardInterface.EnsureIP: %w", errUnimplemented)
}

func (*fakeWGInterface) Close() error {
	return fmt.Errorf("WireGuardInterface.Close: %w", errUnimplemented)
}

func getAllInterfaces(desired string) (map[string]struct{}, error) {
	return nil, fmt.Errorf("getAllInterfaces: %w", errUnimplemented)
}

func newWGInterface(wgClient *wgctrl.Client, name string) (WireGuardInterface, error) {
	return nil, fmt.Errorf("newWGInterface: %w", errUnimplemented)
}

func createWGKernelInterface(wgClient *wgctrl.Client, options *WireGuardInterfaceOptions, name string) (WireGuardInterface, error) {
	return nil, fmt.Errorf("createWGKernelInterface: %w", errUnimplemented)
}
