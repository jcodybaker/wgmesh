package interfaces

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kballard/go-shellquote"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// WireGuardDriver describes how the WireGuard interface should be created and managed.
type WireGuardDriver string

const (
	// AutoSelect will try to find a working driver, first trying to use
	// the existing interface, then creating a new interface via the kernel driver,
	// then boringtun, then wireguard-go.
	AutoSelect WireGuardDriver = "auto"
	// ExistingInterface will succeed only if an interface is explicitly specified,
	// exists, and we have sufficient permissions.
	ExistingInterface WireGuardDriver = "existing"
	// KernelDriver attempts to create an interface using the WireGuard kernel module.
	// At the time of this writing, kernel support is only available in Linux, and
	// has not yet been merged into the mainstream kernel. Even after merge it will likely
	// remain an optional module, not loaded by default on most hosts. Security and logistical
	// concerns may prevent loading the module.
	KernelDriver WireGuardDriver = "kernel"
	// BoringTunDriver attempts to create a WireGuard interface using the BoringTun
	// userspace driver. The process will be run as a child of this process.
	BoringTunDriver WireGuardDriver = "boringtun"
	// WireGuardGoDriver attempts to create a WireGuard interface using the wireguard-go
	// userspace driver. The process will be run as a child of this process.
	WireGuardGoDriver WireGuardDriver = "wireguard-go"

	defaultWireGuardGoPath = "wireguard-go"
	defaultBoringTunPath   = "boringtun"

	// interfaceTimeout is the period we'll wait for a driver to create the interface.
	interfaceTimeout         = 10 * time.Second
	userspaceShutdownTimeout = 10 * time.Second
)

var errUnimplemented = errors.New("unimplemented on this platform")

// WireGuardInterface defines the common set of actions which can be taken against a
// network interface.
type WireGuardInterface interface {
	EnsureUp() error
	EnsureIP(ip *net.IPNet) error
	GetIPs() ([]string, error)
	Close() error
}

// WireGuardInterfaceOptions ...
type WireGuardInterfaceOptions struct {
	InterfaceName        string
	Driver               WireGuardDriver
	ReuseExisting        bool
	WireGuardGoPath      string
	WireGuardGoExtraArgs string
	BoringTunPath        string
	BoringTunExtraArgs   string
}

// EnsureWireGuardInterface creates or reuses a WireGuard interface based upon the options.
func EnsureWireGuardInterface(
	ctx context.Context,
	options *WireGuardInterfaceOptions,
) (WireGuardInterface, error) {
	var name string
	existing, err := getAllInterfaces(options.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("listing existing interfaces: %w", err)
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("initializing wgctrl client: %w", err)
	}

	for {
		var err error
		name, err = nextInterfaceName(options.InterfaceName, name)
		if err != nil {
			return nil, err
		}

		if _, ok := existing[name]; ok {
			if options.ReuseExisting {
				if _, err := wgClient.Device(name); err != nil {
					return nil, fmt.Errorf("initializing existing device: %w", err)
				}
				return newWGInterface(wgClient, name)
			}
			continue
		}

		if options.Driver == KernelDriver || options.Driver == AutoSelect {
			iface, err := createWGKernelInterface(wgClient, options, name)
			switch {
			case err == nil:
				return iface, nil
			case errors.Unwrap(err) == errUnimplemented:
				// move on to the next driver option
			case os.IsExist(err):
				continue
			case true:
				// TODO - Catch unknown interface type case
			default:
				return nil, err
			}
		}

		if options.Driver == BoringTunDriver || options.Driver == AutoSelect {
			iface, err := createWGBoringTunInterface(ctx, wgClient, options, name)
			switch {
			case err == nil:
				return iface, nil
			case errors.Unwrap(err) == errUnimplemented:
				// move on to the next driver option
			case os.IsExist(err):
				continue
			default:
				return nil, err
			}
		}

		if options.Driver == WireGuardGoDriver || options.Driver == AutoSelect {
			iface, err := createWGWireguardGoInterface(ctx, wgClient, options, name)
			switch {
			case err == nil:
				return iface, nil
			case errors.Unwrap(err) == errUnimplemented:
				// move on to the next driver option
			case os.IsExist(err):
				continue
			default:
				return nil, err
			}
		}
		return nil, errors.New("no wireguard drivers succeeded")
	}
}

// nextInterfaceName
func nextInterfaceName(desired, last string) (string, error) {
	if !strings.HasSuffix(desired, "+") {
		if last == "" {
			return desired, nil
		}
		// static interface name - since last != "" it must already exist.
		return "", fmt.Errorf("interface %q exists", last)
	}
	if last == "" {
		return strings.ReplaceAll(desired, "+", "0"), nil
	}
	base := desired[:len(desired)-1] // eth+ = eth
	num, err := strconv.ParseUint(strings.Replace(last, base, "", 0), 10, 32)
	if err != nil {
		return "", fmt.Errorf("generating interface name: %w", err)
	}
	num++
	return fmt.Sprintf("%s%d", base, num), nil
}

func createWGBoringTunInterface(
	ctx context.Context,
	wgClient *wgctrl.Client,
	options *WireGuardInterfaceOptions,
	name string,
) (WireGuardInterface, error) {
	path := options.BoringTunPath
	if path == "" {
		path = defaultBoringTunPath
	}
	qualifiedPath, err := exec.LookPath(path)
	if err != nil {
		return nil, fmt.Errorf("finding boringtun binary %q: %w", path, err)
	}
	args := []string{
		"--foreground",
	}
	if options.BoringTunExtraArgs != "" {
		a, err := shellquote.Split(options.BoringTunExtraArgs)
		if err != nil {
			return nil, fmt.Errorf("parsing boringtun extra args: %w", err)
		}
		args = append(args, a...)
	}
	cmd := exec.Command(qualifiedPath, args...)
	return startWGUserspaceInterface(ctx, wgClient, name, cmd)
}

func createWGWireguardGoInterface(
	ctx context.Context,
	wgClient *wgctrl.Client,
	options *WireGuardInterfaceOptions,
	name string,
) (WireGuardInterface, error) {
	path := options.WireGuardGoPath
	if path == "" {
		path = defaultWireGuardGoPath
	}
	qualifiedPath, err := exec.LookPath(path)
	if err != nil {
		return nil, fmt.Errorf("finding wireguard-go binary %q: %w", path, err)
	}
	args := []string{
		"--foreground",
	}
	if options.WireGuardGoExtraArgs != "" {
		a, err := shellquote.Split(options.WireGuardGoExtraArgs)
		if err != nil {
			return nil, fmt.Errorf("parsing wireguard-go extra args: %w", err)
		}
		args = append(args, a...)
	}
	cmd := exec.Command(qualifiedPath, args...)
	return startWGUserspaceInterface(ctx, wgClient, name, cmd)
}

func cmdExit(cmd *exec.Cmd) <-chan error {
	quit := make(chan error)
	go func() {
		defer close(quit)
		quit <- cmd.Wait()
	}()
	return quit
}
