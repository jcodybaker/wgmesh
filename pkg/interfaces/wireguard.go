package interfaces

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kballard/go-shellquote"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

// WireGuardInterface defines the common set of actions which can be taken against a
// network interface.
type WireGuardInterface interface {
	// Inherit everything from the non-wireguard specific Interface interface.
	Interface

	// ConfigureWireGuard configures WireGuard on the specified interface. See:
	// https://godoc.org/golang.zx2c4.com/wireguard/wgctrl#Client.ConfigureDevice
	ConfigureWireGuard(cfg wgtypes.Config) error

	// GetListenPort returns the UDP port where the WireGuard driver is listening. The
	// interface must be in the UP state.
	GetListenPort() (int, error)
}

// WireGuardInterfaceOptions ...
type WireGuardInterfaceOptions struct {
	InterfaceName        string
	Driver               WireGuardDriver
	Port                 int
	ReuseExisting        bool
	WireGuardGoPath      string
	WireGuardGoExtraArgs string
	BoringTunPath        string
	BoringTunExtraArgs   string
}

type wgInterface struct {
	wgClient *wgctrl.Client
	Interface
}

var _ WireGuardInterface = &wgInterface{}

type wgUserspaceInterface struct {
	wgInterface
	cmd        *exec.Cmd
	driverExit chan error
	closed     sync.Once
}

var _ WireGuardInterface = &wgUserspaceInterface{}

// EnsureWireGuardInterface creates or reuses a WireGuard interface based upon the options.
func EnsureWireGuardInterface(
	ctx context.Context,
	options *WireGuardInterfaceOptions,
) (_ WireGuardInterface, rErr error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("initializing wgctrl client: %w", err)
	}
	defer func() {
		// Don't leak the client if we're closing on error.
		if rErr != nil {
			wgClient.Close()
		}
	}()
	iface, err := createOrReuseWGInterface(ctx, options, wgClient)
	if err != nil {
		return nil, err
	}

	if options.Port != 0 {
		err = iface.ConfigureWireGuard(wgtypes.Config{
			ListenPort: &options.Port,
		})
		if err != nil {
			return nil, fmt.Errorf("setting WireGuard listen port on %q to %d", iface.GetName(), options.Port)
		}
	}
	return iface, nil
}

func createOrReuseWGInterface(
	ctx context.Context,
	options *WireGuardInterfaceOptions,
	wgClient *wgctrl.Client,
) (WireGuardInterface, error) {
	var name string
	existing, err := getAllInterfaces(options.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("listing existing interfaces: %w", err)
	}
	for {
		var err error
		name, err = nextInterfaceName(options.InterfaceName, name)
		if err != nil {
			return nil, err
		}

		if _, ok := existing[name]; ok {
			if options.ReuseExisting || options.Driver == ExistingInterface {
				d, err := wgClient.Device(name)
				if err != nil {
					return nil, fmt.Errorf("initializing existing device: %w", err)
				}
				if options.Port != 0 && d.ListenPort != options.Port {
					return nil, fmt.Errorf(
						"existing device %q listening on port %d; desired port %d",
						name, d.ListenPort, options.Port)
				}
				return newWGInterface(wgClient, name)
			}
			continue
		}

		iface, err := createWGInterfaceWithName(ctx, name, options, wgClient)
		switch {
		case err == nil:
			return iface, nil
		case os.IsExist(errors.Unwrap(err)):
			continue
		default:
			return nil, err
		}
	}
}

func createWGInterfaceWithName(
	ctx context.Context,
	name string,
	options *WireGuardInterfaceOptions,
	wgClient *wgctrl.Client,
) (WireGuardInterface, error) {
	if options.Driver == KernelDriver || options.Driver == AutoSelect {
		iface, err := createWGKernelInterface(wgClient, name)
		if err == nil {
			return iface, nil
		}
		cause := errors.Unwrap(err)
		if options.Driver == KernelDriver || (cause != errDriverNotFound && cause != errUnimplemented) {
			return nil, err
		}
	}

	if options.Driver == BoringTunDriver || options.Driver == AutoSelect {
		iface, err := createWGBoringTunInterface(ctx, wgClient, options, name)
		if err == nil {
			return iface, nil
		}
		cause := errors.Unwrap(err)
		if options.Driver == BoringTunDriver || cause != errDriverNotFound {
			return nil, err
		}
	}

	if options.Driver == WireGuardGoDriver || options.Driver == AutoSelect {
		iface, err := createWGWireguardGoInterface(ctx, wgClient, options, name)
		if err == nil {
			return iface, nil
		}
		cause := errors.Unwrap(err)
		if options.Driver == WireGuardGoDriver || cause != errDriverNotFound {
			return nil, err
		}
	}
	return nil, errors.New("no wireguard drivers succeeded")
}

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
	num, err := strconv.ParseUint(strings.Replace(last, base, "", 1), 10, 64)
	if err != nil {
		return "", fmt.Errorf("generating interface name: %w", err)
	}
	num++
	name := fmt.Sprintf("%s%d", base, num)
	err = IsWireGuardInterfaceNameValid(name)
	if err != nil {
		return "", err
	}
	return name, nil
}

func newWGInterface(wgClient *wgctrl.Client, name string) (WireGuardInterface, error) {
	iface, err := newInterface(name)
	if err != nil {
		return nil, err
	}
	return &wgInterface{
		wgClient:  wgClient,
		Interface: iface,
	}, nil
}

// GetListenPort returns the UDP port where the WireGuard driver is listening. The
// interface must be in the UP state.
func (w *wgInterface) GetListenPort() (int, error) {
	d, err := w.wgClient.Device(w.GetName())
	if err != nil {
		return 0, err
	}
	return d.ListenPort, nil
}

// ConfigureWireGuard configures WireGuard on the specified interface. See:
// https://godoc.org/golang.zx2c4.com/wireguard/wgctrl#Client.ConfigureDevice
func (w *wgInterface) ConfigureWireGuard(cfg wgtypes.Config) error {
	return w.wgClient.ConfigureDevice(w.GetName(), cfg)
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
	switch err {
	case nil: // SUCCESS - fall past switch
	case exec.ErrNotFound:
		return nil, fmt.Errorf("finding boringtun binary %q: %w", path, errDriverNotFound)
	default:
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
	args = append(args, name)
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
	switch err {
	case nil: // SUCCESS - fall past switch
	case exec.ErrNotFound:
		return nil, fmt.Errorf("finding wireguard-go binary %q: %w", path, errDriverNotFound)
	default:
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
	args = append(args, name)
	cmd := exec.Command(qualifiedPath, args...)
	return startWGUserspaceInterface(ctx, wgClient, name, cmd)
}

func startWGUserspaceInterface(
	ctx context.Context,
	wgClient *wgctrl.Client,
	name string,
	cmd *exec.Cmd,
) (WireGuardInterface, error) {
	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("starting userspace: %w", err)
	}
	exit := cmdExit(cmd)
	iface, err := waitForInterface(ctx, exit, name)
	if err != nil {
		return nil, fmt.Errorf("waiting for interface %q to be created: %w", name, err)
	}
	return &wgUserspaceInterface{
		cmd: cmd,
		wgInterface: wgInterface{
			Interface: iface,
			wgClient:  wgClient,
		},
	}, nil
}

// Close stops the userspace driver and cleans up the interface.
func (w *wgUserspaceInterface) Close() error {
	var errs []error
	w.closed.Do(func() {
		err := w.wgInterface.Close()
		if err != nil {
			errs = append(errs, err)
			// fall through to cleanup any processes
		}

		if w.cmd == nil {
			errs = append(errs, errors.New("userspace driver cmd not set"))
			return
		}
		process := w.cmd.Process // TODO - is this sequence safe
		if process == nil {
			errs = append(errs, errors.New("userspace driver cmd.Process not set"))
			return
		}
		if w.cmd.ProcessState != nil {
			// If ProcessState != the process has already exited, wait
			<-w.driverExit
			return
		}
		err = process.Signal(syscall.SIGTERM)
		if err != nil {
			errs = append(errs, fmt.Errorf("signaling shutdown to userspace driver: %w", err))
			// fall through to KILL
		}
		t := time.NewTimer(userspaceShutdownTimeout)
		defer t.Stop()
		select {
		case <-t.C:
			err = process.Kill()
			if err != nil {
				errs = append(errs, fmt.Errorf("killing userspace driver: %w", err))
				return
			}
			// discard exit status because it's likely wonky.
			<-w.driverExit
			return
		case <-w.driverExit:
			return
		}
	})
	if len(errs) > 0 {
		return errs[len(errs)-1]
	}
	return nil
}

func cmdExit(cmd *exec.Cmd) <-chan error {
	quit := make(chan error)
	go func() {
		defer close(quit)
		quit <- cmd.Wait()
	}()
	return quit
}

// GetValidWireGuardDrivers returns a list of available WireGuardDrivers for the current platform.
func GetValidWireGuardDrivers() []string {
	out := []string{
		string(AutoSelect),
		string(ExistingInterface),
		string(BoringTunDriver),
		string(WireGuardGoDriver),
	}
	if runtime.GOOS == "linux" {
		out = append(out, string(KernelDriver))
	}
	return out
}

// WireGuardDriverFromString returns a valid WireGuardDriver, or a descriptive error if the
// specified driver is invalid.
func WireGuardDriverFromString(driver string) (WireGuardDriver, error) {
	switch WireGuardDriver(driver) {
	case AutoSelect:
		return AutoSelect, nil
	case ExistingInterface:
		return ExistingInterface, nil
	case BoringTunDriver:
		return BoringTunDriver, nil
	case WireGuardGoDriver:
		return WireGuardGoDriver, nil
	case KernelDriver:
		if runtime.GOOS == "linux" {
			return KernelDriver, nil
		}
		return "", fmt.Errorf("WireGuard driver %q: %w", KernelDriver, errUnimplemented)
	default:
		return "", fmt.Errorf("unknown WireGuard driver %q", driver)
	}
}
