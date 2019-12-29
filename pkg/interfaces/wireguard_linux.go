// +build linux

package interfaces

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jcodybaker/wgmesh/pkg/log"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type wgInterface struct {
	*wgctrl.Client
	name string
	link netlink.Link
}

var _ WireGuardInterface = &wgInterface{}

type wgUserspaceInterface struct {
	wgInterface
	cmd        *exec.Cmd
	driverExit chan error
	closed     sync.Once
}

var _ WireGuardInterface = &wgUserspaceInterface{}

func createWGKernelInterface(wgClient *wgctrl.Client, options *WireGuardInterfaceOptions, name string) (WireGuardInterface, error) {
	wgLink := netlink.GenericLink{
		LinkType:  "wireguard",
		LinkAttrs: netlink.NewLinkAttrs(),
	}
	wgLink.LinkAttrs.Name = name

	err := netlink.LinkAdd(&wgLink)
	if err != nil {
		return nil, fmt.Errorf("adding net link %q: %w", name, err)
	}
	return newWGInterface(wgClient, name)
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
	link, err := waitForInterface(ctx, exit, name)
	if err != nil {
		return nil, fmt.Errorf("waiting for interface %q to be created: %w", name, err)
	}
	return &wgUserspaceInterface{
		cmd: cmd,
		wgInterface: wgInterface{
			link:   link,
			name:   name,
			Client: wgClient,
		},
	}, nil
}

func waitForInterface(ctx context.Context, exit <-chan error, name string) (netlink.Link, error) {
	updates := make(chan netlink.LinkUpdate) // netlink.LinkSubscribe... will close
	done := make(chan struct{})
	defer close(done)

	err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
		ListExisting: true,
	})
	if err != nil {
		return nil, fmt.Errorf("initializing link subscription: %w", err)
	}

	t := time.NewTimer(interfaceTimeout)
	defer t.Stop()

	ll := log.FromContext(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case update := <-updates:
			attr := update.Attrs()
			if attr == nil {
				return nil, errors.New("netlink update had nil link attributes")
			}
			if attr.Name == name {
				return update.Link, nil
			}
			ll.WithFields(logrus.Fields{
				"interface.name":    attr.Name,
				"interface.desired": name,
			}).Debug("ignoring update about irrelevant interface")
			continue
		case err := <-exit:
			if err == nil {
				return nil, errors.New("userspace driver exited 0")
			}
			if eErr, ok := err.(*exec.ExitError); ok && eErr.ProcessState != nil {
				return nil, fmt.Errorf("userspace driver exited %d", eErr.ProcessState.ExitCode())
			}
			return nil, fmt.Errorf("monitoring userspace driver: %w", err)
		case <-t.C:
			return nil, errors.New("timeout")
		}
	}
}

func newWGInterface(wgClient *wgctrl.Client, name string) (WireGuardInterface, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	return &wgInterface{
		Client: wgClient,
		name:   name,
		link:   link,
	}, nil
}

// EnsureUp sets the interface to the "UP" state if it is not currently up.
func (w *wgInterface) EnsureUp() error {
	err := netlink.LinkSetUp(w.link)
	if err != nil {
		return fmt.Errorf("setting link %q up: %w", w.name, err)
	}
	return nil
}

// GetIPs returns a list of IP addresses currently active on the interface.
func (w *wgInterface) GetIPs() ([]string, error) {
	// TODO - IPv6
	addrs, err := netlink.AddrList(w.link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("listing %q addresses: %w", w.name, err)
	}
	var out []string
	for _, addr := range addrs {
		out = append(out, addr.IPNet.String())
	}
	return out, nil
}

// EnsureIP adds the specified IPNet to the interface, if it is not already added.
func (w *wgInterface) EnsureIP(ip *net.IPNet) error {
	err := netlink.AddrAdd(w.link, &netlink.Addr{IPNet: ip})
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("adding IP address %q: %w", ip.String(), err)
	}
	return nil
}

func (w *wgInterface) Close() error {
	err := netlink.LinkDel(w.link)
	if os.IsNotExist(err) {
		return nil // Don't error if the interface is already gone.
	}
	if err != nil {
		return fmt.Errorf("deleting interface %q: %w", w.name, err)
	}
	return nil
}

func (w *wgUserspaceInterface) Close() error {
	var errs []error
	w.closed.Do(func() {
		err := w.wgInterface.Close()
		if err != nil {
			errs = append(errs, err)
			// fall through to cleanup any processes
		}

		var pid int
		if w.cmd == nil && w.cmd.ProcessState == nil {
			errs = append(errs, errors.New("userspace driver cmd not set"))
			return
		}
		pid = w.cmd.ProcessState.Pid()
		if pid == 0 {
			errs = append(errs, errors.New("userspace driver pid not set"))
			return
		}
		err = syscall.Kill(pid, syscall.SIGTERM)
		if err != nil {
			errs = append(errs, fmt.Errorf("signaling shutdown to userspace driver", err))
			// fall through to KILL
		}
		t := time.NewTimer(userspaceShutdownTimeout)
		defer t.Stop()
		select {
		case <-t.C:
			err = syscall.Kill(pid, syscall.SIGKILL)
			if err != nil {
				errs = append(errs, fmt.Errorf("killing userspace driver", err))
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

func getAllInterfaces(desired string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("listing all interfaces: %w", err)
	}
	base := desired
	if strings.HasSuffix(desired, "+") {
		base = desired[:len(desired)-1]
	}
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			continue
		}
		if !strings.HasPrefix(attrs.Name, base) {
			continue
		}
		out[attrs.Name] = struct{}{}
	}
	return out, nil
}
