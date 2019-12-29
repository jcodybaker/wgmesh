package interfaces

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/jcodybaker/wgmesh/pkg/log"
)

type linuxInterface struct {
	name string
	link netlink.Link
}

func newInterface(name string) (Interface, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	return &linuxInterface{
		name: name,
		link: link,
	}, nil
}

func waitForInterface(ctx context.Context, exit <-chan error, name string) (Interface, error) {
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
				// SUCCESS
				return &linuxInterface{
					name: name,
					link: update.Link,
				}, nil
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

// EnsureUp sets the interface to the "UP" state if it is not currently up.
func (i *linuxInterface) EnsureUp() error {
	err := netlink.LinkSetUp(i.link)
	if err != nil {
		return fmt.Errorf("setting link %q up: %w", i.name, err)
	}
	return nil
}

// GetIPs returns a list of IP addresses currently active on the interface.
func (i *linuxInterface) GetIPs() ([]string, error) {
	// TODO - IPv6
	addrs, err := netlink.AddrList(i.link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("listing %q addresses: %w", i.name, err)
	}
	var out []string
	for _, addr := range addrs {
		out = append(out, addr.IPNet.String())
	}
	return out, nil
}

func (i *linuxInterface) GetName() string {
	return i.name
}

// EnsureIP adds the specified IPNet to the interface, if it is not already added.
func (i *linuxInterface) EnsureIP(ip *net.IPNet) error {
	err := netlink.AddrAdd(i.link, &netlink.Addr{IPNet: ip})
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("adding IP address %q: %w", ip.String(), err)
	}
	return nil
}

func (i *linuxInterface) Close() error {
	err := netlink.LinkDel(i.link)
	if os.IsNotExist(err) {
		return nil // Don't error if the interface is already gone.
	}
	if err != nil {
		return fmt.Errorf("deleting interface %q: %w", i.name, err)
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
