package interfaces

import (
	"net"
)

// Interface describes actions which can be performed against a network interface.
type Interface interface {
	// Close deletes the interface and stops any drivers from servicing it.
	Close() error

	// EnsureIP adds an IP address to the specified interface if it does not already exist.
	EnsureIP(ip *net.IPNet) error

	// EnsureUp sets an interface into the UP state if it is not already UP. This begins
	// communication over the WireGuard protocol w/ any listed peers.
	EnsureUp() error

	// GetName returns the name used to identify the interface.
	GetName() string

	// GetIPs returns a list of IP addresses assigned to the specified interface.
	GetIPs() ([]string, error)
}
