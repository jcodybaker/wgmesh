package agent

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/clientcmd"
)

type options struct {
	ctx context.Context
	ll  log.FieldLogger

	name string

	localKubeClientConfig    clientcmd.ClientConfig
	registryKubeClientConfig clientcmd.ClientConfig
	registryNamespace        string

	iface     string
	keepalive time.Duration

	endpointAddr string
	port         int
	ips          []string
	offerRoutes  []string

	peerSelector labels.Selector
	labels       labels.Set
}

func defaultOptions() options {
	return options{
		peerSelector: labels.Everything(),
	}
}

// OptionFunc describes the function signature for methods which modify the agentOptions.
type OptionFunc func(*options) error

// WithLogger sets a logger on the agent options.
func WithLogger(ll log.FieldLogger) OptionFunc {
	return func(o *options) error {
		o.ll = ll
		return nil
	}
}

// WithLocalKubeClientConfig sets the config for the local kubernetes cluster.
// This is used to retrieve info about the local node, pod, and services. If no
// registry kubeconfig is specified, this config will also be used to register
// this peer and discover others.
func WithLocalKubeClientConfig(config clientcmd.ClientConfig) OptionFunc {
	return func(o *options) error {
		o.localKubeClientConfig = config
		if o.registryKubeClientConfig == nil {
			return WithRegistryKubeClientConfig(config)(o)
		}
		return nil
	}
}

// WithRegistryKubeClientConfig sets the config for the wgmesh registry, which is
// used to register this peer and discover others.
func WithRegistryKubeClientConfig(config clientcmd.ClientConfig) OptionFunc {
	return func(o *options) error {
		o.registryKubeClientConfig = config
		ns, _, err := config.Namespace()
		if err != nil {
			return fmt.Errorf("looking up namespace for local kubeconfig: %w", err)
		}
		o.registryNamespace = ns
		return nil
	}
}

// WithInterface sets the interface name which will be used for wireguard.
func WithInterface(iface string) OptionFunc {
	return func(o *options) error {
		o.iface = iface
		return nil
	}
}

// WithKeepAliveDuration sets the minimum keep-alive duration which this node
// should use when communicating with peers.
func WithKeepAliveDuration(keepalive time.Duration) OptionFunc {
	return func(o *options) error {
		o.keepalive = keepalive
		return nil
	}
}

// WithIPs sets a list of IP addresses to add to the wireguard interface.
func WithIPs(ips []string) OptionFunc {
	return func(o *options) error {
		o.ips = ips
		return nil
	}
}

// WithOfferRoutes sets a list of CIDR style routes which we should offer to peers.
func WithOfferRoutes(offerRoutes []string) OptionFunc {
	return func(o *options) error {
		o.offerRoutes = offerRoutes
		return nil
	}
}

// WithPeerSelector is a label selector which sets the list of peers we will
// add to the wireguard interface. This can be used to exclude peers we have
// local connectivty with.
func WithPeerSelector(peerSelector labels.Selector) OptionFunc {
	return func(o *options) error {
		o.peerSelector = peerSelector
		return nil
	}
}

// WithLabels sets the labels for this peer.
func WithLabels(labels labels.Set) OptionFunc {
	return func(o *options) error {
		o.labels = labels
		return nil
	}
}
