package agent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	wgmeshClientSet "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/clientset/versioned"
	wgInformer "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/informers/externalversions"
	wgk8s "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/v1alpha1"
	"github.com/jcodybaker/wgmesh/pkg/interfaces"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Agent creates a WireGuard interface, advertises it in the registry, and
// manages relationships with its peers.
type Agent struct {
	options

	localCS      *kubernetes.Clientset
	regClientset *wgmeshClientSet.Clientset

	initOnce  sync.Once
	closeOnce sync.Once
	wg        sync.WaitGroup

	localPeer *wgk8s.WireGuardPeer

	iface interfaces.WireGuardInterface

	privateKey  wgtypes.Key
	publicKey   wgtypes.Key
	psk         wgtypes.Key
	peerTracker *peerTracker
}

// NewAgent creates an agent to manage a local WireGuard peer.
func NewAgent(name string, optionFuncs ...OptionFunc) (*Agent, error) {
	a := &Agent{
		options: defaultOptions(),
	}
	a.name = name
	for _, f := range optionFuncs {
		err := f(&a.options)
		if err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *Agent) init(ctx context.Context) error {
	// setup the clientsets
	if a.localKubeClientConfig != nil {
		a.ll.Debugf("building local kubernetes clientset")
		// local kubeconfig is optional. Without it, we can't get insight into this node/pod
		// but all of those values can be manually specified.
		localConfig, err := a.localKubeClientConfig.ClientConfig()
		if err != nil {
			return fmt.Errorf("building restconfig from local kubeconfig: %w", err)
		}
		a.localCS, err = kubernetes.NewForConfig(localConfig)
		if err != nil {
			return fmt.Errorf("building local clientset: %w", err)
		}
	} else {
		a.ll.Debugf("skipping local kubernetes client, no kubeconfig specified")
	}

	a.ll.Debugf("building registry kubernetes clientset")
	registryConfig, err := a.registryKubeClientConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("building restconfig from registry kubeconfig: %w", err)
	}
	a.regClientset, err = wgmeshClientSet.NewForConfig(registryConfig)
	if err != nil {
		return fmt.Errorf("building registry wgmesh clientset: %w", err)
	}

	// Step 1 - Configure WireGuard
	a.ll.Debugln("generating private key")
	a.privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generating WireGuard private key: %w", err)
	}
	a.ll.Debugln("generating pre-shared key")
	a.psk, err = wgtypes.GenerateKey()
	if err != nil {
		return fmt.Errorf("generating WireGuard pre-shared key: %w", err)
	}

	// TODO - Validate K8s permissions w/ CanI
	return nil
}

// Run ...
func (a *Agent) Run(ctx context.Context) error {
	var err error
	a.initOnce.Do(func() {
		err = a.init(ctx)
	})
	if err != nil {
		return err
	}

	// Step 2 - Install our Kubernetes WireGuardPeer resource on to the server.
	a.updateK8sLocalPeer()
	err = a.registerK8sLocalPeer()
	if err != nil {
		return err
	}
	a.configureWireGuardPeers(ctx)
	<-ctx.Done()
	return nil
}

// updateK8sLocalPeer populates the Kubernetes WireGuardPeer object.
func (a *Agent) updateK8sLocalPeer() {
	if a.localPeer == nil {
		a.localPeer = &wgk8s.WireGuardPeer{
			ObjectMeta: metav1.ObjectMeta{
				Name:   a.name,
				Labels: a.labels,
			},
		}
	}
	a.localPeer.Spec = wgk8s.WireGuardPeerSpec{
		PublicKey:        a.publicKey.String(),
		Endpoint:         a.endpointAddr,
		PresharedKey:     a.psk.String(),
		IPs:              a.ips,
		Routes:           a.offerRoutes,
		KeepAliveSeconds: int(a.keepalive.Seconds()),
	}
}

func (a *Agent) registerK8sLocalPeer() error {
	a.ll.Infoln("registering local peer")
	var err error
	a.localPeer, err = a.regClientset.WgmeshV1alpha1().WireGuardPeers(a.registryNamespace).Create(a.localPeer)
	if err == nil {
		return nil
	}
	if !k8sErrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating k8s WireGuardPeer object %q: %w", a.name, err)
	}

	// The record already exists. Determine if its sane, and updates.
	a.ll.Infoln("a local peer wih our name was already registered, trying to update")
	a.localPeer, err = a.regClientset.WgmeshV1alpha1().WireGuardPeers(a.registryNamespace).Get(a.name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("fetching existing k8s WireGuardPeer object %q: %w", a.name, err)
	}
	if a.endpointAddr != a.localPeer.Spec.Endpoint {
		// This may mean two peers are trying to use the same name, which
		// would result flapping and constant rekeying.
		return fmt.Errorf(
			"existing k8s WireGuardPeer had endpoint %q, we have %q. Two or more peers may be sharing the same name",
			a.localPeer.Spec.Endpoint, a.endpointAddr)
	}
	// TODO: If our wg interface is configured w/ a private key and the public key matches the
	// record, we shouldn't rekey.
	a.localPeer, err = a.regClientset.WgmeshV1alpha1().WireGuardPeers(a.registryNamespace).Update(a.localPeer)
	if err != nil {
		return fmt.Errorf("updating k8s WireGuardPeer %q: %w", a.name, err)
	}
	return nil
}

func (a *Agent) initializeWireGuard() error {
	a.ll.Debugln("initializing WireGuard client")

	ll := a.ll.WithField("interface", a.iface)
	ll.Infoln("creating WireGuard interface")
	var err error
	a.iface, err = interfaces.EnsureWireGuardInterface(a.ctx, a.wgIfaceOptions)
	if err != nil {
		return err
	}

	ll.Infoln("configuring key and port on WireGuard interface")
	// TODO - Ability to reuse existing private key
	err = a.iface.ConfigureWireGuard(wgtypes.Config{
		PrivateKey: &a.privateKey,
	})
	if err != nil {
		return err
	}

	for _, ip := range a.ips {
		addr, subnet, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("parsing IP %q", err)
		}
		// net.ParseCIDR puts the network base addr in IP by default, but we need to
		// specify the specific addr we want.
		subnet.IP = addr
		err = a.iface.EnsureIP(subnet)
	}

	ll.Debugln("setting device state up")
	err = a.iface.EnsureUp()
	if err != nil {
		return err
	}

	ifacePort, err := a.iface.GetListenPort()
	if err != nil {
		return err
	}

	endpointAddr, endpointPort, err := net.SplitHostPort(a.endpointAddr)
	if err != nil {
		return err
	}
	if endpointPort == "" || endpointPort == "0" {
		// If endpointAddr included a port, we should trust it. The user likely has some flavor
		// of DNAT between the public internet and this app. If no port is specified, we'll add
		// the port bound by the WireGuard driver.
		a.endpointAddr = net.JoinHostPort(endpointAddr, strconv.FormatInt(int64(ifacePort), 10))
		// TODO - Do we actually want to do this? If we're behind NAT it may mean nothing.
		ll.Debugln("adding port to endpoint")
	}

	return nil
}

func (a *Agent) configureWireGuardPeers(ctx context.Context) error {
	a.ll.Infoln("initializing WireGuardPeers from api")

	ll := a.ll.WithFields(logrus.Fields{
		"namespace": a.registryNamespace,
		"labels":    a.peerSelector.String(),
	})
	ll.Debugln("building informer")
	factory := wgInformer.NewSharedInformerFactoryWithOptions(
		a.regClientset, 0,
		wgInformer.WithTweakListOptions(func(listOptions *metav1.ListOptions) {
			listOptions.LabelSelector = a.peerSelector.String()
		}),
		wgInformer.WithNamespace(a.registryNamespace))

	informer := factory.Wgmesh().V1alpha1().WireGuardPeers().Informer()

	a.peerTracker = &peerTracker{
		keepalive: a.keepalive,
		ll:        a.ll,
		iface:     a.iface,
		peers:     make(map[string]*wgk8s.WireGuardPeer),
		localPeer: a.localPeer,
	}

	informer.AddEventHandler(a.peerTracker)

	ll.Infoln("launching informer")
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		informer.Run(ctx.Done())
	}()

	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return fmt.Errorf("failed to sync WireGuardPeers")
	}
	ll.Infoln("cache fully synced; applying initial config to interface")
	// Ok, everything should be sync'ed now.
	return a.peerTracker.applyInitialConfig()
}

// Close shuts down and cleans up the agent.
func (a *Agent) Close() error {
	var err error
	a.closeOnce.Do(func() {
		// TODO cancel informer context.

		// Wait for the informer to stop so we don't apply any to a closing interface.
		a.wg.Wait()

		if a.iface != nil {
			a.iface.Close()
		}
	})
	return err
}
