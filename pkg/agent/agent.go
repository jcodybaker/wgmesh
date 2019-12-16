package agent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	wgmeshClientSet "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/clientset/versioned"
	wgInformer "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/informers/externalversions"
	wgk8s "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/v1alpha1"
	"github.com/jcodybaker/wgmesh/pkg/interfaces"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Agent creates a wireguard interface, advertises it in the registry, and
// manages relationships with its peers.
type Agent struct {
	options

	localCS      *kubernetes.Clientset
	regClientset *wgmeshClientSet.Clientset

	initOnce sync.Once
	wg       sync.WaitGroup

	localPeer *wgk8s.WireGuardPeer

	wgClient    *wgctrl.Client
	privateKey  wgtypes.Key
	publicKey   wgtypes.Key
	psk         wgtypes.Key
	peerTracker *peerTracker
}

// NewAgent creates an agent to manage a local wireguard peer.
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

	// Step 1 - Configure wireguard
	a.ll.Debugln("generating private key")
	a.privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generating wireguard private key: %w", err)
	}
	a.ll.Debugln("generating pre-shared key")
	a.psk, err = wgtypes.GenerateKey()
	if err != nil {
		return fmt.Errorf("generating wireguard pre-shared key: %w", err)
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

	a.wgClient, err = a.initializeWireguard()
	if err != nil {
		return err
	}
	defer a.wgClient.Close()
	// We don't want to close the wgClient before all of the goroutines which may depend
	// on it are finished, so we put the waitgroup at the top of the stack.
	defer a.wg.Wait()

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

func (a *Agent) initializeWireguard() (wgClient *wgctrl.Client, err error) {
	a.ll.Debugln("initializing wiregaurd client")
	wgClient, err = wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("initializing wgctrl client: %w", err)
	}
	defer func() {
		if err != nil && wgClient != nil {
			a.ll.Infoln("closing wireguard client")
			wgClient.Close()
			wgClient = nil
		}
	}()
	ll := a.ll.WithField("interface", a.iface)
	ll.Infoln("creating wireguard interface")
	err = interfaces.EnsureWireguardInterface(wgClient, a.iface)
	if err != nil {
		return // named args to facilitate cleanup.
	}

	ll.Debugln("loading up wireguard device")
	device, err := wgClient.Device(a.iface)
	if err != nil {
		return // named args to facilitate cleanup.
	}
	existingPort := device.ListenPort
	if a.port == 0 {
		a.port = existingPort
	}
	if a.port != existingPort {
		return nil, fmt.Errorf("existing interface bound to different port")
	}

	ll.Infoln("configuring key and port on wireguard interface")
	err = wgClient.ConfigureDevice(a.iface, wgtypes.Config{
		PrivateKey: &a.privateKey,
		ListenPort: &a.port,
	})
	if err != nil {
		return
	}

	ll.Debugln("setting device state up")
	err = interfaces.SetInterfaceUp(a.iface)
	if err != nil {
		return // named args to facilitate cleanup.
	}
	device, err = wgClient.Device(a.iface)
	if err != nil {
		return // named args to facilitate cleanup.
	}
	a.port = device.ListenPort
	endpointAddr, endpointPort, err := net.SplitHostPort(a.endpointAddr)
	if err != nil {
		return // named args to facilitate cleanup.
	}
	if endpointPort == "" || endpointPort == "0" {
		// The endpointAddr didn't specifiy a port, use the dynamic port from the wg interface.
		a.endpointAddr = net.JoinHostPort(endpointAddr, strconv.FormatInt(int64(a.port), 10))
		// TODO - Do we actually want to do this? If we're behind NAT it may mean nothing.
		ll.Debugln("adding port to endpoint")
	}

	return wgClient, nil
}

func (a *Agent) configureWireGuardPeers(ctx context.Context) error {
	a.ll.Infoln("initializing WireGuardPeers from api")

	ll := a.ll.WithFields(log.Fields{
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
		wgClient:  a.wgClient,
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
