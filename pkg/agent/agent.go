package agent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	wgmeshClientSet "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/clientset/versioned"
	wgInformer "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/informers/externalversions"
	wgk8s "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/v1alpha1"
	"github.com/jcodybaker/wgmesh/pkg/interfaces"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s.io/apimachinery/pkg/labels"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type agent struct {
	name         string
	privateKey   wgtypes.Key
	publicKey    wgtypes.Key
	psk          wgtypes.Key
	endpointAddr string
	port         int
	keepalive    time.Duration
	ips          []string
	routes       []string

	ll log.FieldLogger

	labelSelector string

	peerTracker *peerTracker

	iface         string
	wgClient      *wgctrl.Client
	kubeNamespace string

	minKeepAlive time.Duration
}

// Run ...
func Run(ctx context.Context, ll log.FieldLogger, iface, name, endpointAddr string, port uint16, keepalive time.Duration, kubeCS *kubernetes.Clientset, wgmeshCS *wgmeshClientSet.Clientset, kubeNamespace string) error {
	// TODO - Step 0 - Validate K8s permissions w/ CanI

	// Step 1 - Configure wireguard
	ll.Debugln("generating private key")
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generating wireguard private key: %w", err)
	}
	ll.Debugln("generating pre-shared key")
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return fmt.Errorf("generating wireguard pre-shared key: %w", err)
	}

	a := &agent{
		name:          name,
		privateKey:    privateKey,
		publicKey:     privateKey.PublicKey(),
		psk:           psk,
		endpointAddr:  endpointAddr,
		port:          int(port),
		keepalive:     keepalive,
		iface:         iface,
		kubeNamespace: kubeNamespace,
		ll:            log.WithContext(ctx),
	}

	a.wgClient, err = a.initializeWireguard()
	if err != nil {
		return err
	}
	//defer wgClient.Close()

	// Step 2 - Install our Kubernetes WireGuardPeer resource on to the server.
	localPeer := &wgk8s.WireGuardPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	a.updatek8sLocalPeer(localPeer)
	localPeer, err = wgmeshCS.WgmeshV1alpha1().WireGuardPeers(a.kubeNamespace).Create(localPeer)
	switch {
	case k8sErrors.IsAlreadyExists(err):
		localPeer, err = wgmeshCS.WgmeshV1alpha1().WireGuardPeers(a.kubeNamespace).Get(a.name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("fetching existing k8s WireGuardPeer object %q: %w", a.name, err)
		}
		if a.endpointAddr != localPeer.Spec.Endpoint {
			// This may mean two peers are trying to use the same name, which
			// would result flapping and constant rekeying.
			return fmt.Errorf(
				"existing k8s WireGuardPeer had endpoint %q, we have %q. Two or more peers may be sharing the same name",
				localPeer.Spec.Endpoint, a.endpointAddr)
		}
		a.ips = localPeer.Spec.IPs
		a.updatek8sLocalPeer(localPeer)
		localPeer, err = wgmeshCS.WgmeshV1alpha1().WireGuardPeers(a.kubeNamespace).Update(localPeer)
		if err != nil {
			return fmt.Errorf("updating k8s WireGuardPeer %q: %w", a.name, err)
		}
	case err == nil:
		// success
	default:
		return fmt.Errorf("creating k8s WireGuardPeer object %q: %w", a.name, err)
	}

	a.configureWireGuardPeers(ctx, wgmeshCS, localPeer)
	<-ctx.Done()
	return nil
}

// updateK8sLocalPeer populates the Kubernetes WireGuardPeer object.
func (a *agent) updatek8sLocalPeer(localPeer *wgk8s.WireGuardPeer) {
	localPeer.Spec = wgk8s.WireGuardPeerSpec{
		PublicKey:        a.publicKey.String(),
		Endpoint:         a.endpointAddr,
		PresharedKey:     a.psk.String(),
		IPs:              a.ips,
		Routes:           a.routes,
		KeepAliveSeconds: int(a.keepalive.Seconds()),
	}
}

func (a *agent) initializeWireguard() (wgClient *wgctrl.Client, err error) {
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

func (a *agent) configureWireGuardPeers(ctx context.Context, wgmeshCS *wgmeshClientSet.Clientset, localPeer *wgk8s.WireGuardPeer) error {
	var err error
	a.ll.Infoln("initializing WireGuardPeers from api")
	labelSelector := labels.Everything()

	if a.labelSelector != "" {
		labelSelector, err = labels.Parse(a.labelSelector)
		if err != nil {
			return fmt.Errorf("failed to parse label selector: %w", labelSelector)
		}
	}

	ll := a.ll.WithFields(log.Fields{
		"namespace": a.kubeNamespace,
		"labels":    labelSelector.String(),
	})
	ll.Debugln("building informer")
	factory := wgInformer.NewSharedInformerFactoryWithOptions(
		wgmeshCS, 0,
		wgInformer.WithTweakListOptions(func(listOptions *metav1.ListOptions) {
			listOptions.LabelSelector = labelSelector.String()
		}),
		wgInformer.WithNamespace(a.kubeNamespace))

	informer := factory.Wgmesh().V1alpha1().WireGuardPeers().Informer()

	a.peerTracker = &peerTracker{
		keepalive: a.keepalive,
		wgClient:  a.wgClient,
		ll:        a.ll,
		iface:     a.iface,
		peers:     make(map[string]*wgk8s.WireGuardPeer),
		localPeer: localPeer,
	}

	informer.AddEventHandler(a.peerTracker)

	ll.Infoln("launching informer")
	go informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return fmt.Errorf("failed to sync WireGuardPeers")
	}
	ll.Infoln("cache fully synced; applying initial config to interface")
	// Ok, everything should be sync'ed now.
	return a.peerTracker.applyInitialConfig()
}
