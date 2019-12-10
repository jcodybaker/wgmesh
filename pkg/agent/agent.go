package agent

import (
	"context"
	"fmt"
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
	name       string
	privateKey wgtypes.Key
	publicKey  wgtypes.Key
	psk        wgtypes.Key
	endpoint   string
	port       int
	keepalive  time.Duration
	ips        []string
	routes     []string

	labelSelector string

	peerTracker *peerTracker

	iface    string
	wgClient *wgctrl.Client

	minKeepAlive time.Duration
}

// Run ...
func Run(ll log.FieldLogger, endpointName string, bindAddr string, port uint16, keepalive time.Duration, kubeCS *kubernetes.Clientset, wgmeshCS *wgmeshClientSet.Clientset) error {
	// TODO - Step 0 - Validate K8s permissions w/ CanI

	// Step 1 - Configure wireguard
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generating wireguard private key: %w", err)
	}
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return fmt.Errorf("generating wireguard pre-shared key: %w", err)
	}

	a := &agent{
		name:       endpointName,
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey(),
		psk:        psk,
		endpoint:   bindAddr,
		port:       int(port),
		keepalive:  keepalive,
	}

	wgClient, err := a.initializeWireguard()
	if err != nil {
		return err
	}
	defer wgClient.Close()

	// Step 2 - Install our Kubernetes WireGuardPeer resource on to the server.
	thisPeer := &wgk8s.WireGuardPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name: endpointName,
		},
	}
	a.updatek8sLocalPeer(thisPeer)
	thisPeer, err = wgmeshCS.WgmeshV1alpha1().WireGuardPeers("").Create(thisPeer)
	switch {
	case k8sErrors.IsAlreadyExists(err):
		thisPeer, err = wgmeshCS.WgmeshV1alpha1().WireGuardPeers("").Get(a.name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("fetching existing k8s WireGuardPeer object %q: %w", endpointName, err)
		}
		if a.endpoint != thisPeer.Spec.Endpoint {
			// This may mean two peers are trying to use the same name, which
			// would result flapping and constant rekeying.
			return fmt.Errorf(
				"existing k8s WireGuardPeer had endpoint %q, we have %q. Two or more peers may be sharing the same name",
				thisPeer.Spec.Endpoint, a.endpoint)
		}
		a.ips = thisPeer.Spec.IPs
		a.updatek8sLocalPeer(thisPeer)
		thisPeer, err = wgmeshCS.WgmeshV1alpha1().WireGuardPeers("").Update(thisPeer)
		if err != nil {
			return fmt.Errorf("updating k8s WireGuardPeer %q: %w", endpointName, err)
		}
	case err == nil:
		// success
	default:
		return fmt.Errorf("creating k8s WireGuardPeer object %q: %w", endpointName, err)
	}

	return nil
}

// updateK8sLocalPeer populates the Kubernetes WireGuardPeer object.
func (a *agent) updatek8sLocalPeer(thisPeer *wgk8s.WireGuardPeer) {
	thisPeer.Spec = wgk8s.WireGuardPeerSpec{
		PublicKey:        a.publicKey.String(),
		Endpoint:         a.endpoint,
		Port:             uint16(a.port),
		PresharedKey:     a.psk.String(),
		IPs:              a.ips,
		Routes:           a.routes,
		KeepAliveSeconds: int(a.keepalive.Seconds()),
	}
}

func (a *agent) initializeWireguard() (wgClient *wgctrl.Client, err error) {
	wgClient, err = wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("initializing wgctrl client: %w", err)
	}
	defer func() {
		if err != nil && wgClient != nil {
			wgClient.Close()
			wgClient = nil
		}
	}()
	err = interfaces.EnsureWireguardInterface(wgClient, a.iface)
	if err != nil {
		return // named args to facilitate cleanup.
	}
	err = wgClient.ConfigureDevice(a.iface, wgtypes.Config{
		PrivateKey: &a.privateKey,
		ListenPort: &a.port,
	})
	if err != nil {
		return
	}
	return wgClient, nil
}

func (a *agent) configureWireGuardPeers(ctx context.Context, wgClient *wgctrl.Client, wgmeshCS *wgmeshClientSet.Clientset) error {
	var err error
	labelSelector := labels.Everything()

	if a.labelSelector != "" {
		labelSelector, err = labels.Parse(a.labelSelector)
		if err != nil {
			return fmt.Errorf("failed to parse label selector: %w", labelSelector)
		}
	}

	factory := wgInformer.NewSharedInformerFactoryWithOptions(
		wgmeshCS, 0, wgInformer.WithTweakListOptions(func(listOptions *metav1.ListOptions) {
			listOptions.LabelSelector = labelSelector.String()
		}))

	informer := factory.Wgmesh().V1alpha1().WireGuardPeers().Informer()

	a.peerTracker = &peerTracker{
		keepalive: a.keepalive,
		wgClient:  wgClient,
	}

	informer.AddEventHandler(a.peerTracker)

	go informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return fmt.Errorf("failed to sync WireGuardPeers")
	}
	// Ok, everything should be sync'ed now.
	return a.peerTracker.applyInitialConfig()
}
