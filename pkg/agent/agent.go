package agent

import (
	"fmt"

	wgmeshClientSet "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/clientset/versioned"
	wgk8s "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/v1alpha1"
	"github.com/jcodybaker/wgmesh/pkg/interfaces"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

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
	ip         string
	routes     []string

	iface    string
	wgClient *wgctrl.Client
}

// Run ...
func Run(endpointName string, bindAddr string, port uint16, kubeCS *kubernetes.Clientset, wgmeshCS *wgmeshClientSet.Clientset) error {
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
	}

	wgClient, err := a.initializeWireguard()
	if err != nil {
		return err
	}
	defer wgClient.Close()

	// Step 2 - Install our Kubernetes WireguardPeer resource on to the server.
	thisPeer := &wgk8s.WireguardPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name: endpointName,
		},
	}
	a.updatek8sLocalPeer(thisPeer)
	thisPeer, err = wgmeshCS.WgmeshV1alpha1().WireguardPeers("").Create(thisPeer)
	switch {
	case k8sErrors.IsAlreadyExists(err):
		thisPeer, err = wgmeshCS.WgmeshV1alpha1().WireguardPeers("").Get(a.name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("fetching existing k8s WireguardPeer object %q: %w", endpointName, err)
		}
		if a.endpoint != thisPeer.Spec.Endpoint {
			// This may mean two peers are trying to use the same name, which
			// would result flapping and constant rekeying.
			return fmt.Errorf(
				"existing k8s WireguardPeer had endpoint %q, we have %q. Two or more peers may be sharing the same name",
				thisPeer.Spec.Endpoint, a.endpoint)
		}
		a.ip = thisPeer.Spec.IP
		a.updatek8sLocalPeer(thisPeer)
		thisPeer, err = wgmeshCS.WgmeshV1alpha1().WireguardPeers("").Update(thisPeer)
		if err != nil {
			return fmt.Errorf("updating k8s WireguardPeer %q: %w", endpointName, err)
		}
	case err == nil:
		// success
	default:
		return fmt.Errorf("creating k8s WireguardPeer object %q: %w", endpointName, err)
	}

	return nil
}

// updateK8sLocalPeer populates the Kubernetes WireguardPeer object.
func (a *agent) updatek8sLocalPeer(thisPeer *wgk8s.WireguardPeer) {
	thisPeer.Spec = wgk8s.WireguardPeerSpec{
		PublicKey:    a.publicKey.String(),
		Endpoint:     a.endpoint,
		Port:         uint16(a.port),
		PresharedKey: a.psk.String(),
		IP:           a.ip,
		Routes:       a.routes,
	}
	// ep.Name = "whoops"
	// _, err = wgmeshClientset.WgmeshV1alpha1().WireguardPeers("default").Create(ep)
	// if err != nil {
	// 	panic(err.Error())
	// }

	// factory := wgInformer.NewSharedInformerFactoryWithOptions(wgmeshClientset, 0)
	// informer := factory.Wgmesh().V1alpha1().WireguardPeers()
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

func (a *agent) configureWireguardPeers(wgClient *wgctrl.Client) error {
	return nil
}
