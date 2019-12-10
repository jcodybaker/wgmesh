package agent

import (
	"fmt"
	"net"
	"sync"
	"time"
	"reflect"

	wgk8s "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/v1alpha1"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type peerTracker struct {
	sync.Mutex

	ll                   log.FieldLogger
	wgClient             *wgctrl.Client
	iface                string
	peers                map[string]*wgk8s.WireGuardPeer
	initialConfigApplied bool

	keepalive time.Duration
}

func (pt *peerTracker) applyUpdate(wgPeer *wgk8s.WireGuardPeer) error {
	pt.Lock()
	defer pt.Unlock()
	name := k8sNameString(wgPeer)
	if current, ok := pt.peers[name]; ok && reflect.DeepEqual(current, wgPeer) {
		// No update
		return nil
	}
	pt.peers[name] = wgPeer.DeepCopy()
	if !pt.initialConfigApplied {
		return nil
	}
	peer, err := pt.k8sToWgctrl(wgPeer)
	if err != nil {
		return err
	}
	return pt.wgClient.ConfigureDevice(pt.iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	})
}

func (pt *peerTracker) applyInitialConfig() error {
	pt.Lock()
	defer pt.Unlock()
	pt.initialConfigApplied = true

	device, err := pt.wgClient.Device(pt.iface)
	if err != nil {
		return fmt.Errorf("initializing peer tracker: %w", err)
	}

	var config = wgtypes.Config{
		ReplacePeers: true,
	}
	for _, wgPeer := range pt.peers {
		peer, err := pt.k8sToWgctrl(wgPeer)
		if err != nil {
			// Don't fail out if a single peer fails.
			// TODO - add retry for temporary erors (ex. dns resolution)
			pt.ll.WithFields(log.Fields{
				"k8s_namespace": wgPeer.Namespace,
				"k8s_kind":      wgPeer.Kind,
				"k8s_name":      wgPeer.Name,
			}).WithError(err).Error("failed to build control peer")
			continue
		}
		config.Peers = append(config.Peers, peer)
	}
	return pt.wgClient.ConfigureDevice(pt.iface, config)
}

func (pt *peerTracker) OnAdd(obj interface{}) {
	wgPeer, ok := obj.(*wgk8s.WireGuardPeer)
	if !ok {
		pt.ll.WithField("unexpected_type", fmt.Sprintf("%T", obj)).
			Warn("unexpected type")
	}
	ll := pt.ll.WithFields(log.Fields{
		"k8s_namespace": wgPeer.Namespace,
		"k8s_kind":      wgPeer.Kind,
		"k8s_name":      wgPeer.Name,
	})
	err := pt.applyUpdate(wgPeer)
	if err != nil {

	}
}

func (pt *peerTracker) OnUpdate(oldObj, newObj interface{}) {
	pt.OnAdd(newObj)
}

func (pt *peerTracker) OnDelete(obj interface{}) {
	config := &wgtypes.PeerConfig{
		PublicKey: publicKey,
		Endpoint:  dst,
	}
}

func  (pt *peerTracker) k8sToWgctrl(wgPeer *wgk8s.WireGuardPeer) (config wgtypes.PeerConfig, err error) {
	config.PublicKey, err = wgtypes.ParseKey(wgPeer.Spec.PublicKey)
	if err != nil {
		err = fmt.Errorf("failed to parse public key: %w", err)
		return
	}

	addr := net.JoinHostPort(wgPeer.Spec.Endpoint, string(wgPeer.Spec.Port))
	config.Endpoint, err = net.ResolveUDPAddr("udp", addr)
	if err != nil {
		err = fmt.Errorf("failed to resolve endpoint %q: %w", addr, err)
		return
	}

	if wgPeer.Spec.KeepAliveSeconds > 0 {
		keepalive := time.Duration(time.Duration(wgPeer.Spec.KeepAliveSeconds) * time.Second)
		if pt.keepalive > 0 && pt.keepalive < keepalive {
			keepalive = pt.keepalive
		}
		config.PersistentKeepaliveInterval = &keepalive
	}
	return
}

func k8sNameString(obj metav1.Object) string {
	return fmt.Sprintf("%s/%s/%s", obj.Kind, obj.Namespace, obj.Name)
}

func wireGuardPeerIsEqual(old, new *wgk8s.WireGuardPeer) bool {
	return reflect.Equal(old.Spec, new.Spec)
}