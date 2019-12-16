package agent

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

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
	localPeer            *wgk8s.WireGuardPeer

	keepalive time.Duration
}

func (pt *peerTracker) applyUpdate(wgPeer *wgk8s.WireGuardPeer) error {
	pt.Lock()
	defer pt.Unlock()
	name := wgPeer.GetSelfLink()
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

func (pt *peerTracker) deletePeer(wgPeer *wgk8s.WireGuardPeer) error {
	pt.Lock()
	defer pt.Unlock()
	name := wgPeer.GetSelfLink()
	current, ok := pt.peers[name]
	if !ok {
		return nil // We've never heard of it, goodbye.
	}
	if !pt.initialConfigApplied {
		delete(pt.peers, name)
		return nil
	}
	// Ok, we actually have to wind this one back.
	peer, err := pt.k8sToWgctrl(current)
	if err != nil {
		return err
	}
	peer.Remove = true
	return pt.wgClient.ConfigureDevice(pt.iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	})
}

func (pt *peerTracker) applyInitialConfig() error {
	pt.Lock()
	defer pt.Unlock()
	pt.initialConfigApplied = true

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
			}).WithError(err).Warn("failed to build control peer")
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
	if wgPeer.GetSelfLink() == pt.localPeer.GetSelfLink() {
		// Got ourselves, no-op
		return
	}
	ll := pt.ll.WithFields(log.Fields{
		"k8s_namespace": wgPeer.Namespace,
		"k8s_kind":      wgPeer.Kind,
		"k8s_name":      wgPeer.Name,
	})
	ll.Info("WireGuardPeer added, adding peer")
	err := pt.applyUpdate(wgPeer)
	if err != nil {
		// TODO - requeue when appropriate
		ll.Errorf("WireGuardPeer failed to add: %v", err)
	}
	ll.Info("WireGuardPeer added successfully")
}

func (pt *peerTracker) OnUpdate(_, newObj interface{}) {
	wgPeer, ok := newObj.(*wgk8s.WireGuardPeer)
	if !ok {
		pt.ll.WithField("unexpected_type", fmt.Sprintf("%T", newObj)).
			Warn("unexpected type")
	}
	if wgPeer.GetSelfLink() == pt.localPeer.GetSelfLink() {
		// Got ourselves, no-op
		return
	}
	ll := pt.ll.WithFields(log.Fields{
		"k8s_namespace": wgPeer.Namespace,
		"k8s_kind":      wgPeer.Kind,
		"k8s_name":      wgPeer.Name,
	})
	ll.Info("WireGuardPeer updated, applying changes")
	err := pt.applyUpdate(wgPeer)
	if err != nil {
		// TODO - requeue when appropriate
		ll.Errorf("WireGuardPeer failed to apply updates: %v", err)
	}
	ll.Info("WireGuardPeer updates applied successfully")
}

func (pt *peerTracker) OnDelete(obj interface{}) {
	wgPeer, ok := obj.(*wgk8s.WireGuardPeer)
	if !ok {
		pt.ll.WithField("unexpected_type", fmt.Sprintf("%T", obj)).
			Warn("unexpected type")
	}
	if wgPeer.GetSelfLink() == pt.localPeer.GetSelfLink() {
		// Got ourselves, no-op
		return
	}
	ll := pt.ll.WithFields(log.Fields{
		"k8s_namespace": wgPeer.Namespace,
		"k8s_kind":      wgPeer.Kind,
		"k8s_name":      wgPeer.Name,
	})
	ll.Info("WireGuardPeer deleted, removing peer")
	err := pt.deletePeer(wgPeer)
	if err != nil {
		// TODO - requeue when appropriate
		ll.Errorf("WireGuardPeer failed to apply delete: %v", err)
	}
	ll.Info("WireGuardPeer successfully deleted")
}

func (pt *peerTracker) k8sToWgctrl(wgPeer *wgk8s.WireGuardPeer) (config wgtypes.PeerConfig, err error) {
	config.PublicKey, err = wgtypes.ParseKey(wgPeer.Spec.PublicKey)
	if err != nil {
		err = fmt.Errorf("failed to parse public key: %w", err)
		return
	}

	config.Endpoint, err = net.ResolveUDPAddr("udp", wgPeer.Spec.Endpoint)
	if err != nil {
		err = fmt.Errorf("failed to resolve endpoint %q: %w", wgPeer.Spec.Endpoint, err)
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

func wireGuardPeerIsEqual(old, new *wgk8s.WireGuardPeer) bool {
	return reflect.DeepEqual(old.Spec, new.Spec)
}
