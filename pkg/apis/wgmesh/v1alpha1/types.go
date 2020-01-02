/*
MIT License

Copyright (c) 2019 John Cody Baker

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WireGuardPeerSpec describes the info necessary to establish connectivity
// with the peer.
type WireGuardPeerSpec struct {
	Endpoint     string   `json:"endpoint"`
	PublicKey    string   `json:"publicKey"`
	PresharedKey string   `json:"presharedKey"`
	IPs          []string `json:"ips,omitempty"`
	Routes       []string `json:"routes,omitempty"`
	// KeepAliveSeconds is the frequency which keep-alive packets will be sent to
	// maintain connectivity between peers.
	// NOTE: For each set of peers we use the lower of the two peers.
	KeepAliveSeconds int `json:"keepalive,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=wireguardpeers

// WireGuardPeer describes a WG Mesh node which can be networked with.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type WireGuardPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec WireGuardPeerSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=wireguardpeers

// WireGuardPeerList contains a list of WireGuardPeer(s).
type WireGuardPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WireGuardPeer `json:"items"`
}

// IPPoolSpec describes the IP pool
type IPPoolSpec struct {
	IPv4Ranges []IPv4Range `json:"ipv4Ranges"`
}

// IPv4Range defines a range of IP address available for allocation.
type IPv4Range struct {
	CIDR string `json:"cidr"`
	// Start defines the first address in the pool available for allocation. If omitted, the start
	// address is assumed to be start of the subnet. Unless the mask is >= a /31, the 0 address
	// is reserved as the network address.
	Start string `json:"start,omitempty"`
	// Start defines the last address in the pool available for allocation. If omitted, the start
	// address is assumed to be end of the subnet. Unless the mask is >= a /31, the top address
	// (all ones) is reserved as the broadcast address.
	End string `json:"end,omitempty"`
	// Reserved lists addresses which should not be assigned.
	Reserved []string `json:"reserved,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=ippools

// IPPool is the Schema for the WireGuardPeers API
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type IPPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec IPPoolSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=ippools

// IPPoolList contains a list of IPPools.
type IPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IPPool `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=ipv4claims

// IPv4Claim is the Schema for the WireGuardPeers API
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type IPv4Claim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec IPv4ClaimSpec `json:"spec,omitempty"`
}

// IPv4ClaimSpec describes the IP claim.
type IPv4ClaimSpec struct {
	IP string `json:"ip"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=ipv4claims

// IPv4ClaimList contains a list of IPv4Claims.
type IPv4ClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IPv4Claim `json:"items"`
}
