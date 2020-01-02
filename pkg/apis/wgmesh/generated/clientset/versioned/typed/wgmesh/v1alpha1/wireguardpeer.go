/*
MIT License

Copyright (c) 2020 John Cody Baker

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

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"time"

	scheme "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/clientset/versioned/scheme"
	v1alpha1 "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// WireGuardPeersGetter has a method to return a WireGuardPeerInterface.
// A group's client should implement this interface.
type WireGuardPeersGetter interface {
	WireGuardPeers(namespace string) WireGuardPeerInterface
}

// WireGuardPeerInterface has methods to work with WireGuardPeer resources.
type WireGuardPeerInterface interface {
	Create(*v1alpha1.WireGuardPeer) (*v1alpha1.WireGuardPeer, error)
	Update(*v1alpha1.WireGuardPeer) (*v1alpha1.WireGuardPeer, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.WireGuardPeer, error)
	List(opts v1.ListOptions) (*v1alpha1.WireGuardPeerList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.WireGuardPeer, err error)
	WireGuardPeerExpansion
}

// wireGuardPeers implements WireGuardPeerInterface
type wireGuardPeers struct {
	client rest.Interface
	ns     string
}

// newWireGuardPeers returns a WireGuardPeers
func newWireGuardPeers(c *WgmeshV1alpha1Client, namespace string) *wireGuardPeers {
	return &wireGuardPeers{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the wireGuardPeer, and returns the corresponding wireGuardPeer object, and an error if there is any.
func (c *wireGuardPeers) Get(name string, options v1.GetOptions) (result *v1alpha1.WireGuardPeer, err error) {
	result = &v1alpha1.WireGuardPeer{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("wireguardpeers").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of WireGuardPeers that match those selectors.
func (c *wireGuardPeers) List(opts v1.ListOptions) (result *v1alpha1.WireGuardPeerList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.WireGuardPeerList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("wireguardpeers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested wireGuardPeers.
func (c *wireGuardPeers) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("wireguardpeers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a wireGuardPeer and creates it.  Returns the server's representation of the wireGuardPeer, and an error, if there is any.
func (c *wireGuardPeers) Create(wireGuardPeer *v1alpha1.WireGuardPeer) (result *v1alpha1.WireGuardPeer, err error) {
	result = &v1alpha1.WireGuardPeer{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("wireguardpeers").
		Body(wireGuardPeer).
		Do().
		Into(result)
	return
}

// Update takes the representation of a wireGuardPeer and updates it. Returns the server's representation of the wireGuardPeer, and an error, if there is any.
func (c *wireGuardPeers) Update(wireGuardPeer *v1alpha1.WireGuardPeer) (result *v1alpha1.WireGuardPeer, err error) {
	result = &v1alpha1.WireGuardPeer{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("wireguardpeers").
		Name(wireGuardPeer.Name).
		Body(wireGuardPeer).
		Do().
		Into(result)
	return
}

// Delete takes name of the wireGuardPeer and deletes it. Returns an error if one occurs.
func (c *wireGuardPeers) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("wireguardpeers").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *wireGuardPeers) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("wireguardpeers").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched wireGuardPeer.
func (c *wireGuardPeers) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.WireGuardPeer, err error) {
	result = &v1alpha1.WireGuardPeer{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("wireguardpeers").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
