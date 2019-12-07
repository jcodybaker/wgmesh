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

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// IPClaimLister helps list IPClaims.
type IPClaimLister interface {
	// List lists all IPClaims in the indexer.
	List(selector labels.Selector) (ret []*v1alpha1.IPClaim, err error)
	// IPClaims returns an object that can list and get IPClaims.
	IPClaims(namespace string) IPClaimNamespaceLister
	IPClaimListerExpansion
}

// iPClaimLister implements the IPClaimLister interface.
type iPClaimLister struct {
	indexer cache.Indexer
}

// NewIPClaimLister returns a new IPClaimLister.
func NewIPClaimLister(indexer cache.Indexer) IPClaimLister {
	return &iPClaimLister{indexer: indexer}
}

// List lists all IPClaims in the indexer.
func (s *iPClaimLister) List(selector labels.Selector) (ret []*v1alpha1.IPClaim, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.IPClaim))
	})
	return ret, err
}

// IPClaims returns an object that can list and get IPClaims.
func (s *iPClaimLister) IPClaims(namespace string) IPClaimNamespaceLister {
	return iPClaimNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// IPClaimNamespaceLister helps list and get IPClaims.
type IPClaimNamespaceLister interface {
	// List lists all IPClaims in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1alpha1.IPClaim, err error)
	// Get retrieves the IPClaim from the indexer for a given namespace and name.
	Get(name string) (*v1alpha1.IPClaim, error)
	IPClaimNamespaceListerExpansion
}

// iPClaimNamespaceLister implements the IPClaimNamespaceLister
// interface.
type iPClaimNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all IPClaims in the indexer for a given namespace.
func (s iPClaimNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.IPClaim, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.IPClaim))
	})
	return ret, err
}

// Get retrieves the IPClaim from the indexer for a given namespace and name.
func (s iPClaimNamespaceLister) Get(name string) (*v1alpha1.IPClaim, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("ipclaim"), name)
	}
	return obj.(*v1alpha1.IPClaim), nil
}
