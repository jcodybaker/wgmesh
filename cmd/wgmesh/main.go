package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jcodybaker/wgmesh/pkg/agent"
	"github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/clientset/versioned"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}

	var hostname string
	hostname, _ = os.Hostname()
	endpointName := flag.String("endpoint-name", hostname, "name of the endpoint (default hostname)")
	bindAddress := flag.String("bind-address", "0.0.0.0:0", "address:port to bind the wireguard service")
	flag.Parse()
	validateNodeName(endpointName)
	bindAddr, port := validateBindAddress(bindAddress)

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	kubeClientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	wgmeshClientset, err := versioned.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	agent.Run(*endpointName, bindAddr, port, kubeClientset, wgmeshClientset)
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

func validateNodeName(endpointName *string) {
	if endpointName == nil {
		fmt.Fprintln(os.Stderr, "--endpoint-name: was nil")
		os.Exit(1)
	}
	errs := validation.IsDNS1123Subdomain(*endpointName)
	if len(errs) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "--endpoint-name: %s", strings.Join(errs, " "))
	os.Exit(1)
}

func validateBindAddress(bindAddress *string) (addr string, port uint16) {
	if bindAddress == nil {
		fmt.Fprintln(os.Stderr, "--bind-address: was nil")
		os.Exit(1)
	}
	addr = *bindAddress
	if strings.Contains(*bindAddress, ":") {
		var err error
		var sPort string
		addr, sPort, err = net.SplitHostPort(*bindAddress)
		if err != nil {
			fmt.Fprintf(os.Stderr, "--bind-address: invalid %q %v", *bindAddress, err)
			os.Exit(1)
		}
		var port64 uint64
		port64, err = strconv.ParseUint(sPort, 10, 16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "--bind-address: invalid port %q %v", sPort, err)
			os.Exit(1)
		}
		port = uint16(port64)
	}
	if net.ParseIP(*bindAddress) == nil {
		fmt.Fprintf(os.Stderr, "--bind-address: invalid %q", *bindAddress)
		os.Exit(1)
	}
	return
}
