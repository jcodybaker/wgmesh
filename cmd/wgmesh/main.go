package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jcodybaker/wgmesh/pkg/agent"
	"github.com/jcodybaker/wgmesh/pkg/apis/wgmesh/generated/clientset/versioned"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Showmax/go-fqdn"

	"github.com/mattn/go-isatty"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)
}

func main() {
	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}

	var hostname string
	hostname, _ = os.Hostname()
	name := flag.String("name", hostname, "name of the endpoint (default hostname)")
	endpointAddr := flag.String("endpoint-addr", fqdn.Get(), "endpoint address used by peers (default fqdn)")
	port := flag.Uint("port", 0, "port to bind the wireguard service. 0 = random available port")
	keepaliveSeconds := flag.Int("keepalive-seconds", 0, "send keepalive packets every x seconds")
	iface := flag.String("interface", "wg0", "network interface name for the wiregard interface")
	debug := flag.Bool("debug", false, "debug logging")
	kubeNamespace := flag.String("kube-namespace", "", "kubernetes namespace, default current")

	flag.Parse()

	if debug != nil && *debug {
		log.SetLevel(log.DebugLevel)
	}
	if isatty.IsTerminal(os.Stdout.Fd()) {
		log.SetFormatter(&log.TextFormatter{})
	}

	ctx := signalContext(context.Background())
	ll := log.WithContext(ctx)

	validateNodeName(name)
	validateEndpointAddr(*endpointAddr)
	validatePort(*port)

	var keepalive time.Duration
	if keepaliveSeconds != nil {
		keepalive = time.Duration(*keepaliveSeconds) * time.Second
	}

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

	err = agent.Run(ctx, ll, *iface, *name, *endpointAddr, uint16(*port), keepalive, kubeClientset, wgmeshClientset, *kubeNamespace)
	if err != nil {
		panic(err)
	}
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
	fmt.Fprintf(os.Stderr, "--endpoint-name: %s\n", strings.Join(errs, " "))
	os.Exit(1)
}

func validatePort(port uint) {
	if port >= 0xFFFF {
		fmt.Fprintln(os.Stderr, "--port: port must be between 0 and 65535")
		os.Exit(1)
	}
}

func validateEndpointAddr(endpointAddr string) {
	_, _, err := net.SplitHostPort(endpointAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "--endpoint-addr: invalid: %v", err)
		os.Exit(1)
	}
}

func signalContext(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1) // exit hard for the impatient
	}()

	return ctx
}
