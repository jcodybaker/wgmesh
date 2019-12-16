package main

import (
	"context"
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
	"github.com/spf13/cobra"
)

var name, endpointAddr, iface, registryNamespace, kubeNode, kubeconfig string
var ips, offerRoutes []string
var port uint16
var keepAliveSeconds uint
var debug bool

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)
}

func main() {
	var hostname string
	hostname, _ = os.Hostname()

	var rootCmd = &cobra.Command{}
	if home := homeDir(); home != "" {
		rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	}
	rootCmd.Flags().StringVar(&name, "name", hostname, "name of the endpoint (default hostname)")
	rootCmd.Flags().StringVar(&endpointAddr, "endpoint-addr", fqdn.Get(), "endpoint address used by peers (default fqdn)")
	rootCmd.Flags().Uint16Var(&port, "port", 0, "port to bind the wireguard service. 0 = random available port")
	rootCmd.Flags().UintVar(&keepAliveSeconds, "keepalive-seconds", 0, "send keepalive packets every x seconds")
	rootCmd.Flags().StringVar(&iface, "interface", "wg0", "network interface name for the wiregard interface")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "debug logging")
	// TODO - figure out how to default this to the namespace specified in the kubeconfig file.
	rootCmd.Flags().StringVar(&registryNamespace, "kube-namespace", "", "kubernetes namespace")
	rootCmd.Flags().StringVar(&kubeNode, "kubeNode", "", "specify the Kubernetes node name (optional)")
	rootCmd.Flags().StringSliceVar(&ips, "ips", nil, "ip addresses which should be assigned to the local wireguard interface")
	rootCmd.Flags().StringSliceVar(&offerRoutes, "offer-routes", nil, "routes which this node will offer to peers")
	rootCmd.Run = runAgent
	rootCmd.Execute()
}

func runAgent(cmd *cobra.Command, args []string) {

	if debug {
		log.SetLevel(log.DebugLevel)
	}
	if isatty.IsTerminal(os.Stdout.Fd()) {
		log.SetFormatter(&log.TextFormatter{})
	}

	ctx := signalContext(context.Background())
	ll := log.WithContext(ctx)

	validateNodeName(name)
	validateEndpointAddr(endpointAddr)

	var keepalive time.Duration
	if keepAliveSeconds > 0 {
		keepalive = time.Duration(keepAliveSeconds) * time.Second
	}


	// if a.labelSelector != "" {
	// 	labelSelector, err = labels.Parse(a.labelSelector)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to parse label selector: %w", labelSelector)
	// 	}
	// }


	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}

	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		glog.Fatalf("Couldn't get Kubernetes default config: %s", err)
	}


	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}



	err = agent.Run(ctx, ll, iface, name, endpointAddr, port, keepalive, kubeClientset, wgmeshClientset, registryNamespace)
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

func validateNodeName(endpointName string) {
	if endpointName == "" {
		fmt.Fprintln(os.Stderr, "--endpoint-name: was empty")
		os.Exit(1)
	}
	errs := validation.IsDNS1123Subdomain(endpointName)
	if len(errs) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "--endpoint-name: %s\n", strings.Join(errs, " "))
	os.Exit(1)
}

func validateEndpointAddr(endpointAddr string) {
	_, _, err := net.SplitHostPort(endpointAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "--endpoint-addr: invalid: %v", err)
		os.Exit(1)
	}
}

func validateIPs(ips []string) {
	for _, ip := range ips {
		if strings.Index(ip, "/") == -1 {
			fmt.Fprintf(os.Stderr, "--ips: %q missing prefix length", ip)
			os.Exit(1)
		}
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "--ips: invalid ip %q: %v", ip, err)
			os.Exit(1)
		}
	}
}

func validateOfferRoutes(offerRoutes []string) {
	for _, route := range offerRoutes {
		_, _, err := net.ParseCIDR(route)
		if err != nil {
			fmt.Fprintf(os.Stderr, "--offer-routes: invalid CIDR %q: %v", route, err)
			os.Exit(1)
		}
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
