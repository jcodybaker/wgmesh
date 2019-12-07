package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jcodybaker/wgmesh/pkg/agent"
	"github.com/jcodybaker/wgmesh/pkg/interfaces"

	"github.com/Showmax/go-fqdn"
	"github.com/spf13/cobra"

	k8sLabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/clientcmd"
)

var name, endpointAddr, registryNamespace, kubeNode, kubeconfig string
var peerSelector, labels, registryKubeconfig, driver string
var ips, offerRoutes []string
var port uint16
var keepAliveSeconds uint
var wgIfaceOptions interfaces.WireGuardInterfaceOptions

var agentCmd = &cobra.Command{
	Run:   runAgent,
	Use:   "agent",
	Short: "Run wgmesh agent",
}

func init() {

	agentCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig file for the local cluster")
	agentCmd.Flags().StringVar(&registryKubeconfig, "registry-kubeconfig", "", "path to kubeconfig file for registry")

	hostname, _ := os.Hostname()
	agentCmd.Flags().StringVar(&name, "name", hostname, "name of the endpoint (default hostname)")

	agentCmd.Flags().StringVar(&endpointAddr, "endpoint-addr", fqdn.Get(), "endpoint address used by peers (default fqdn)")
	agentCmd.Flags().UintVar(&keepAliveSeconds, "keepalive-seconds", 0, "send keepalive packets every x seconds")

	agentCmd.Flags().Uint16Var(&port, "port", 0, "port to bind the wireguard service. 0 = random available port")
	agentCmd.Flags().StringVar(&wgIfaceOptions.InterfaceName, "interface", interfaces.DefaultWireGuardInterfaceName, "network interface name for the wiregard interface. Use + suffix to auto-select the next available id (ex. wg+ for wg0,wg1...")
	agentCmd.Flags().StringVar(&driver, "driver", "auto",
		fmt.Sprintf("wireguard driver to use. Valid: %s", strings.Join(interfaces.GetValidWireGuardDrivers(), ",")))
	agentCmd.Flags().BoolVar(&wgIfaceOptions.ReuseExisting, "reuse-existing-interface", false, "If --interface already exists, and is a compatible WireGuard device, reuse it.")
	agentCmd.Flags().StringVar(&wgIfaceOptions.BoringTunPath, "boringtun-path", "", "path to boringtun userspace driver")
	agentCmd.Flags().StringVar(&wgIfaceOptions.BoringTunExtraArgs, "boringtun-extra-args", "", "extra arguments to pass to boringtun")
	agentCmd.Flags().StringVar(&wgIfaceOptions.WireGuardGoPath, "wireguard-go-path", "", "path to wireguard-go userspace driver")
	agentCmd.Flags().StringVar(&wgIfaceOptions.WireGuardGoExtraArgs, "wireguard-go-extra-args", "", "extra arguments to pass to the wireguard-go userspace driver")

	// TODO - figure out how to default this to the namespace specified in the kubeconfig file.
	agentCmd.Flags().StringVar(&registryNamespace, "registry-namespace", "", "kubernetes namespace")
	agentCmd.Flags().StringVar(&kubeNode, "kube-node", "", "specify the Kubernetes node name (optional)")

	agentCmd.Flags().StringSliceVar(&ips, "ips", nil, "ip addresses which should be assigned to the local wireguard interface")
	agentCmd.Flags().StringSliceVar(&offerRoutes, "offer-routes", nil, "routes which this node will offer to peers")

	agentCmd.Flags().StringVar(&peerSelector, "peer-selector", "", "select a subset of peers based on labels")
	agentCmd.Flags().StringVar(&labels, "labels", "", "apply kubernetes labels the local WireGuardPeer")

	rootCmd.AddCommand(agentCmd)
}

func runAgent(cmd *cobra.Command, args []string) {
	validateNodeName(name)
	validateEndpointAddr(endpointAddr)

	opts := []agent.OptionFunc{
		agent.WithLogger(ll),
		agent.WithIPs(ips),
		agent.WithOfferRoutes(offerRoutes),
		agent.WithRegistryNamespace(registryNamespace),
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	config := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})
	if config != nil {
		opts = append(opts, agent.WithLocalKubeClientConfig(config))
	}

	if registryKubeconfig != "" {
		rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: registryKubeconfig}
		config := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})
		if config != nil {
			opts = append(opts, agent.WithRegistryKubeClientConfig(config))
		}
	}

	if keepAliveSeconds > 0 {
		keepalive := time.Duration(keepAliveSeconds) * time.Second
		opts = append(opts, agent.WithKeepAliveDuration(keepalive))
	}

	if kubeNode != "" {
		// TODO - bail if there's not local kubeconfig
		validateKubeNode(kubeNode)
		opts = append(opts, agent.WithKubeNode(kubeNode))
	}

	if peerSelector != "" {
		ps, err := k8sLabels.Parse(peerSelector)
		if err != nil {
			fmt.Fprintf(os.Stderr, "--peer-selector: invalid %w", err)
			os.Exit(1)
		}
		opts = append(opts, agent.WithPeerSelector(ps))
	}

	if labels != "" {
		labelsSet, err := k8sLabels.ConvertSelectorToLabelsMap(labels)
		if err != nil {
			fmt.Fprintf(os.Stderr, "--labels: invalid %w", err)
			os.Exit(1)
		}
		opts = append(opts, agent.WithLabels(labelsSet))
	}

	if endpointAddr != "" {
		opts = append(opts, agent.WithEndpointAddr(endpointAddr))
	}

	var err error
	wgIfaceOptions.Driver, err = interfaces.WireGuardDriverFromString(driver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "--driver: %w", err)
		os.Exit(1)
	}
	if err = interfaces.IsWireGuardInterfaceNameValid(wgIfaceOptions.InterfaceName); err != nil {
		fmt.Fprintf(os.Stderr, "--interface: %w", err)
		os.Exit(1)
	}
	wgIfaceOptions.Port = int(port)
	opts = append(opts, agent.WithWireGuardInterfaceOptions(&wgIfaceOptions))

	a, err := agent.NewAgent(name, opts...)
	if err != nil {
		ll.Fatalf("Failed to initialize agent: %w", err)
	}
	defer a.Close()
	err = a.Run(ctx)
	if ctx.Err() == nil && err != nil {
		ll.Fatalf("Failed to run agent: %w", err)
	}
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

func validateKubeNode(kubeNode string) {
	errs := validation.IsDNS1123Subdomain(kubeNode)
	if len(errs) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "--kube-node: %s\n", strings.Join(errs, " "))
	os.Exit(1)
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
