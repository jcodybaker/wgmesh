# WG Mesh

WG Mesh facilitates building a secure overlay network using the WireGuard protocol and a Kubernetes API.

## Why??
WG Mesh is built for a variety of use-cases. WG Mesh can be used to provide virtual network connectivity between the pod/service networks of one or more clusters and non-local (other cloud, vpc, or on-prem) networks.  For example, WG Mesh could provide secure routing between an on-prem network and an cloud hosted Kubernetes cluster.  

## Status
This project is under active development as of Dec 31, 2019. It should be considered as an early alpha. Basic functionality may work, but lots of useful features and testing are missing.

## Using

```
$ ./wgmesh 
Usage:
   [command]

Available Commands:
  agent       Run wgmesh agent
  help        Help about any command

Flags:
      --debug   debug logging
  -h, --help    help for this command

Use " [command] --help" for more information about a command.
```

### Agent
```
Run wgmesh agent

Usage:
   agent [flags]

Flags:
      --boringtun-extra-args string      extra arguments to pass to boringtun
      --boringtun-path string            path to boringtun userspace driver
      --driver string                    wireguard driver to use. Valid: auto,existing,boringtun,wireguard-go,kernel (default "auto")
      --endpoint-addr string             endpoint address used by peers (default fqdn) (default "ubuntu-bionic")
  -h, --help                             help for agent
      --interface string                 network interface name for the wiregard interface. Use + suffix to auto-select the next available id (ex. wg+ for wg0,wg1... (default "wg+")
      --ips strings                      ip addresses which should be assigned to the local wireguard interface
      --keepalive-seconds uint           send keepalive packets every x seconds
      --kube-node string                 specify the Kubernetes node name (optional)
      --kubeconfig string                path to kubeconfig file for the local cluster
      --labels string                    apply kubernetes labels the local WireGuardPeer
      --name string                      name of the endpoint (default hostname) (default "ubuntu-bionic")
      --offer-routes strings             routes which this node will offer to peers
      --peer-selector string             select a subset of peers based on labels
      --port uint16                      port to bind the wireguard service. 0 = random available port
      --registry-kubeconfig string       path to kubeconfig file for registry
      --registry-namespace string        kubernetes namespace
      --reuse-existing-interface         If --interface already exists, and is a compatible WireGuard device, reuse it.
      --wireguard-go-extra-args string   extra arguments to pass to the wireguard-go userspace driver
      --wireguard-go-path string         path to wireguard-go userspace driver

Global Flags:
      --debug   debug logging

```

## Todo
* Finish MacOS/BSD support.  Windows support???
* IPAM
* Populate routes via Kubernetes object references. Ex. node.PodCIDR
* More testing
* Template out Kubernetes deployment/ds and offer Kustomize or helm templates.

## License

Copyright 2019 - J Cody Baker - WG Mesh is licensed under the [MIT License](LICENSE).

## Legal
WireGuard is a registered trademark of Jason A. Donenfeld. WG Mesh is not sponsored or endorsed by Jason A. Donenfeld.