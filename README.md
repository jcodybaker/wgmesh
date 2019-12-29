# WG Mesh

WG Mesh facilitates building a secure overlay network using the WireGuard protocol and a Kubernetes API.

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
$ ./wgmesh agent --help
Run wgmesh agent

Usage:
   agent [flags]

Flags:
      --endpoint-addr string         endpoint address used by peers (default fqdn) (default "ubuntu-bionic")
  -h, --help                         help for agent
      --interface string             network interface name for the wiregard interface (default "wg0")
      --ips strings                  ip addresses which should be assigned to the local wireguard interface
      --keepalive-seconds uint       send keepalive packets every x seconds
      --kube-node string             specify the Kubernetes node name (optional)
      --kubeconfig string            path to kubeconfig file for the local cluster
      --labels string                apply kubernetes labels the local WireGuardPeer
      --name string                  name of the endpoint (default hostname) (default "ubuntu-bionic")
      --offer-routes strings         routes which this node will offer to peers
      --peer-selector string         select a subset of peers based on labels
      --port uint16                  port to bind the wireguard service. 0 = random available port
      --registry-kubeconfig string   path to kubeconfig file for registry
      --registry-namespace string    kubernetes namespace

Global Flags:
      --debug   debug logging
```

## Todo

## License

WG Mesh is licensed under the [MIT License](LICENSE).