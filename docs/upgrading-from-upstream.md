# Upgrading from upstream

This fork diverges from [jodevsa/wireguard-operator](https://github.com/jodevsa/wireguard-operator)
at `v2.11.0`. It keeps the API group (`vpn.wireguard-operator.io`), the version (`v1alpha1`) and
both kinds, and changes the schema in place. Upstream served clients outside the cluster; this
fork serves pods inside it, so most of what was removed has no replacement.

> **One operator per cluster.** Both operators install the same two CRDs, so they cannot run side
> by side. Remove upstream before you install this fork.

## Removed from `Wireguard`

| Field | What to do instead |
|---|---|
| `serviceType`, `port`, `serviceAnnotations` | Nothing. The Service is always `ClusterIP` on UDP `51820`. |
| `address`, `externalAddress` | Nothing. There is no external endpoint; clients use the Service's cluster IP. |
| `tunnel` (wstunnel, `dualMode`) | Nothing. wstunnel is gone. |
| `peerCIDRv6`, `ipv6Only` | Nothing. The tunnel is IPv4 only. |
| `dns`, `dnsSearchDomain` | Nothing. Clients keep cluster DNS. |
| `mtu` | Nothing. The server's `wg0` MTU is fixed at 1420. |
| `persistentKeepalive` | Set `PersistentKeepalive` in your own client configuration. |
| `enableIpForwardOnPodInit` | Nothing. Forwarding is always enabled by the `sysctl` init container. |
| `useWgUserspaceImplementation` | Nothing. The agent falls back to wireguard-go automatically when the kernel module is missing. |
| `metric` | Nothing. The metrics exporter is gone. |
| `status.address`, `status.dns`, `status.port`, `status.tunnel`, `status.uniqueIdentifier`, `status.resources` | Read the Service and Secret directly — see [crd-wireguard.md](crd-wireguard.md#owned-objects). |

## Added to `Wireguard`

`Wireguard` now requires `spec.localCIDRs` and `spec.gluetun`, so a `spec: {}` server must gain
both before upgrading. See [crd-wireguard.md](crd-wireguard.md#spec) and
[`examples/01-server.yaml`](../examples/01-server.yaml).

## Removed from `WireguardPeer`

| Field | What to do instead |
|---|---|
| `privateKeyRef` | Generate the key pair on the client and set `publicKey`. The operator no longer mints peer keys. |
| `addressV6` | Nothing. The tunnel is IPv4 only. |
| `allowedIPs` | Nothing. The server routes exactly the peer's `/32` to it. |
| `dns`, `dnsSearchDomain` | Nothing. |
| `disabled` | Delete the `WireguardPeer`. |
| `egressNetworkPolicies`, `downloadSpeed`, `uploadSpeed` | Nothing. Per-peer policy and rate limits are gone. |

## Removed behaviour

- **Peer configuration Secrets.** Upstream rendered `<wireguard>-peer-configs` and a
  `<peer>-peer` key Secret per peer. This fork writes neither; build the client configuration
  yourself from [these values](client-sidecar.md#without-the-sidecar), or run the client sidecar,
  which needs none.
- **Server iptables and NAT.** Upstream masqueraded peer traffic out of the server pod's `eth0`.
  This fork masquerades peer traffic into gluetun's tunnel, never out of `eth0` — see
  [gluetun-egress.md](gluetun-egress.md).
- **Metrics.** The `<wireguard>-metrics-svc` Service and the agent's Prometheus exporter are gone.
- **The `<wireguard>-config` ConfigMap.** It carried no data and is no longer rendered.
- **The OLM bundle and the webhook server.** The bundle was never published, and the webhook
  server had no handler registered.

## What still carries over

- **Object names.** The server key Secret `<wireguard>`, its keys `privateKey` and `publicKey`,
  the Service `<wireguard>-svc` and the Deployment `<wireguard>-dep` keep upstream's names.
- **Peer public keys and addresses.** `spec.publicKey` keeps its meaning, so a peer upstream keyed
  for you keeps its key, as long as you still hold the private half from its rendered
  configuration. The peer address is no longer a spec field: the operator allocates each peer a
  fresh `status.address`, so a peer's address can change.

## Moving an install

This fork has not tested an in-place upgrade over a running upstream install. Treat it as a new
install:

1. Save what you need: each `Wireguard` and `WireguardPeer` manifest and, for each client you keep,
   its private key from the `<wireguard>-peer-configs` Secret.
2. Uninstall upstream the way you installed it (`helm uninstall`, or `kubectl delete -f` its
   `release.yaml`). If its CRDs survive, delete them, which also deletes every remaining
   `Wireguard` and `WireguardPeer`:

   ```sh
   kubectl delete crd wireguards.vpn.wireguard-operator.io wireguardpeers.vpn.wireguard-operator.io
   ```

3. Install this fork — see [installation.md](installation.md).
4. Recreate each `Wireguard` with only the fields in [crd-wireguard.md](crd-wireguard.md#spec), and
   each `WireguardPeer` with `wireguardRef` and `publicKey` only. The operator allocates each peer
   an address afresh, so read it from `status.address` and update the client's `[Interface] Address`.
5. The server gets a new key pair. Update every client's `[Peer] PublicKey`, and point its
   `Endpoint` at the new Service's cluster IP.

The Go module is now `github.com/jacaudi/wireguard-operator`, and the images are
`ghcr.io/jacaudi/wireguard-operator/manager` and `ghcr.io/jacaudi/wireguard-operator/agent`.
