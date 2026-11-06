# Upgrading from upstream

This fork diverges from [jodevsa/wireguard-operator](https://github.com/jodevsa/wireguard-operator)
at `v2.11.0`. It keeps the version (`v1alpha1`) and both kinds, but serves them under its own
group, `vpn.tunnel-operator.io` (upstream's is `vpn.wireguard-operator.io`), with a changed schema.
Upstream served clients outside the cluster; this fork serves pods inside it. You migrate side by
side, not in place.

## Migrating side by side

1. **Install this fork alongside upstream.** The two do not collide: the CRD groups differ, every
   ClusterRole, ClusterRoleBinding and admission policy this fork installs carries the `tunnel-`
   prefix, and its CRDs are named by the new group, and the leader-election leases differ. Follow
   [installation.md](installation.md); it applies to the `tunnel-system` namespace by default.
2. **Create the new `Wireguard`** under `vpn.tunnel-operator.io/v1alpha1`. Never give it the same
   name in the same namespace as an upstream one: both operators derive `<name>-dep`, `<name>-svc`
   and the Secret `<name>` from it and set a controller `ownerReference` on them, so they would
   fight over the same objects. Create it in the operator's own namespace, where it can be the
   default gateway, and pick a new name if upstream's server already lives there. The fields are in
   [crd-wireguard.md](crd-wireguard.md#spec) and [`examples/01-server.yaml`](../examples/01-server.yaml).
3. **Do not carry over keys or peers.** Upstream's peers are clients outside the cluster, and this
   fork has no external endpoint. Pods attach through the sidecar or the label and make their own
   keys, so there is nothing to translate.
4. **Remove upstream**, the way you installed it: `helm uninstall`, or `kubectl delete -f` its
   `release.yaml`. If its CRDs survive, delete them:

   ```sh
   kubectl delete crd wireguards.vpn.wireguard-operator.io wireguardpeers.vpn.wireguard-operator.io
   ```

   > **Deleting upstream's CRDs deletes upstream's objects.** Every remaining upstream `Wireguard`
   > and `WireguardPeer` goes with them. Do it only once nothing depends on them.

Both CRDs share their kind, plural and singular, so `kubectl get wireguard` silently picks one
group. Name the group in every command: `wireguards.vpn.tunnel-operator.io` or
`wireguards.vpn.wireguard-operator.io`, and `wireguardpeers.vpn.tunnel-operator.io` or
`wireguardpeers.vpn.wireguard-operator.io`.

The tables below are the reference for translating an upstream server spec into this fork's.

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

`Wireguard` now requires `spec.localCIDRs` and `spec.gluetun`, so when you translate a server
spec, a `spec: {}` server must gain both. See [crd-wireguard.md](crd-wireguard.md#spec) and
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

The Go module is `github.com/jacaudi/tunnel-operator`, and the images are
`ghcr.io/jacaudi/tunnel-operator/manager` and `ghcr.io/jacaudi/tunnel-operator/agent`.
