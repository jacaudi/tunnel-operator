# Egress through gluetun

The server pod runs a [gluetun](https://github.com/qdm12/gluetun) container beside the agent. The
two share one network namespace, so peer traffic arriving on `wg0` is forwarded into gluetun's
`tun0` and on to your VPN provider. Peer traffic never leaves the pod any other way: with the tunnel
down it is dropped, not sent out of `eth0`.

The client end of the tunnel is the [client sidecar](client-sidecar.md).

See [`examples/01-server.yaml`](../examples/01-server.yaml) for a `Wireguard` with its provider
Secret.

## Configuration

`spec.gluetun` is passed through to the `gluetun` container. There is no typed provider schema:
gluetun's own [environment variables](https://github.com/qdm12/gluetun-wiki) are the contract, so
every provider gluetun supports works.

- **`gluetun.envFrom`** — reference a Secret that holds the provider credentials, for example
  `VPN_SERVICE_PROVIDER` and `WIREGUARD_PRIVATE_KEY`. Credentials are never written inline in the
  `Wireguard`, and they never reach the operator's own `state.json` Secret: the operator drops
  `spec.gluetun` from it.
- **`gluetun.env`** — any other gluetun variable, rendered after the operator's own.
- **`gluetun.resources`** — requests and limits for the container.

The operator owns the variables the routing depends on. It renders `VPN_TYPE`, `VPN_INTERFACE`, the
firewall settings, `HEALTH_SERVER_ADDRESS` and `WIREGUARD_MTU` itself (the full table is in
[crd-wireguard.md](crd-wireguard.md#reserved-gluetun-variables)). If `env`, or the keys of a Secret
that `envFrom` references, set any of them, the `Wireguard` is `Degraded` with reason
`ReservedGluetunEnv` and no Deployment is rendered. A referenced ConfigMap is not checked, because
the operator's value takes precedence.

## `localCIDRs`

`spec.localCIDRs` is required: list the cluster's pod, Service and node CIDRs, and
`169.254.20.10/32` if you use NodeLocal DNSCache. Cluster traffic stays in the cluster:

- Clients route these ranges over the CNI, never through the tunnel.
- The server hands them to gluetun as `FIREWALL_OUTBOUND_SUBNETS`, so gluetun lets the pod answer
  cluster addresses over `eth0`.

The operator checks that each entry is a canonical IPv4 CIDR, that the Service's ClusterIP falls
inside one (clients route everything outside `localCIDRs` into the tunnel, including the gateway's
own Service), and that none overlaps `peerCIDR`. An entry that contains `192.0.2.1` sets `Degraded`
with reason `ProbeAddressInLocalCIDRs` and no Deployment is rendered, because the agent's readiness
check routes that address through the tunnel (see
[Readiness follows the tunnel](#readiness-follows-the-tunnel)). The operator does **not** check that
`localCIDRs` avoids the provider's tunnel range. An entry that overlaps it keeps that traffic off the
tunnel, so keep your `localCIDRs` outside the range your provider uses; gluetun's firewall
documentation says the same of `FIREWALL_OUTBOUND_SUBNETS`.

## Fail closed by routing

The safety property comes from policy routing, not from firewall rules. The agent installs two
`ip rule`s and two one-route tables. This is the lookup order for a packet that arrives on `wg0`
bound for the internet:

```text
pref  90   to <peerCIDR>        lookup 51821   # agent: table 51821 = <peerCIDR> dev wg0 (the return path)
pref  98-101                                   # gluetun: its own rules, ending in the tunnel table
pref 102   iif wg0              lookup 51822   # agent: table 51822 = blackhole default route
          main                                 # never reached for traffic that arrived on wg0
```

- **Rule 90** sends traffic for `peerCIDR` back to `wg0`, so the provider's replies to a peer reach
  `wg0` instead of re-entering `tun0`.
- **Rules 98 to 101** are gluetun's. Rules 98 to 100 keep local, outbound-subnet and inbound
  traffic on `eth0`; rule 101 routes everything else into `tun0` while the tunnel is up. Rules 98 and
  99 match by destination, so a peer packet addressed inside `localCIDRs` routes to `eth0` and is
  stopped by the `FORWARD` drop policy rather than by routing. Traffic for the internet never reaches
  the main table.
- **Rule 102** catches whatever gluetun's rules did not route and blackholes it. This is the
  fail-closed rule: the pod's main-table default route through `eth0` is unreachable for peer
  traffic whatever happens to iptables.

If gluetun's tunnel table has no route, or its tunnel rule (rule 101) is gone, rule 102 drops peer
traffic, whatever gluetun's firewall does. The agent then also reports the pod not ready; see
[Readiness follows the tunnel](#readiness-follows-the-tunnel).

## The iptables rules

iptables rules handle availability: they let the traffic that routing allows actually flow. gluetun
sets the `FORWARD` policy to `DROP` and adds no accepts of its own, so the agent asserts:

```text
-P FORWARD DROP
filter  -A FORWARD -i wg0 -o tun0 -s <peerCIDR> -j ACCEPT
filter  -A FORWARD -i tun0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
mangle  -A FORWARD -o tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
nat     -A POSTROUTING -s <peerCIDR> -o tun0 -j MASQUERADE
```

Peer traffic is masqueraded into gluetun's tunnel, never out of `eth0`. The agent re-asserts the
routing and these rules after every state change and every 10 seconds, adding only a rule whose
check fails, so a rule is never duplicated. When gluetun restarts it can flush its firewall, and the
rules come back within one interval. During that window the blackhole rule drops peer traffic, so a
gluetun restart costs an outage, not a leak.

## Readiness follows the tunnel

The agent's `/health` is the pod's readiness probe. It succeeds only when the desired state is
valid, `wg0` is synced to it, the datapath above has been asserted, the kernel would forward a
peer's packet arriving on `wg0` into `tun0`, and gluetun's health server on `127.0.0.1:9999`
answers `200`. An unhealthy tunnel makes the server pod not ready, the Service drops its only
endpoint, and clients stop handshaking.

The peer-path check asks the kernel for the route to `192.0.2.1`, a documentation address
([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)), from the second address in `peerCIDR`
arriving on `wg0`. That is the lookup `ip route get 192.0.2.1 from 10.8.0.2 iif wg0` performs
with the default `peerCIDR`, and the agent sends no packet. It exists because gluetun's own health
check can pass while peers are blackholed: gluetun's traffic does not arrive on `wg0`, so only a
lookup that does catches it. With the default probe settings (every 10 seconds, 3 failures), the
pod goes not ready within about 30 seconds of the path breaking.

The `Wireguard` follows the pod: `Ready` is `False` with reason `DeploymentNotReady` until the
Deployment rendered from the current spec has rolled out, and `True` only then. A new gateway
therefore reads `pending` until gluetun has connected to your provider. See
[crd-wireguard.md](crd-wireguard.md#conditions).
