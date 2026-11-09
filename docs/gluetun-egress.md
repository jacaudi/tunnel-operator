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
- **`gluetun.portForwarding.staticPort`** — a fixed forwarded port; see
  [Forwarded port](#forwarded-port).

The operator owns the variables the routing and the egress API depend on. It renders `VPN_TYPE`,
`VPN_INTERFACE`, the firewall settings, `HEALTH_SERVER_ADDRESS`, `WIREGUARD_MTU`, the three
`HTTP_CONTROL_SERVER_*` variables that lock down gluetun's control server, and
`VPN_PORT_FORWARDING_LISTENING_PORT`, which it renders empty (11 variables in all; the full table
is in [crd-wireguard.md](crd-wireguard.md#reserved-gluetun-variables)). If `env`, or the keys of a
Secret that `envFrom` references, set any of them, the `Wireguard` is `Degraded` with reason
`ReservedGluetunEnv` and no Deployment is rendered. A referenced ConfigMap is not checked, because
the operator's value takes precedence.

## `localCIDRs`

`spec.localCIDRs` is required: the cluster's pod, Service and node ranges, and `169.254.20.10/32` if
you use NodeLocal DNSCache. [Prerequisites](prerequisites.md#localcidrs) shows how to find them and
lists the checks the operator makes. Cluster traffic stays in the cluster:

- Clients route these ranges over the CNI, never through the tunnel.
- The server hands them to gluetun as `FIREWALL_OUTBOUND_SUBNETS`, so gluetun lets the pod answer
  cluster addresses over `eth0`.

The operator does **not** check that `localCIDRs` avoids the provider's tunnel range. An entry that
overlaps it keeps that traffic off the tunnel, so keep your `localCIDRs` outside the range your
provider uses; gluetun's firewall documentation says the same of `FIREWALL_OUTBOUND_SUBNETS`.

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
  stopped by the `FORWARD` drop policy rather than by routing (but see the window after a firewall
  rollback, under [The iptables rules](#the-iptables-rules)). Traffic for the internet never reaches
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
check fails, so a rule is never duplicated. gluetun can flush these rules, for example when it
restarts or rolls its firewall back; until the agent's next pass restores them (within 10 seconds,
or sooner on a state change), two conditions matter:

- **While the tunnel is down** (table `51820` empty, or rule 101 absent), rule 102 blackholes
  internet-bound peer traffic. That costs an outage, not a leak.
- **While the `FORWARD` policy is `ACCEPT`**, as it can be after gluetun rolls its firewall back, a
  peer packet addressed inside `localCIDRs` can be forwarded out of `eth0` to a cluster network,
  whatever the tunnel's state. It reaches the cluster, not the internet, and only a hand-configured
  peer sends such packets: the client sidecar routes `localCIDRs` over its own pod's `eth0`.

### The agent's own chains

The [egress API](#egress-api) and the [forwarded port](#forwarded-port) need rules of their own. The
agent keeps them in four chains, each reached by one jump inserted at position 1 of its built-in
chain:

| Table | Chain | Jump | Holds |
|---|---|---|---|
| `nat` | `TUNNEL-OP-PREROUTING` | `PREROUTING` | the forwarded port's DNAT to the holder |
| `filter` | `TUNNEL-OP-FORWARD` | `FORWARD` | the accept for that forwarded traffic |
| `filter` | `TUNNEL-OP-INPUT` | `INPUT` | the accept for the egress API on `wg0` |
| `filter` | `TUNNEL-OP-OUTPUT` | `OUTPUT` | the accept for the API's replies on `wg0` |

With tunnel address `10.8.0.1` (the first host of `peerCIDR`), holder `10.8.0.2` and port `51413`
they hold:

```text
nat     -A TUNNEL-OP-PREROUTING -i tun0 -p tcp --dport 51413 -j DNAT --to-destination 10.8.0.2:51413
nat     -A TUNNEL-OP-PREROUTING -i tun0 -p udp --dport 51413 -j DNAT --to-destination 10.8.0.2:51413
filter  -A TUNNEL-OP-FORWARD -i tun0 -o wg0 -d 10.8.0.2 -p tcp --dport 51413 -j ACCEPT
filter  -A TUNNEL-OP-FORWARD -i tun0 -o wg0 -d 10.8.0.2 -p udp --dport 51413 -j ACCEPT
filter  -A TUNNEL-OP-INPUT -i wg0 -d 10.8.0.1 -p tcp --dport 8081 -j ACCEPT
filter  -A TUNNEL-OP-OUTPUT -o wg0 -s 10.8.0.1 -p tcp --sport 8081 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

With no holder, or no port, the four DNAT and `FORWARD` lines are absent. The other two stay,
because gluetun's `INPUT` and `OUTPUT` policies are `DROP`. On every pass the agent creates a
missing chain, re-inserts a missing jump, and replaces the contents of the four chains in one
`iptables-restore --noflush` call, atomic per table, whose input flushes and refills only the
`TUNNEL-OP-*` chains. The chains therefore come back after gluetun flushes the firewall, and a
stale rule is gone after the next pass. The agent does not touch gluetun's firewall variables:
DNAT'd traffic crosses only `FORWARD`, which the agent's own chain accepts. A failure to assert
these chains holds the pod not ready, as a failure of the rules above does.

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

**A VPN cycle is the exception.** While a [cycle](#cycling-the-vpn) is in progress, `/health` skips
the gluetun-health and peer-path checks and stays `200`; every other check still applies. gluetun is
down on purpose, and a not-ready pod would lose its Service endpoint and break every peer's
handshake. The cycle's own deadline is 150 s, but the exemption lasts until the cycle's work is
done: the deadline, plus a restore of gluetun of up to 30 s, plus the refresh after the cycle of up
to 60 s, so up to about 240 s. Egress stays closed throughout, behind gluetun's killswitch and the
blackhole rule. gluetun's own `HEALTH_RESTART_VPN` restarts are not exempted.

The `Wireguard` follows the pod: `Ready` is `False` with reason `DeploymentNotReady` until the
Deployment rendered from the current spec has rolled out, and `True` only then. A new gateway
therefore reads `pending` until gluetun has connected to your provider. See
[crd-wireguard.md](crd-wireguard.md#conditions).

## Egress API

The gateway's agent serves a small HTTP API to the pods attached to it. A workload reads the exit IP
and the forwarded port, and a workload you opt in can cycle the VPN for a new exit IP without
restarting the gateway pod. A person can cycle it with `kubectl`. The same facts appear in the
`Wireguard`'s [status](crd-wireguard.md#status-operator-written).

### Calling the API

The base URL is the `Wireguard`'s `status.egressAPI`: `http://<server tunnel address>:8081`, which is
`http://10.8.0.1:8081` with the default `peerCIDR`. Read it with `kubectl`:

```sh
kubectl -n network get wireguard vpn -o jsonpath='{.status.egressAPI}'
```

The API listens only on the server's tunnel address, never on `0.0.0.0`, because gluetun accepts
all pod-subnet input on `eth0` and a wildcard bind would expose it to the cluster. A pod that is not
attached to the gateway gets a refused connection. The agent identifies the caller by its source
address, which is the peer's tunnel address and cannot be spoofed because the server routes only
`<address>/32` to each peer. An address that is not an admitted peer gets `403`.

| Route | Who | Answer |
|---|---|---|
| `GET /v1/egress` | any attached peer | `200` with the egress snapshot below, read from the agent's cache |
| `POST /v1/cycle` | peers allowed to cycle | `202 {"accepted":true}`; `403` when not allowed; `409` when refused |

Every error body is `{"reason","message"}`. Reading the snapshot from an attached pod:

```sh
wget -q -O- http://10.8.0.1:8081/v1/egress
```

```json
{"exitIP":"203.0.113.7","forwardedPort":51413,"forwardedPortHolder":true,"lastCycle":{"reason":"Succeeded","oldExitIP":"203.0.113.5","newExitIP":"203.0.113.7","trigger":"api:10.8.0.2","finishedAt":"2026-11-08T14:03:21Z"},"cycleInProgress":false}
```

| Field | Meaning |
|---|---|
| `exitIP` | gluetun's public IP. Absent while unknown, for example while the tunnel is down. |
| `forwardedPort` | The forwarded port in use. Absent when there is none. |
| `forwardedPortHolder` | `true` when the caller is the peer that holds the port, else `false`. |
| `lastCycle` | The last finished cycle: `reason`, `oldExitIP`, `newExitIP`, `trigger` and `finishedAt` (RFC 3339, whole seconds). Absent until a cycle has finished. |
| `cycleInProgress` | `true` while a cycle runs. |

Asking for a cycle from an attached pod that has the `tunnel-operator.io/cycle: "allowed"` label:

```sh
wget -q -O- --post-data= http://10.8.0.1:8081/v1/cycle    # {"accepted":true}
```

| Status | Body | Meaning |
|---|---|---|
| `202` | `{"accepted":true}` | A cycle started. Its result appears in `lastCycle` when it finishes. |
| `403` | `{"reason":"UnknownPeer",…}` | The caller is not an admitted peer of this gateway. |
| `403` | `{"reason":"CycleNotAllowed",…}` | The caller is a peer, but its pod is not [allowed to cycle](#who-may-cycle-and-who-holds-the-port). |
| `409` | `{"reason":"CycleInProgress","retryAfterSeconds":N,…}` | A cycle is running; `N` is what is left of its 150 s deadline, rounded up. While the agent restarts a stopped gluetun, `N` is 1. |
| `409` | `{"reason":"CooldownActive","retryAfterSeconds":N,…}` | The last cycle stopped gluetun less than 60 s ago; `N` is the cooldown that is left. |

gluetun's own control server is not exposed to workloads; see
[gluetun's control server](#gluetuns-control-server).

### Cycling the VPN

A cycle stops gluetun, starts it again and waits for its new public IP, so the provider may hand out
a new exit. **It interrupts all egress through this gateway for about 10 to 30 seconds. Peers stay
connected** and nothing leaves any other way: the killswitch and the blackhole rule hold while
gluetun is down.

A caller's `202` does not wait for the cycle, which runs under one hard deadline of 150 s. The
agent records one of these reasons in `lastCycle`:

| Reason | Meaning |
|---|---|
| `Succeeded` | gluetun is back with a different exit IP. |
| `IPUnchanged` | gluetun is back with the same exit IP. |
| `EmptyIP` | gluetun is back but reported no public IP within 60 s. |
| `Timeout` | stopping or starting gluetun, or the cycle as a whole, ran out of time. |
| `GluetunError` | gluetun answered an error while it was being stopped or started. |

- **gluetun is always asked to run again.** Whatever way a cycle ends, the agent sends gluetun a
  start with its own 30 s limit, and every 10 s it starts a gluetun that reports `stopped`, so an
  interrupted cycle does not leave the gateway down.
- **One at a time, with a cooldown.** The 60 s cooldown starts when gluetun is stopped, so a cycle
  that fails or times out also arms it. That bounds a restart storm.
- **The port comes back late.** gluetun re-obtains a forwarded port after every tunnel-up, so
  `forwardedPort` can read absent for a few seconds after a cycle until the agent's next refresh.
- **Who started it** is in `lastCycle.trigger`: `api:<peer address>` for a workload, or
  `annotation:<value>` for a person.

A person cycles the VPN by changing an annotation on the `Wireguard`:

```sh
kubectl -n network annotate wireguard vpn tunnel-operator.io/cycle-requested-at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" --overwrite
```

Any non-empty value that differs from the last one starts one cycle; the RFC 3339 time above is
only a convenient way to get a new value. The annotation value is also visible to every pod through
the agent's `/egress` endpoint (see [Freshness](#freshness-of-status)), so put nothing secret in it.

- **A value is handled once.** The agent records a value as handled when its cycle starts, and
  the operator writes it to `status.egress.lastHandledAnnotation`. An agent restart after a cycle
  starts can run the same value once more, until the handled value has come back to the agent
  through `state.json` (the 30 s poll plus the Secret sync); the cooldown bounds that.
- **A value that arrives during a cycle or a cooldown is not lost.** It runs when the cycle or the
  cooldown ends.

**How soon the agent acts.** The agent runs two loops. The local datapath pass (the iptables chains
and the API listener) runs at startup, on every state change and every 10 s. The gluetun loop
(refreshing the cached exit IP and port, restarting a stopped gluetun, and handling the annotation)
runs separately, every 10 s. A cycle requested through the annotation therefore starts within about
10 s of the agent seeing the new state. A state change reaches the agent through the kubelet's
Secret sync, which can take 1 to 2 minutes.

**Reading the result.** The last cycle is in `status.egress.lastCycle`, with the trigger and both IPs.
The `Cycled` condition mirrors it: `True` with reason `Succeeded`, otherwise `False` with that
reason (`IPUnchanged`, `EmptyIP`, `Timeout` or `GluetunError`), or `False` with reason `Unknown` for
a reason the operator does not recognise. The condition's message says nothing more; the trigger
and IPs are only in `lastCycle`.

### Who may cycle and who holds the port

A workload's pod opts in with labels on the **pod** (in a Deployment, its pod template):

| Label | Grants |
|---|---|
| `tunnel-operator.io/cycle: "allowed"` | `POST /v1/cycle` |
| `tunnel-operator.io/forwarded-port: "true"` | a candidate for the [forwarded port](#forwarded-port) |

**The namespace is the trust boundary.** Anyone who can create pods, or patch pod labels, in a
namespace attached to the gateway can give a pod these labels, and so gets cycle rights and
candidacy for the forwarded port. A same-namespace actor can also create a peer for a labelled pod
before that pod's own sidecar registers, and that peer's key, the actor's own, then holds the pod's
cycle rights and port candidacy. Attach only namespaces you trust to the gateway; set
[`allowedNamespaces.from: Same`](crd-wireguard.md#spec) to keep the gateway to its own namespace.

The operator limits what a forged peer can claim. A label counts only when the peer is
controller-owned by the live pod: the peer has the pod's name, its controlling ownerReference names
that pod's current UID, and the pod is not terminating. The operator reads each peer's pod directly
from the API server on every reconcile, and a label change takes effect on the next one, about 30 s
for a Ready gateway, and then reaches the agent through the kubelet's Secret sync (see
[How soon the agent acts](#cycling-the-vpn)). A pod that is missing, replaced under the same name
or terminating gets nothing.

A transient error reading a client's pod, anything but NotFound, pauses that gateway's `state.json`
updates until the read succeeds. That is deliberate: treating the pod as unverified would revoke
permissions that are live and could hand the port over.

### Forwarded port

gluetun forwards a port natively for PIA, ProtonVPN, Perfect Privacy and PrivateVPN only. Turn it on
in `spec.gluetun.env` with gluetun's own variable (`VPN_PORT_FORWARDING=on`). The provider assigns
the port, which is re-obtained, and may change, on every tunnel-up: a cycle, a health restart, a
reconnect. The agent follows it, and `status.egress.forwardedPort` shows the port in use.

`spec.gluetun.portForwarding.staticPort` (1 to 65535) is for a provider or setup where the port is
fixed, for example one the provider shows in its dashboard. When it is set, the agent forwards that
port and does not read gluetun's.

```yaml
spec:
  gluetun:
    portForwarding:
      staticPort: 51413
```

One pod at a time holds the port, and the agent sends TCP and UDP on it to that pod over the tunnel:

- **The holder keeps the port** while it stays a candidate. Removing the label, deleting the pod or
  detaching it releases the port. The holder is a peer (`namespace/name`), not a tunnel address: a
  restarted workload gets a new pod and so a new peer name, and competes as a new candidate even if
  it is given the old address.
- **Otherwise the oldest candidate wins**: by the peer's `creationTimestamp`, then name, then
  namespace.
- **Each candidate peer's `PortForwarding` condition says who won**: `True` with reason `Held` on
  the holder, and `False` with reason `HeldByAnotherPeer` on the others, naming the holder. See
  [`WireguardPeer`](crd-wireguardpeer.md#portforwarding).
  `status.egress.forwardedPortPeer` names the holder as `namespace/name`.
- **A handover is not instant.** The agent learns the new holder through the kubelet's Secret sync
  (see [How soon the agent acts](#cycling-the-vpn)), so the old DNAT can outlive the change by that
  lag.

The holder's application must listen on the port on all addresses, not only on loopback: the DNAT'd
packets arrive on `wg0` addressed to the holder's tunnel address. Replies are reversed by conntrack
and leave through the tunnel. The rules are the [`TUNNEL-OP-*` chains](#the-agents-own-chains).

### Freshness of status

The manager reads `status.egress` by polling each gateway pod, so it is not instant:

- **It needs TCP 8080 on the gateway pod.** For a Ready gateway with exactly one Ready pod, every
  30 s the manager calls `GET /egress` on the pod IP with a 2 s timeout. Where a NetworkPolicy
  blocks the manager from that port, `status.egress` goes stale and an Error is logged every 30 s;
  `Ready` is not affected.
- **Polls are serial.** An unreachable agent costs up to 2 s of every 30 s of the manager's single
  reconcile worker.
- **A failed poll keeps the last value.** `status.egress` is not cleared while the gateway is not
  Ready or cannot be reached. A body over 1 MiB is a failed read and behaves the same way: stale,
  an Error logged, `Ready` unaffected.

The `/egress` body is the snapshot above without `forwardedPortHolder`, plus
`lastHandledAnnotation`, and the same port answers the kubelet's probes, so any pod in the cluster
can read it. The exit IP is not secret.

### gluetun's control server

The operator locks gluetun's control server down so only the agent can use it. It listens on
`127.0.0.1:8000`. Its one role, `tunnel-operator-agent`, allows `GET /v1/publicip/ip`,
`GET /v1/portforward`, `GET /v1/vpn/status` and `PUT /v1/vpn/status`, and needs an API key. The
default role is empty, so every other route, such as `/v1/vpn/settings`, which returns credentials,
answers `401`. The agent holds the key as `GLUETUN_API_KEY`, from a `secretKeyRef`. The key never
reaches a workload, the `Wireguard` or its status.

- **The key is generated once.** The operator writes 32 random bytes, base64url without padding, to
  the server's Secret as `gluetun-api-key`, with gluetun's role file as `gluetun-auth.toml`, and
  never rotates it. gluetun reads the file from `/gluetun/auth/config.toml`.
- **To rotate it, delete `gluetun-api-key` from the Secret.** The operator generates a new key and
  rewrites the role file, but a running pod keeps the old key until it restarts, so restart the
  gateway pod after deleting the key.
- **An empty `GLUETUN_API_KEY` does not stop the agent.** The API keeps serving, and every cycle
  fails as `GluetunError`.
