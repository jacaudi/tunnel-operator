# Architecture

## The problem

Some workloads need their internet traffic to leave through a commercial VPN provider, while
everything in-cluster — DNS, other pods, Services — keeps working normally. Running a VPN client in
every pod spreads provider credentials across the cluster and makes each pod's kill switch its own
problem. This operator puts one WireGuard server in the cluster instead: pods tunnel to it
by public key, from any namespace the server allows, and the server is the single place where
traffic meets the provider.

## Two resources

```text
WireguardPeer ──wireguardRef──▶ Wireguard ──owns──▶ Secret <name>, Service <name>-svc, Deployment <name>-dep
  (one per client)               (one per gateway)
```

- **[`Wireguard`](crd-wireguard.md)** — the server. It owns the key Secret, the ClusterIP Service
  and the single-replica Deployment. It does not own its peers.
- **[`WireguardPeer`](crd-wireguardpeer.md)** — a client. It carries the public key and receives an
  address. It lives in its own namespace and names its server by `wireguardRef` and, for a server in
  another namespace, `wireguardNamespace`.

There is one controller. It reconciles each `Wireguard` and also watches `WireguardPeer` objects,
mapping each peer to the server its `wireguardRef` and `wireguardNamespace` name, not to an owner.
A peer change therefore reconciles the server it points at, and a peer that changes `wireguardRef`
reconciles both the old and the new server.

The split follows WireGuard itself: an interface has one key pair and many peers, and a peer is
nothing more than a public key and the addresses routed to it.

## Data path

A client that holds a registered key reaches the server's `wg0` through the
ClusterIP Service, and the server forwards its traffic into a gluetun container in the same pod,
which holds the tunnel to the provider.

```text
client (your WireGuard config) ──UDP 51820──▶ <name>-svc (ClusterIP) ──▶ server pod: agent wg0 10.8.0.1 ──▶ gluetun tun0 ──▶ VPN provider
```

The client is a sidecar in the application pod. It routes the pod's internet traffic into the
server and keeps the cluster CIDRs on `eth0`.

```text
app pod: app + wg-client sidecar ──wg──▶ server pod: agent wg0 ──▶ gluetun tun0 ──▶ VPN provider
          cluster CIDRs stay on eth0
```

The sidecar is described in [client-sidecar.md](client-sidecar.md). The gluetun hop is described
in [gluetun-egress.md](gluetun-egress.md). You can write the sidecar into a pod yourself, or label
the pod and have the operator inject it; see [Sidecar injection](#sidecar-injection).

## The server pod

- **`sysctl`** (init, privileged) — sets `net.ipv4.ip_forward=1` in the pod's network namespace.
- **`agent`** (`NET_ADMIN`, read-only root filesystem) — creates `wg0` with the kernel module, or
  starts `wireguard-go` when the module is missing. It assigns the first host of `peerCIDR` to
  `wg0`, routes `peerCIDR` to it, and listens on UDP `51820`. It also asserts the fail-closed
  routing and the forwarding rules, and re-asserts them every 10 seconds.
- **`gluetun`** (`NET_ADMIN`) — holds the tunnel to the VPN provider as `tun0`. It is configured
  by `spec.gluetun`, shares the agent's network namespace, and has no probes of its own: the agent
  polls its health server.
- **Recreate, not rolling.** The Deployment's strategy is `Recreate`: one pod owns the key and the
  tunnel, so the old pod is gone before the new one starts.
- **State, not commands.** The manager never talks to the agent. It writes the desired state — the
  server's private key, the server's name, namespace and spec (without `spec.gluetun`, so provider
  credentials never reach a second Secret), and, for each peer the server
  admits (a valid key and an address), the peer's name, namespace, `publicKey`, `wireguardRef` and
  `status.address`, sorted by name and then namespace — into the Secret's `state.json`, which
  the pod mounts. A peer with no key, an invalid key, a key another peer holds, a namespace
  the server does not allow, an address conflict or no free address is left out. Other peer
  metadata (labels, annotations, resourceVersion, managedFields) and the rest of the status never
  reach the file, so writing them does not rewrite the Secret. The agent watches the file and
  diffs it against the live device, adding, updating and removing peers by public key.
- **Readiness.** `GET /health` on port `8080` re-reads and re-applies the state. It fails when the
  state is missing, invalid or cannot be applied, when the datapath has not been asserted, when a
  peer's packet arriving on `wg0` would not be forwarded into the tunnel, and when gluetun's health
  server answers anything but `200`. The pod is ready only when `wg0` is synced, the datapath is
  asserted, a peer's packet arriving on `wg0` would be forwarded into the tunnel and gluetun is
  healthy, and the `Wireguard` reports `Ready` only once that pod has rolled out. See
  [Readiness follows the tunnel](gluetun-egress.md#readiness-follows-the-tunnel).

## Identity and addresses

- **A peer is its public key.** The client generates its key pair and registers the public half;
  the operator never handles a peer private key. The server's own key pair is generated once by
  the operator and kept in the Secret.
- **Addresses are allocated, not leased.** The operator assigns the first free address in
  `peerCIDR` to each peer that has a key and no address, skipping the network address and the
  server's, and writes it to the peer's `status.address`. Allocation runs inside one reconcile over
  the server's peers, so two new peers in the same pass cannot collide. The server routes exactly
  `<address>/32` to each peer.
- **Duplicates are resolved.** If a stale cache still lets two peers hold one address, the oldest
  `creationTimestamp` wins. The others get `AddressConflict` and are re-allocated.

## Sidecar injection

A pod labelled `wireguard-operator.io/enabled: "true"` is injected with the sidecar at admission, by
two policies the API server evaluates itself, so there is no webhook server and no certificate:

```text
labelled pod ──▶ MutatingAdmissionPolicy (operator-written) inserts wg-client ──▶ ValidatingAdmissionPolicy (static, in release.yaml) admits it or says why not
```

- **The mutating policy follows the default gateway.** One controller writes it with Server-Side
  Apply, aimed at the single `Wireguard` in the operator's own namespace annotated
  `wireguard-operator.io/default: "true"`, and deletes it when there is not exactly one. Only the
  operator's namespace counts, so a tenant cannot pick the gateway.
- **The validating policy is the backstop.** It ships in `release.yaml`, so it exists before the
  operator first starts, and it rejects a labelled pod that is not injected. A labelled pod
  therefore either carries the tunnel or does not run.
- **The client RoleBinding follows the pods.** A second controller creates the `RoleBinding` that
  gives the client `ClusterRole` to a namespace's service accounts when its first labelled pod
  appears, and deletes it after the last is gone. To do that without caching every pod in the
  cluster, the manager's Pod cache holds only labelled pods; the gateway-pod lookup reads through
  the API reader instead.

See [injection.md](injection.md).

## Failure behaviour

The gateway fails closed by **routing** rather than by firewall rules alone:

- **Server side** — traffic arriving on `wg0` that has no route through gluetun's
  tunnel hits a blackhole route instead of the pod's default route, and peer traffic is
  masqueraded into gluetun's tunnel, never out of `eth0`. See
  [gluetun-egress.md](gluetun-egress.md#fail-closed-by-routing).
- **Client side** — the sidecar replaces the pod's default route
  with `wg0` and keeps only the cluster CIDRs on `eth0`, so a missing tunnel means no route to the
  internet, not a direct one.

## Out of scope

- **Clients outside the cluster** — phones, laptops, LoadBalancer or NodePort Services, external
  addresses, wstunnel.
- **IPv6, per-peer egress policy, bandwidth limits, metrics, high availability, and DNS through the
  gateway** — clients keep cluster DNS.
