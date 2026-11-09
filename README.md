# tunnel-operator

A Kubernetes operator that sends chosen pods' internet traffic through a commercial VPN provider,
declaratively. Label a workload and its pods get a WireGuard client sidecar that tunnels to an
in-cluster gateway, which egresses through [gluetun](https://github.com/qdm12/gluetun) and fails
closed: a pod that cannot be tunnelled does not run, and traffic is dropped, never leaked, when the
tunnel is down. Cluster traffic — DNS, Services, other pods — never enters the tunnel.

This is a fork of [jodevsa/wireguard-operator](https://github.com/jodevsa/wireguard-operator) that
trims it to an in-cluster gateway — no LoadBalancer or NodePort Service, no wstunnel, no IPv6, no
client private keys held by the operator — and reconciles what is left with Server-Side Apply; see
[What's changed in this fork](#whats-changed-in-this-fork).
Versions restart at v0.1.0; the fork began from upstream v2.11.0 (commit `7cda258`).

The operator is **not** a VPN for phones or laptops. The gateway is reachable in-cluster only,
through a ClusterIP Service.

> [!WARNING]
> **Agentically generated.** This codebase was produced through agentic,
> spec-driven development: each feature began as a written design and
> implementation spec, then a coding agent executed the plan under human
> review. Tests, code review, and CI gates apply as they would for any
> project, but the authorship pattern is not a single human contributor —
> keep that in mind when evaluating fit for your environment.

## What it does

- **Label-driven injection** — pods labelled `tunnel-operator.io/enabled: "true"` get the client
  sidecar at admission and attach to the default gateway. A labelled pod that cannot be injected,
  or uses the host network, is rejected with a reason; one in a namespace the gateway refuses is
  admitted and waits in its startup probe. See [docs/injection.md](docs/injection.md).
- **`Wireguard`** — a gateway: a WireGuard server pod with a gluetun container that holds the
  tunnel to your VPN provider. It fails closed by routing, and reads ready only when a peer's packet
  would be forwarded into the tunnel and gluetun is healthy. See [docs/gluetun-egress.md](docs/gluetun-egress.md).
- **Egress API** — the gateway reports its exit IP and forwarded port, sends the forwarded port to
  one labelled pod, and lets labelled pods and `kubectl` cycle the VPN for a new exit IP. See
  [docs/gluetun-egress.md](docs/gluetun-egress.md#egress-api).
- **`WireguardPeer`** — one client, identified by its public key, in the client's own namespace.
  The operator allocates its address and copies the gateway's endpoint, public key and
  `localCIDRs` into its status. The operator never sees a client's private key.
- **Any namespace** — a gateway serves peers from every namespace unless its
  `allowedNamespaces.from` is `Same`.
- **The sidecar without injection** — write the same sidecar into a pod spec yourself. See
  [docs/client-sidecar.md](docs/client-sidecar.md).

## Quick start

**Prerequisites:** Kubernetes 1.34 or later (on 1.34 and 1.35, with the `MutatingAdmissionPolicy`
beta enabled), `kubectl`, Helm 4 (tested with 4.3.1), and Pod Security `privileged` in the
namespaces that run the gateway and tunnelled pods. Details:
[docs/prerequisites.md](docs/prerequisites.md).

**1. Install the operator into `network`.** The clone is for step 2's example file:

<!-- x-release-please-start-version -->
```sh
git clone https://github.com/jacaudi/tunnel-operator.git
cd tunnel-operator
helm install tunnel-operator oci://ghcr.io/jacaudi/charts/tunnel-operator --version 0.1.0 -n network --create-namespace
kubectl label namespace network pod-security.kubernetes.io/enforce=privileged --overwrite
kubectl -n network rollout status deployment/tunnel-operator-manager
```
<!-- x-release-please-end -->

**2. Create the default gateway.** Copy [`examples/01-server.yaml`](examples/01-server.yaml) out of the
clone, so your provider key never sits in it (`cp examples/01-server.yaml ~/vpn-gateway.yaml`). Set
`localCIDRs` to your cluster's networks ([how to find them](docs/prerequisites.md#localcidrs)) and
put your provider's gluetun variables in its `vpn-provider` Secret. The file carries the
`tunnel-operator.io/default: "true"` annotation, which counts only in the operator's namespace:

```sh
kubectl -n network apply -f ~/vpn-gateway.yaml
kubectl -n network get wireguard vpn    # STATUS: ready once gluetun has connected
```

**3. Label a workload.** Here, a Deployment in `default`:

```sh
kubectl label namespace default pod-security.kubernetes.io/enforce=privileged --overwrite
kubectl -n default patch deployment <name> \
  -p '{"spec":{"template":{"metadata":{"labels":{"tunnel-operator.io/enabled":"true"}}}}}'
```

The patch rolls the Deployment, and each new pod starts with the `wg-client` sidecar. Without a
workload of your own, apply [`examples/injected-client.yaml`](examples/injected-client.yaml).

**4. Check.**

```sh
kubectl get wireguardpeer -A    # one peer per tunnelled pod, STATUS ready
```

The [walkthrough](docs/walkthrough.md) runs these steps with a check at each, shows a pod's exit IP,
shows a labelled pod being refused, and cleans up.

## How it works

How traffic flows from a labelled pod to the VPN provider:

![Traffic flow: a labelled pod's injected wg-client sidecar tunnels its internet traffic over UDP 51820, through the gateway's ClusterIP Service, to the WireGuard server, which forwards it into gluetun and out through the VPN provider; cluster DNS, pods, Services and nodes stay local, and a blackhole route, gluetun's firewall and the client's routes fail closed](docs/images/01-traffic-flow.svg)

Where it runs: the operator and its default gateway in `network`, a labelled workload in `default`:

![Infrastructure: the operator in network writes the injection policy, reconciles the Wireguard and its WireguardPeers, and applies the gateway's Secret, Service and server pod; each labelled pod in default runs an injected wg-client sidecar that registers its own WireguardPeer and tunnels to the gateway, which egresses through the VPN provider](docs/images/02-infrastructure.svg)

- **Manager** — reconciles each `Wireguard` into a key Secret, a ClusterIP Service on UDP `51820`
  and a single-replica server Deployment, allocates peer addresses, and writes the server's desired
  state into the Secret. It also writes the injection policy for the default gateway, and a client
  `RoleBinding` in each namespace with labelled pods.
- **Admission** — the API server injects the sidecar from the operator's `MutatingAdmissionPolicy`;
  a static `ValidatingAdmissionPolicy` rejects a labelled pod that was not injected. No webhook.
- **Server pod** — the `agent` runs `wg0` (kernel WireGuard, or wireguard-go when the module is
  missing) and keeps it in step with the state; `gluetun` holds the provider tunnel; peer traffic
  leaves only through it.
- **Client sidecar** — mints its key in the pod's memory, registers its pod as a `WireguardPeer`,
  configures `wg0` from the peer's status, and routes everything outside `localCIDRs` into it.

[docs/architecture.md](docs/architecture.md) has the detail.

## What's changed in this fork

Beyond the upstream project, this fork:

- **Adds the egress gateway** — gluetun egress that fails closed, the client sidecar, label-driven
  injection, and peers that attach from other namespaces.
- **Removes external-client exposure** — the Service is always ClusterIP; `serviceType`, `port`,
  `address`, `externalAddress` and `serviceAnnotations` are gone, and so is wstunnel.
- **Removes operator-held client keys** — peers bring their own `publicKey`; the operator no
  longer mints peer keys, reads `privateKeyRef`, or renders a peer configuration Secret.
- **Removes the server iptables sync, IPv6, per-peer policy, server-pushed DNS and the metrics
  exporter** — none has a consumer in an in-cluster gateway, and the iptables sync replaced the
  pod's whole `nat` and `filter` tables on every peer change.
- **Reconciles with Server-Side Apply** — the Service and Deployment converge on every reconcile,
  with field ownership migrated from the upstream manager.
- **Publishes its own images** — `ghcr.io/jacaudi/tunnel-operator/{manager,agent}`, built from
  the Go module `github.com/jacaudi/tunnel-operator`. Releases are cut from `main` by release-please;
  the images and the chart share one version, and the chart's `appVersion` picks the matching
  images.

Coming from upstream? Read [docs/upgrading-from-upstream.md](docs/upgrading-from-upstream.md).

## Documentation

Full docs live in [`docs/`](docs/):

- [Prerequisites](docs/prerequisites.md) · [Installation](docs/installation.md) · [Walkthrough](docs/walkthrough.md)
- [Sidecar injection](docs/injection.md) · [Client sidecar](docs/client-sidecar.md) · [Gluetun egress](docs/gluetun-egress.md)
- [Architecture](docs/architecture.md) · [`Wireguard`](docs/crd-wireguard.md) · [`WireguardPeer`](docs/crd-wireguardpeer.md) references
- [Upgrading from upstream](docs/upgrading-from-upstream.md) · [Examples](examples/)

## Acknowledgements

- **[Subhi Al Hasan (jodevsa)](https://github.com/jodevsa)** — the author of
  [wireguard-operator](https://github.com/jodevsa/wireguard-operator), which this project is forked
  from. The two CRDs, the agent's netlink and wgctrl code, the kernel-to-userspace fallback and
  the IP allocator are his work; this fork keeps them and removes the parts an in-cluster gateway
  does not need. Thank you for building it and keeping it open! GitHub lists
  this repository as a fork of [NCCloud/wireguard-operator](https://github.com/NCCloud/wireguard-operator),
  which carries the same history; thanks to everyone who contributed there.
- **[qdm12](https://github.com/qdm12)** — the author of [gluetun](https://github.com/qdm12/gluetun),
  the VPN client the egress design builds on.
- **[angelnu](https://github.com/angelnu)** — [pod-gateway](https://github.com/angelnu/pod-gateway)
  is the prior art for routing a pod's traffic through an in-cluster gateway and failing closed by
  routing.
- [WireGuard](https://www.wireguard.com/), [wireguard-go](https://github.com/WireGuard/wireguard-go)
  and [wgctrl](https://github.com/WireGuard/wgctrl-go) for the tunnel itself, and
  [Kubebuilder](https://github.com/kubernetes-sigs/kubebuilder) for the scaffolding.

## License

[MIT](LICENSE)
