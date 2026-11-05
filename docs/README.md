# wireguard-operator documentation

A Kubernetes operator that runs a WireGuard server inside your cluster and admits pods to it by
public key, declaratively — the base of an in-cluster VPN gateway that egresses through gluetun.

New here? Start with the [Quick start in the root README](../README.md#quick-start), then dig in:

| Doc | What it covers |
|---|---|
| [Installation](installation.md) | Prerequisites, install from source, your own images, manager flags, uninstall |
| [Architecture](architecture.md) | The two-resource model, the server pod, identity and addresses, what is out of scope |
| [`Wireguard` reference](crd-wireguard.md) | Server CRD: spec, status, conditions, owned objects, lifecycle |
| [`WireguardPeer` reference](crd-wireguardpeer.md) | Peer CRD: spec, status, conditions, lifecycle |
| [Gluetun egress](gluetun-egress.md) | Server egress through a gluetun container: configuration, `localCIDRs`, fail-closed routing, readiness |
| [Client sidecar](client-sidecar.md) | The in-pod WireGuard client: what it does, the pod spec, routing, the startup check, troubleshooting |
| [Sidecar injection](injection.md) | Label a pod and the operator injects the sidecar: the default gateway, the admission policies, rejections, uninstall cleanup |
| [Upgrading from upstream](upgrading-from-upstream.md) | What this fork removed from jodevsa/wireguard-operator and what to do instead |
| [Examples](../examples/) | Runnable sample manifests |

## What's implemented

- **`Wireguard`** reconcile — server key Secret, single-replica server Deployment, ClusterIP
  Service on UDP `51820`, all applied with Server-Side Apply and garbage-collected with the CR.
- **`WireguardPeer`** registration — `status.address` allocation from `peerCIDR`,
  `PublicKeyMissing`/`InvalidPublicKey`/`NamespaceNotAllowed` reporting, address and public key
  dedupe.
- **Agent** — kernel WireGuard with a wireguard-go fallback; adds, updates and removes peers by
  public key as `state.json` changes; `/health` readiness.
- **Egress through gluetun** — the server pod runs a gluetun container, forwards peer traffic into
  its tunnel and fails closed by routing; `Ready` waits for gluetun to be healthy. See
  [gluetun-egress.md](gluetun-egress.md).
- **Client sidecar** — an init container with `restartPolicy: Always` that registers its pod as a
  `WireguardPeer`, configures `wg0` from its peer's status and routes the pod's internet traffic
  through it. See [client-sidecar.md](client-sidecar.md).
- **Cross-namespace attachment** — a peer names a `Wireguard` in another namespace with
  `wireguardNamespace`, and the gateway admits or refuses that namespace through
  `allowedNamespaces`. See [client-sidecar.md](client-sidecar.md#attaching-to-a-gateway-in-another-namespace).
- **Sidecar injection** — pods labelled `wireguard-operator.io/enabled: "true"` get the client sidecar
  from an operator-written `MutatingAdmissionPolicy`, aimed at the default gateway in the operator's
  namespace; a static `ValidatingAdmissionPolicy` rejects any labelled pod that was not injected, and
  the operator keeps the client `RoleBinding` in namespaces that have labelled pods. See
  [injection.md](injection.md).

## Not yet implemented (designed)

- **OCI Helm chart** — see [installation.md](installation.md#install-with-helm-oci). Tracked in
  [#48](https://github.com/jacaudi/wireguard-operator/issues/48).

The design specs and implementation plans are working documents kept outside this repository, so
the issue threads are where design intent gets shared.
