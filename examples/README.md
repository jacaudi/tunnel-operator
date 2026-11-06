# Example custom resources

Four files: a server with its provider Secret, a peer of that server, and two client Deployments that
attach an application pod to it, one with the sidecar written out and one that the operator injects. Pair them with the reference docs:
[`Wireguard`](../docs/crd-wireguard.md) and [`WireguardPeer`](../docs/crd-wireguardpeer.md).

## Files

| File | What it shows |
|---|---|
| [`01-server.yaml`](01-server.yaml) | `Wireguard` named `vpn`, annotated `tunnel-operator.io/default: "true"` (the default gateway when it is in the operator's namespace), with the required `localCIDRs` (pod, Service and node placeholders) and `gluetun.envFrom` a Secret, plus that `vpn-provider` Secret with placeholder gluetun variables for a WireGuard provider; the defaults apply otherwise (`peerCIDR` `10.8.0.0/24`, ClusterIP Service on UDP `51820`) |
| [`02-peer.yaml`](02-peer.yaml) | `WireguardPeer` that references `vpn` and registers a client's public key; the operator fills in `status.address` |
| [`client.yaml`](client.yaml) | A `Deployment` whose pod runs the client sidecar, with its `ServiceAccount` and the `RoleBinding` to `tunnel-operator-client`; the sidecar registers its own peer, so no `WireguardPeer` is applied for it |
| [`injected-client.yaml`](injected-client.yaml) | A `Deployment` with no sidecar block, only the `tunnel-operator.io/enabled: "true"` label on its pod template; the operator injects the sidecar and attaches it to the default gateway (see [../docs/injection.md](../docs/injection.md)) |

## Reading order

Apply `01` first, then `02`, then `client.yaml`, into the same namespace:

```sh
kubectl apply -f examples/01-server.yaml
kubectl apply -f examples/02-peer.yaml
kubectl apply -f examples/client.yaml
kubectl get wireguard,wireguardpeer
```

The peer reads `ready` once the server has reconciled it. Applied before the server exists, it
reads `pending` (`Waiting for wireguard resource 'vpn' to be created`) until then.

`client.yaml` makes a peer too, and the sidecar creates it itself. `kubectl get wireguardpeer` lists
it beside `peer20`, named after the `app` pod:

```text
NAME                  STATUS   AGE
app-6d8f7c9b5-x2k4q   ready    40s
peer20                ready    3m
```

Deleting the Deployment deletes the pod and, with it, its peer. The namespace must allow
`NET_ADMIN` (Pod Security `privileged`); see
[../docs/prerequisites.md](../docs/prerequisites.md#pod-security-privileged).

`injected-client.yaml` is the alternative to `client.yaml`: apply one or the other. It attaches to
the default gateway, so apply `01-server.yaml` in the operator's namespace and `injected-client.yaml`
in any namespace the gateway allows; the [walkthrough](../docs/walkthrough.md) does exactly that.

> **Keys:** `02-peer.yaml` carries a sample public key. Replace it with the output of
> `wg genkey | wg pubkey` from the client that will connect; the operator never holds the private
> half.

> **Egress:** egress through gluetun works once you fill in the provider Secret in
> `01-server.yaml` (see [../docs/gluetun-egress.md](../docs/gluetun-egress.md)). The server reads
> `ready` only when gluetun has connected. `client.yaml` attaches a pod to it.
