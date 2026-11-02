# Example custom resources

Two files: one holds a server and its provider Secret, the other a peer of that server. Pair them with the reference docs:
[`Wireguard`](../docs/crd-wireguard.md) and [`WireguardPeer`](../docs/crd-wireguardpeer.md).

## Files

| File | What it shows |
|---|---|
| [`01-server.yaml`](01-server.yaml) | `Wireguard` named `vpn` with the required `localCIDRs` (pod, Service and node placeholders) and `gluetun.envFrom` a Secret, plus that `vpn-provider` Secret with placeholder gluetun variables for a WireGuard provider; the defaults apply otherwise (`peerCIDR` `10.8.0.0/24`, ClusterIP Service on UDP `51820`) |
| [`02-peer.yaml`](02-peer.yaml) | `WireguardPeer` that references `vpn` and registers a client's public key; the operator fills in `status.address` |

## Reading order

Apply `01` first, then `02`, into the same namespace:

```sh
kubectl apply -f examples/01-server.yaml
kubectl apply -f examples/02-peer.yaml
kubectl get wireguard,wireguardpeer
```

The peer reads `ready` once the server has reconciled it. Applied before the server exists, it
reads `pending` (`Waiting for wireguard resource 'vpn' to be created`) until then.

> **Keys:** `02-peer.yaml` carries a sample public key. Replace it with the output of
> `wg genkey | wg pubkey` from the client that will connect; the operator never holds the private
> half.

> **Egress:** egress through gluetun works once you fill in the provider Secret in
> `01-server.yaml` (see [../docs/gluetun-egress.md](../docs/gluetun-egress.md)). The server reads
> `ready` only when gluetun has connected. The in-pod client is not built yet, so a peer needs a
> hand-configured client to use it.
