# Client sidecar

> **Status: designed, not yet implemented.** The agent image has no client mode, and the operator
> does not inject or run anything in application pods. This page describes the intended design and,
> until it ships, how to connect a client by hand. Tracked in
> [#32](https://github.com/jacaudi/wireguard-operator/issues/32).

## Today: configure the client yourself

Register a [`WireguardPeer`](crd-wireguardpeer.md) with your public key, wait for it to read
`ready`, then build a WireGuard configuration from these values. The Service is ClusterIP, so the
client must run inside the cluster.

| Setting | Value | How to read it |
|---|---|---|
| `[Interface] PrivateKey` | Your private key | The `peer.key` you generated with `wg genkey`. |
| `[Interface] Address` | `<address>/32` | `kubectl get wireguardpeer <peer> -o jsonpath='{.status.address}'` |
| `[Peer] PublicKey` | The server's public key | `kubectl get wireguard <wireguard> -o jsonpath='{.status.publicKey}'` |
| `[Peer] Endpoint` | `<cluster IP>:51820` | `kubectl get wireguard <wireguard> -o jsonpath='{.status.endpoint}'` |
| `[Peer] AllowedIPs` | The server's address, `/32` | The first host of the server's `peerCIDR`: `10.8.0.1/32` by default. |

```ini
[Interface]
PrivateKey = <contents of peer.key>
Address = 10.8.0.2/32

[Peer]
PublicKey = <server public key>
Endpoint = <cluster IP>:51820
AllowedIPs = 10.8.0.1/32
PersistentKeepalive = 25
```

The server now egresses through gluetun, so `AllowedIPs = 0.0.0.0/0` sends a client's internet
traffic through the provider (see [gluetun-egress.md](gluetun-egress.md)).

## Planned: a native sidecar that registers itself

You add one init container with `restartPolicy: Always` — a native sidecar — as the **first** init
container of the application pod, running the existing agent image in a new client mode. The
operator injects nothing; there is no webhook.

1. **One key per pod, minted in the pod.** The sidecar generates its private key into a
   memory-backed volume, so a container restart reuses it and it never reaches etcd or disk.
2. **Self-registration.** It creates a `WireguardPeer` named after the pod, with the pod as its
   controller owner, so the peer is garbage-collected with the pod. The allocated address is in
   `status.address`, which only the operator can write.
3. **Configuration from the server.** It reads the server's endpoint, public key and
   `localCIDRs` from the `Wireguard` and re-applies them when they change.
4. **Routing, not firewalling.** It routes each `localCIDRs` entry via the pod's CNI gateway,
   replaces the default route with `wg0`, and deletes the IPv6 default route. A missing `wg0`
   leaves no route to the internet. Cluster DNS and in-cluster traffic never enter the tunnel.
5. **Startup gate.** A startup probe holds the application containers until the tunnel is up and
   the default route points at `wg0`.

Prerequisites for the planned sidecar: a Kubernetes version with native sidecars, a namespace that
allows `NET_ADMIN` (Pod Security `privileged`), and a RoleBinding to a new
`wireguard-operator-client` ClusterRole that grants `create get list watch delete` on
`wireguardpeers` and `get list watch` on `wireguards`.
