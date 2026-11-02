# Client sidecar

The client sidecar is the WireGuard client for an application pod. You add one init container with
`restartPolicy: Always` — a native sidecar — as the **first** init container of the pod. It runs
the agent image as `agent client`, registers the pod with a [`Wireguard`](crd-wireguard.md) server
and routes the pod's internet traffic through the tunnel to the gateway. The operator injects
nothing; there is no webhook. [`examples/client.yaml`](../examples/client.yaml) is a complete
Deployment.

## What it does

1. **Refuses a pod in the host network.** If `POD_IP` equals `HOST_IP`, the pod shares the node's
   network namespace, and replacing its default route would cut the node off. The sidecar exits
   with `refusing to start`. It also exits, naming each one, when any of `POD_NAME`,
   `POD_NAMESPACE`, `POD_UID`, `POD_IP` or `HOST_IP` is unset, or when `--wireguard` is missing.
2. **Keeps one key in the pod.** It generates a private key into `/var/run/wireguard/key` on a
   memory-backed volume, with mode `0600`, and reuses it when the container restarts. The key never
   reaches etcd or disk. A key file that holds no valid WireGuard key stops the sidecar and is
   left as it is.
3. **Registers the pod.** It creates a [`WireguardPeer`](crd-wireguardpeer.md) named after the pod,
   in the pod's namespace, with `spec.wireguardRef` set to `--wireguard`, the public half of its key
   as `spec.publicKey`, and the pod as its controller owner. Deleting the pod deletes the peer.
   If a peer already exists under the pod's name:
   - **it is this pod's, with this pod's key and `wireguardRef`** — the sidecar keeps it;
   - **a Pod controls it, but not this pod, or it carries another key or `wireguardRef`** — the
     sidecar deletes it, guarded by the old peer's UID, and creates its own. This is what happens
     when a StatefulSet pod comes back under the same name;
   - **no Pod controls it** — the sidecar refuses to delete it and registers nothing. The peer was
     not made by a sidecar, so it is yours to remove.
4. **Watches and re-applies.** It watches the pod's peer and the `Wireguard` named by
   `--wireguard`, and runs a pass on every change to either and every 10 seconds. A pass registers
   the peer, reads `status.address` from the peer and `status.endpoint`, `status.publicKey` and
   `spec.localCIDRs` from the `Wireguard`, and applies them. While the operator has not published
   them yet, the pass waits and the next one retries.
5. **Configures `wg0`.** It creates `wg0` (kernel module, or wireguard-go when the node has none)
   at MTU `1320`, with the peer's `status.address` as a `/32` and exactly one peer: the server's
   public key and endpoint, `AllowedIPs 0.0.0.0/0` and a keepalive of 25 seconds. It reconfigures
   the device only when it differs, so a pass never resets a live session.
6. **Routes the pod through it.** See [Routing](#routing).

## Routing

The safety property comes from routes, not firewall rules. A pass leaves the pod's main routing
table like this:

```text
10.244.0.0/16 via <CNI gateway> dev eth0 proto 151     # one route per entry of localCIDRs
10.96.0.0/12  via <CNI gateway> dev eth0 proto 151
192.168.0.0/24 via <CNI gateway> dev eth0 proto 151
default dev wg0 scope link proto 151                   # everything else
```

- **Local traffic stays on `eth0`.** Each `localCIDRs` entry of the `Wireguard` gets a route via the
  CNI gateway on `eth0`. Cluster DNS and in-cluster traffic never enter the tunnel, as long as
  `localCIDRs` covers them.
- **Everything else is tunnelled.** The default route is `default dev wg0`. The gateway's own
  Service is reachable because its ClusterIP is inside `localCIDRs`.
- **No other way out.** The sidecar deletes every other IPv4 default route, and every IPv6 default
  route. A pod with no IPv6 default route has no IPv6 internet; IPv6 is out of scope.
- **Marked routes.** Every route the sidecar installs carries rtnetlink protocol `151`. It
  removes only routes it installed: an entry that left `localCIDRs` is deleted on the next pass,
  and routes the CNI installed, such as the pod subnet's own, stay.
- **Fail closed.** If `wg0` vanishes, the default route goes with it and the main table has no
  route to the internet, so the application's traffic fails instead of leaving through `eth0`.
  The next pass, within 10 seconds, recreates `wg0` and the default route.
- **Re-entry after a restart.** After a container restart the default route is already `wg0`, so
  the CNI gateway cannot be read from it. The sidecar reads it from its own protocol-151 routes.
- **No iptables.** The client installs no firewall rules; the server's
  [fail-closed routing](gluetun-egress.md#fail-closed-by-routing) covers the other end.

## The pod spec

[`examples/client.yaml`](../examples/client.yaml) holds the whole Deployment, its `ServiceAccount`
and the RoleBinding. The init container needs these fields:

| Field | Why |
|---|---|
| First in `initContainers` | A native sidecar starts before, and stays up beside, every container after it. Init containers listed after it run inside the tunnel too. |
| `restartPolicy: Always` | Makes the init container a native sidecar, so it keeps running with the application containers. |
| `args: ["client", "--wireguard", "<name>"]` | Runs the agent in client mode and names the `Wireguard`, in the pod's namespace, to attach to. |
| `POD_NAME`, `POD_NAMESPACE`, `POD_UID` | Downward API (`metadata.name`, `metadata.namespace`, `metadata.uid`). They name the peer and make the pod its controller owner. |
| `POD_IP`, `HOST_IP` | Downward API (`status.podIP`, `status.hostIP`). They tell a pod in the host network from one in its own. |
| `securityContext.capabilities.add: [NET_ADMIN]` | Creates `wg0` and changes the pod's routes. |
| A memory-backed `emptyDir` mounted at `/var/run/wireguard` | Holds the key in memory. It survives a container restart and is gone with the pod. |
| `startupProbe` running `agent client --check` | Holds the application containers until the tunnel is up and the routes are in place. `periodSeconds: 2` and `failureThreshold: 90` give it 180 seconds; if the check has not passed by then, the kubelet restarts the sidecar. |
| A `serviceAccountName` bound to `wireguard-operator-client` | Lets the sidecar create its peer and read the `Wireguard`. See [Prerequisites](#prerequisites). |

There is no liveness or readiness probe. The sidecar only configures: the kernel keeps the tunnel
and the routes running without the process, so a hung sidecar leaks nothing. The kubelet restarts
it if it exits.

## `agent client` flags

| Flag | Default | Description |
|---|---|---|
| `--wireguard` | — | **Required.** The name of the `Wireguard` in the pod's namespace to attach to. |
| `--check` | off | Run the [startup check](#the-startup-check) once and exit `0` if it passes, `1` with the reason on stderr if not. |
| `-v` | `0` | Log verbosity. `1` also logs `tunnel applied` for every pass that completes. |

The key is always `/var/run/wireguard/key`; there is no flag for it.

## The startup check

`agent client --check` passes only when both of these hold:

- **`wg0` has exactly one peer, and its last handshake is under 180 seconds old.** WireGuard
  rejects a session older than that.
- **The kernel routes `1.1.1.1` via `wg0`.** The check asks the kernel for the route; it sends no
  packet.

It prints what is missing and exits `1`, for example `wg0 has not completed a handshake with its
peer` or `1.1.1.1 does not route via wg0`. While the probe fails, the application containers do not
start.

## Prerequisites

- **Native sidecars.** A Kubernetes version that supports init containers with
  `restartPolicy: Always` (on by default from 1.29).
- **Pod Security `privileged`** in the application's namespace, because the sidecar needs
  `NET_ADMIN`. Label the namespace `pod-security.kubernetes.io/enforce: privileged`.
- **A RoleBinding to `wireguard-operator-client`.** The ClusterRole grants nothing until it is
  bound. In the application's namespace, bind it to the pod's ServiceAccount:

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: RoleBinding
  metadata:
    name: vpn-client
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: wireguard-operator-client
  subjects:
    - kind: ServiceAccount
      name: vpn-client
  ```

  The role grants `create get list watch delete` on `wireguardpeers` and `get list watch` on
  `wireguards`.
- **`localCIDRs` that cover the pod, Service and node CIDRs** on the `Wireguard`, plus
  `169.254.20.10/32` if you use NodeLocal DNSCache. See [`localCIDRs`](gluetun-egress.md#localcidrs).
  Anything outside them goes into the tunnel.

## Troubleshooting

The sidecar logs to stderr. Start with `kubectl logs <pod> -c wg-client`.

- **`waiting for the operator: …`** — not an error. The operator has not published something yet:
  the peer's `status.address`, or the `Wireguard`'s `status.endpoint` or `status.publicKey`. The line
  names which. The first line after registering reads `waiting for the operator: WireguardPeer
  <namespace>/<name> registered`. The sidecar retries on the next change and every 10 seconds. If
  the line stays, check `kubectl get wireguard,wireguardpeer`.
- **`client pass failed` with `… exists and no Pod controls it`** — a `WireguardPeer` with the
  pod's name exists and was not created by a sidecar, so the sidecar will not delete it. Delete
  the peer, or give the pod another name.
- **`client pass failed` with another error** — the message names it: a `Wireguard` with no
  `localCIDRs`, a value that does not parse, or a main table with no default route to read the CNI
  gateway from. The pass retries every 10 seconds.
- **A missing RoleBinding.** The sidecar logs nothing of its own. Its log shows client-go
  `failed to list … forbidden` lines, the startup probe keeps failing, and the kubelet restarts the
  sidecar, so the application containers never start. Create the RoleBinding to
  `wireguard-operator-client`, as in [Prerequisites](#prerequisites).
- **The startup probe fails with a handshake message.** The tunnel is configured but the server is
  not answering. Check that the `Wireguard` reads `ready` and that its server pod is running.

## Without the sidecar

A client the sidecar does not serve, such as a VM or a pod you cannot add an init container to,
needs its own WireGuard configuration. Register a [`WireguardPeer`](crd-wireguardpeer.md) with your
public key, wait for it to read `ready`, then build a configuration from these values. The Service
is ClusterIP, so the client must run inside the cluster.

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

The server egresses through gluetun, so `AllowedIPs = 0.0.0.0/0` sends a client's internet traffic
through the provider (see [gluetun-egress.md](gluetun-egress.md)). You then own the routes: keep
the cluster CIDRs off the tunnel yourself.
