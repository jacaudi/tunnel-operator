# `Wireguard` reference

The server. One `Wireguard` yields one WireGuard server pod, its key Secret and a ClusterIP
Service, all in the CR's namespace. **Namespaced**, group `vpn.wireguard-operator.io`, version
`v1alpha1`, no short name. `kubectl get wireguard` prints `STATUS` (`.status.status`) and `AGE`.

Source of truth: [`api/v1alpha1/wireguard_types.go`](../api/v1alpha1/wireguard_types.go). See
[`examples/01-server.yaml`](../examples/01-server.yaml).

## Spec

`localCIDRs` and `gluetun` are required. Every other field is optional.

| Field | Type | Default | Description |
|---|---|---|---|
| `peerCIDR` | string | `10.8.0.0/24` | IPv4 range peer addresses are allocated from. It must be a canonical IPv4 prefix (no host bits set) of `/30` or shorter; anything else sets `Degraded` with reason `InvalidPeerCIDR`. It may not contain `192.0.2.1` (`ProbeAddressInPeerCIDR`), the address the gateway's readiness check routes. The server's `wg0` takes the first host (`10.8.0.1` by default); the network address and that host are never allocated to a peer. The default is applied by the operator when the field is empty; the field itself stays empty. |
| `localCIDRs` | []string | — (**required**) | The cluster's pod, Service and node CIDRs, plus `169.254.20.10/32` when NodeLocal DNSCache is in use; at least one entry. Clients route these over the CNI and never through the tunnel, and the server hands them to gluetun as `FIREWALL_OUTBOUND_SUBNETS`. Each entry must be a canonical IPv4 CIDR (`InvalidLocalCIDRs`), overlap no part of `peerCIDR` (`PeerCIDROverlapsLocalCIDRs`) and not contain `192.0.2.1` (`ProbeAddressInLocalCIDRs`), and one entry must hold the Service's ClusterIP (`ClusterIPOutsideLocalCIDRs`); each reason is a `Degraded` condition. How to find the ranges, and the checks in full: [prerequisites.md](prerequisites.md#localcidrs). |
| `gluetun.env` | []`EnvVar` | — | Passed through to the `gluetun` container, after the variables the operator renders. Setting a reserved variable (below) sets `Degraded` with reason `ReservedGluetunEnv`. |
| `gluetun.envFrom` | []`EnvFromSource` | — | Passed through to the `gluetun` container. Reference provider credentials from a Secret here rather than writing them inline in `env`. A reserved variable among a referenced Secret's keys (with `prefix`, if set) sets `ReservedGluetunEnv`. A referenced ConfigMap is not checked, because the rendered value takes precedence. |
| `gluetun.resources` | `ResourceRequirements` | — | Requests and limits for the `gluetun` container. |
| `nodeSelector` | map[string]string | — | Copied to the server pod's `nodeSelector`. |
| `tolerations` | []`Toleration` | — | Copied to the server pod's `tolerations`. |
| `agent.resources` | `ResourceRequirements` | — | Requests and limits for the `agent` container. The `sysctl` init container gets none. |
| `allowedNamespaces.from` | `All` or `Same` | `All` | Which namespaces may attach peers to this server. `All` (also when `allowedNamespaces` is omitted) admits a peer in any namespace; `Same` admits only peers in the server's own namespace. A peer from another namespace under `Same` reads `Ready=False` with reason `NamespaceNotAllowed`, is allocated no address and is left out of the server's state; see [`WireguardPeer`](crd-wireguardpeer.md#conditions). Any other value is rejected at admission. With `All`, any namespace whose users may create `WireguardPeer`s can attach to the server and read its endpoint and public key from its own peer's status, and a conflict message names the holding peer as `namespace/name`, whatever its namespace. `Same` withholds the endpoint and key, and `NamespaceNotAllowed` still names the server. |

`gluetun` may be empty (`gluetun: {}`), but then gluetun has no provider configuration, so a useful
gateway sets `envFrom` or `env`.

### Reserved gluetun variables

The operator renders these seven variables, in this order and before `gluetun.env`, because the
server's routing depends on each value. They come from `ReservedGluetunEnv` in
[`internal/resources/gluetun.go`](../internal/resources/gluetun.go).

| Variable | Value | Why |
|---|---|---|
| `VPN_TYPE` | `wireguard` | The routing assumes gluetun's WireGuard-mode tables and marks. |
| `VPN_INTERFACE` | `tun0` | Clearing it makes gluetun delete the agent's `wg0`. |
| `FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT` | `on` | gluetun's own kill switch stays on. |
| `FIREWALL_INPUT_PORTS` | `51820,8080` | gluetun drops inbound traffic by default; these are the WireGuard and health ports. |
| `FIREWALL_OUTBOUND_SUBNETS` | `localCIDRs`, joined by commas | Lets the pod reach and answer cluster addresses over `eth0`. |
| `HEALTH_SERVER_ADDRESS` | `127.0.0.1:9999` | The agent's `/health` polls it. |
| `WIREGUARD_MTU` | `1320` | Pins the tunnel MTU. |

Everything else is gluetun's own configuration; see [gluetun-egress.md](gluetun-egress.md).

## Status (operator-written)

| Field | Description |
|---|---|
| `status` | Summary: `pending`, `ready` or `error`. Derived from the condition the operator wrote last — `Ready=True` → `ready`, `Ready=False` → `pending`, `Degraded` → `error`, anything else → `pending`. |
| `message` | The message of the condition the operator wrote last, for example `VPN is active!`. |
| `endpoint` | The address a client dials: the Service's ClusterIP and the WireGuard port, `<ClusterIP>:51820`. Written with every `Ready` condition, `True` or `False`; keeps its last value while the server is `Degraded`. |
| `publicKey` | The server's WireGuard public key. Written with every `Ready` condition, `True` or `False`; keeps its last value while the server is `Degraded`. |
| `conditions` | Standard `metav1.Condition` list, keyed by `type`. See below. |

## Conditions

| Type | Meaning |
|---|---|
| `Ready` | `True`, reason `Active`, once the Service, key Secret and Deployment are applied, every admissible peer was processed, and the Deployment rendered from this generation has rolled out: its controller has observed the generation and one pod is updated and ready. That pod is ready only when `wg0` is synced, the datapath is asserted, a peer's packet arriving on `wg0` would be forwarded into the tunnel (see [gluetun-egress.md](gluetun-egress.md#readiness-follows-the-tunnel)), and gluetun reports healthy. `False`, reason `DeploymentNotReady`, until then, with a message such as `Deployment vpn-dep is not rolled out: 0/1 ready, 1/1 updated`. A peer the pool cannot serve reports `AddressPoolExhausted` and does not hold the server back. |
| `Progressing` | `True`, reason `FetchingStatus`, written on the first reconcile of a new object. The operator does not set it back to `False` today. |
| `Degraded` | `True` when the spec cannot be rendered, or when building or applying an owned object fails. Reasons: `InvalidPeerCIDR`, `ProbeAddressInPeerCIDR`, `InvalidLocalCIDRs`, `PeerCIDROverlapsLocalCIDRs`, `ProbeAddressInLocalCIDRs`, `ClusterIPOutsideLocalCIDRs`, `ReservedGluetunEnv`, `ServiceBuildFailed`, `ServiceApplyFailed`, `DeploymentBuildFailed`, `DeploymentApplyFailed`; the message is the error. A spec problem is checked again every minute, so a fixed Secret clears `ReservedGluetunEnv` without a spec edit. Set to `False`, reason `Reconciled`, in any write of the `Ready` condition, `True` or `False`. |

## Owned objects

All three carry the labels `app: wireguard` and `instance: <name>`, are owned by the `Wireguard`,
and are deleted with it.

| Kind | Name | Contents |
|---|---|---|
| `Secret` | `<name>` | `privateKey` and `publicKey` (the server key pair), and `state.json` (the server's name, namespace and spec **without `spec.gluetun`**, plus its admitted peers, those with a valid key and an address, read by the agent). `spec.gluetun` is dropped so that provider credentials never reach a second Secret. |
| `Service` | `<name>-svc` | `ClusterIP`, one port `wireguard`, UDP `51820`. |
| `Deployment` | `<name>-dep` | One replica, strategy `Recreate`: the old pod is gone before the new one starts, because one pod owns the key and the tunnel. Init container `sysctl` (privileged, sets `net.ipv4.ip_forward=1`). Container `agent` (`NET_ADMIN`, read-only root filesystem, UDP `51820`, readiness `GET /health` with a 5 s timeout, liveness TCP on `8080`). Container `gluetun` (the pinned image `ghcr.io/qdm12/gluetun:v3.41.3@sha256:…`, `NET_ADMIN`, writable root filesystem, no probes of its own, and a `postStart` hook that deletes a stale `ip rule` for table `51820` so an abruptly restarted gluetun can start). Seccomp `RuntimeDefault`; no service-account token. |

## Lifecycle notes

- **A default gateway is chosen by annotation, in the operator's namespace only.** A `Wireguard`
  annotated `wireguard-operator.io/default: "true"` is the gateway that injected sidecars attach to,
  but only when it is in the namespace the operator runs in; the annotation anywhere else is ignored.
  Exactly one such `Wireguard` must exist for injection to run. See
  [injection.md](injection.md#the-default-gateway).
- **The server key is minted once.** The operator generates the key pair when the Secret does not
  exist and reuses it afterwards. Deleting the Secret makes the next reconcile mint a new key,
  and every client then needs the new public key.
- **Peer changes reach the server without a restart.** When the desired state changes, the
  operator rewrites `state.json` and stamps a `wgConfigLastUpdated` annotation on the server pods
  so the kubelet refreshes the mounted Secret sooner; the agent watches the file and applies the
  difference.
- **Set `peerCIDR` before you add peers.** Changing it re-allocates every peer whose address falls
  outside the new range, and a running server keeps its old `wg0` address until its pod is
  replaced.
- **Peers attach from any namespace by default.** The server lists the `WireguardPeer`s of every
  namespace that name it (`wireguardRef` plus `wireguardNamespace`), allocates their addresses from
  one `peerCIDR`, and copies its `status.endpoint`, `status.publicKey` and `spec.localCIDRs` into
  each admitted peer's status, so a client reads only its own peer. Set
  `allowedNamespaces.from: Same` to refuse every namespace but the server's own. Changing it takes
  effect on the next reconcile: peers it newly refuses lose their address and status copy, and
  peers it newly admits are allocated one.
- **Peers outlive their server.** Peers created by this operator version carry no
  ownerReference to their `Wireguard` and are not deleted with it. Peers created by an earlier
  version keep theirs.
- **Server-Side Apply.** The operator applies the Service and Deployment as field manager
  `wireguard-operator`. Fields it renders converge on every reconcile; fields it does not render,
  such as the Service's allocated `clusterIP`, are left alone.
- **Egress goes through gluetun, and fails closed.** Peer traffic leaves the pod only through
  gluetun's tunnel; see [gluetun-egress.md](gluetun-egress.md).
- **A referenced Secret that does not exist is not a spec error.** The reserved-variable check
  skips it. Unless the reference sets `optional: true`, the kubelet reports the missing Secret on
  the pod, so the `Wireguard` reads `Ready=False` until the Secret exists. With `optional: true`
  the pod starts without it.
