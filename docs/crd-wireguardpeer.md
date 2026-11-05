# `WireguardPeer` reference

A client of a [`Wireguard`](crd-wireguard.md) server, identified by its public key. The operator
allocates the peer an address and the server's agent adds it to `wg0`. **Namespaced**, group
`vpn.wireguard-operator.io`, version `v1alpha1`, no short name. `kubectl get wireguardpeer` prints
`STATUS` (`.status.status`) and `AGE`.

Source of truth: [`api/v1alpha1/wireguardpeer_types.go`](../api/v1alpha1/wireguardpeer_types.go).
See [`examples/02-peer.yaml`](../examples/02-peer.yaml).

A [client sidecar](client-sidecar.md) creates its peer itself, named after its pod, with the pod as
its controller owner, so deleting the pod deletes the peer. A peer created by hand still works for
a hand-configured client.

## Spec

| Field | Type | Default | Description |
|---|---|---|---|
| `wireguardRef` | string | — | **Required**, minimum length 1. The name of the `Wireguard` this peer belongs to, in `wireguardNamespace`, or in the peer's own namespace when that is empty. |
| `wireguardNamespace` | string | — | The namespace of that `Wireguard`. Empty means the peer's own namespace. A DNS label, at most 63 characters. The `Wireguard` decides whether this namespace may attach: see [`allowedNamespaces`](crd-wireguard.md#spec). |
| `publicKey` | string | — | The peer's WireGuard public key, as printed by `wg pubkey`. Validated at admission as a canonical 32-byte base64 WireGuard key. To register a peer without a key, omit the field: an explicit `""` is rejected. Without a key the peer gets no address and the server does not admit it. |

> **The operator never mints, stores or reads a peer private key.** A client sidecar generates its
> key inside its pod and keeps it in the pod's memory-backed volume; a hand-configured client keeps
> it where it runs. Only the public half is registered.

## Status (operator-written)

| Field | Description |
|---|---|
| `status` | `pending`, `ready` or `error`. |
| `message` | Why the peer is in that state. See the table below. |
| `address` | The peer's IPv4 tunnel address, without a prefix length, allocated by the operator from the server's `peerCIDR`. The server routes `<address>/32` to this peer. Released when the peer loses its key, and re-allocated when it is not a usable host address inside the server's `peerCIDR`. |
| `endpoint` | The address the peer dials: the `Wireguard`'s `status.endpoint`, `<ClusterIP>:51820`. Copied by the operator once the peer is admitted, and cleared when it is not. |
| `serverPublicKey` | The `Wireguard`'s `status.publicKey`. Copied and cleared with `endpoint`. |
| `localCIDRs` | The `Wireguard`'s `spec.localCIDRs`, which the client keeps off the tunnel. Copied and cleared with `endpoint`. |
| `conditions` | Standard `metav1.Condition` list, keyed by `type`. Empty for a healthy peer. |

What each state means:

| `status` | `message` | Meaning |
|---|---|---|
| `pending` | `Waiting for spec.publicKey` | No `publicKey`; see `PublicKeyMissing` below. |
| `error` | `spec.publicKey is not a valid WireGuard key` | The stored key is not a canonical WireGuard key; see `InvalidPublicKey` below. |
| `pending` | `Waiting for wireguard resource '<ref>' to be created` | No `Wireguard` named `wireguardRef` exists in `wireguardNamespace` (the peer's own namespace when empty). |
| `error` | `Wireguard <namespace>/<name> does not accept peers from namespace <namespace>` | The `Wireguard` sets `spec.allowedNamespaces.from` to `Same` and the peer is in another namespace; see `NamespaceNotAllowed` below. |
| `pending` | `Address <ip> is held by peer <namespace>/<name>; waiting for a new address` | Another peer of the same server holds this peer's address and wins the dedupe (oldest `creationTimestamp`, smaller name and then namespace on a tie); see `AddressConflict` below. |
| `pending` | `Public key is held by peer <namespace>/<name>; waiting for it to be released` | Another peer of the same server holds this peer's `publicKey`; see `PublicKeyConflict` below. |
| `pending` | `No free address in <peerCIDR>` | The server's `peerCIDR` has no free address left. |
| `ready` | `Peer configured` | The peer is admitted with an address. The server's agent picks it up from the next `state.json` write. |

## Conditions

`Ready` is written only as `False`. The operator removes it once the peer is admitted.

| Type | Reason | Meaning |
|---|---|---|
| `Ready=False` | `PublicKeyMissing` | `spec.publicKey` is empty, so the server cannot admit this peer. |
| `Ready=False` | `InvalidPublicKey` | `spec.publicKey` is not a base64-encoded 32-byte WireGuard key, so the server cannot admit this peer. |
| `Ready=False` | `WireguardNotFound` | No `Wireguard` named `wireguardRef` exists in `wireguardNamespace`, or in the peer's namespace when that is empty. The message names the namespace it looked in. |
| `Ready=False` | `NamespaceNotAllowed` | The `Wireguard` admits only its own namespace (`allowedNamespaces.from: Same`), and the peer is in another. The peer is not allocated an address or handed to the server. |
| `Ready=False` | `AddressConflict` | Another peer holds this peer's address and is the one that wins the dedupe (oldest `creationTimestamp`, smaller name and then namespace on a tie). The peer gives its address up and is allocated a new one. |
| `Ready=False` | `PublicKeyConflict` | Another peer of the same server holds this peer's `publicKey`, and the message names it as `namespace/name`. This peer is not allocated an address, gets no copy of the gateway identity and is left out of the server's state, and it waits until the holder goes away. |
| `Ready=False` | `AddressPoolExhausted` | The server's `peerCIDR` has no free address for this peer. The server stays `ready` and keeps serving the peers that hold addresses. |

## Lifecycle notes

- **A peer can attach across namespaces.** Set `wireguardNamespace` and the peer, which stays in
  its own namespace and keeps its pod as owner, attaches to the `Wireguard` there. The server
  lists peers in every namespace, and one address pool covers them all, so no two peers of one
  server share an address whatever their namespace. Two servers with the same `peerCIDR` can hand
  out the same address. A `Wireguard` admits every namespace unless its
  `allowedNamespaces.from` says `Same`.
- **The server finds its peers by `wireguardRef` and `wireguardNamespace`.** Peers created by this operator version carry no
  ownerReference to their `Wireguard` and are not deleted with it. Peers created by an earlier
  version keep theirs. Deleting the server leaves peers created by this version in place, reading
  `pending` with `WireguardNotFound`.
- **Deleting a peer removes it from `wg0`.** The operator drops it from `state.json`, and the
  agent removes any device peer whose key is no longer listed.
- **One address, one peer.** If two peers of one server end up with the same
  `status.address`, the peer with the oldest `creationTimestamp` keeps it. Ties go to the smaller
  name, then the smaller namespace. The other peer reads `AddressConflict` and is allocated a new address.
- **One public key, one peer.** The agent keys peers by public key, so a server admits one peer per
  `publicKey`. The peer the server is already serving under that key keeps it, whatever its age or
  name, so editing a peer's key to another peer's cannot displace it. Only when no peer holds the
  key yet does the oldest `creationTimestamp` win, with ties to the smaller name and then
  namespace. Every other peer with that key reads `PublicKeyConflict`, whichever namespace it is in.
  It waits, and is promoted only when the holder goes away: it is deleted, changes its key, moves to
  another server, or is refused.
- **A malformed `publicKey` is rejected at admission.** The API refuses a key that is not a
  canonical 32-byte base64 WireGuard key, so it cannot stall the server. A key stored before that
  check reports `InvalidPublicKey` and is left out of the server's state.
  CRD validation ratcheting is always on from Kubernetes 1.33, so such a peer does not block its own
  status writes.
