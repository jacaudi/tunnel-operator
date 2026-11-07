# Prerequisites

Everything the cluster and your workstation need, and how to fill in a gateway's `localCIDRs`.

## Kubernetes 1.34 or later

The operator injects the client sidecar with a `MutatingAdmissionPolicy` (see
[injection.md](injection.md)). That API is GA and on by default from Kubernetes 1.36. On 1.34 and
1.35 it is beta and off, so the API server must run with both:

```text
--feature-gates=MutatingAdmissionPolicy=true
--runtime-config=admissionregistration.k8s.io/v1beta1=true
```

On a cluster without them the operator still runs, and labelled pods are rejected rather than run
untunnelled. The test suites run against Kubernetes 1.34.1 (envtest) and a 1.34.11 kind node, both
with the beta enabled. For a local [kind](https://kind.sigs.k8s.io/) cluster, this config sets both:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
featureGates:
  MutatingAdmissionPolicy: true
runtimeConfig:
  admissionregistration.k8s.io/v1beta1: "true"
```

```sh
kind create cluster --config kind.yaml --image kindest/node:v1.34.11
```

## Pod Security `privileged`

Two kinds of namespace need it, because both run containers with `NET_ADMIN`, which Pod Security
`baseline` forbids:

- **The gateway's namespace** — the server pod has a privileged `sysctl` init container, and its
  `agent` and `gluetun` containers add `NET_ADMIN`.
- **Every namespace with tunnelled pods** — the client sidecar adds `NET_ADMIN` to create `wg0` and
  replace the pod's routes. Pod Security evaluates the pod after injection, so a labelled pod in a
  `baseline` namespace is rejected.

If your cluster enforces Pod Security admission, label each of them:

```sh
kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=privileged
```

The operator never relaxes Pod Security itself.

## Workstation

- **`kubectl`** pointed at the cluster.
- **Helm 4** (tested with 4.3.1) — installs the operator from its OCI chart. See
  [installation.md](installation.md#install-with-helm-oci).
- **Go 1.26 and `make`** — only to install from source: `make deploy` regenerates the CRDs and RBAC
  and downloads `controller-gen` and `kustomize` into `./bin`. See
  [installation.md](installation.md#install-from-source).
- **Docker** — only to build your own images.
- **`wireguard-tools`** — only for `wg genkey` / `wg pubkey`, when you register a peer by hand.

## `localCIDRs`

Every `Wireguard` lists the cluster's own networks in `spec.localCIDRs`. Clients route these over the
CNI and everything else into the tunnel, and the server lets gluetun answer them over `eth0`. A
range you leave out is tunnelled: cluster traffic to it goes to the VPN provider and fails. The
operator does **not** discover them; collect them with the commands below. Use IPv4 ranges only: in
a dual-stack cluster, leave the IPv6 ones out.

**Service range.** `ServiceCIDR` is GA since Kubernetes 1.33, so every supported cluster has at
least the default object, named `kubernetes`; the `CIDRS` column lists the ranges:

```sh
kubectl get servicecidr
```

**Pod range.** When the control plane allocates node pod ranges, each node carries its slice:

```sh
kubectl get nodes -o jsonpath='{range .items[*]}{.spec.podCIDRs}{"\n"}{end}'
```

The slices belong to one cluster-wide range (for example `10.244.0.0/24` and `10.244.1.0/24` from
`10.244.0.0/16`); list that range, so nodes added later are covered. A CNI that manages its own IP
pools, such as Cilium in cluster-pool mode or Calico with IP pools, may leave `podCIDRs` empty or
allocate from other ranges. Then take the ranges from the CNI's own pool configuration.

**Node network.** The subnet your nodes' `INTERNAL-IP` addresses sit in:

```sh
kubectl get nodes -o wide
```

**NodeLocal DNSCache.** Add `169.254.20.10/32` if the cluster runs it.

### What the operator checks

Each entry must be a canonical IPv4 CIDR, overlap no part of `peerCIDR` and not contain `192.0.2.1`,
and one entry must hold the gateway Service's ClusterIP, so always list the Service range. A broken
rule sets `Degraded`, and the operator renders no server Deployment until it is fixed;
`kubectl describe wireguard <name> -n <namespace>` shows the reason and a message naming the entry,
or the Service and its ClusterIP. The reasons are in [crd-wireguard.md](crd-wireguard.md#spec); the
operator does **not** check the provider's tunnel range (see
[gluetun-egress.md](gluetun-egress.md#localcidrs)).
