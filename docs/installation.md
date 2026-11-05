# Installation

## Prerequisites

- **A Kubernetes cluster, 1.34 or later,** and `kubectl` pointed at it. On 1.34 and 1.35 the API
  server must run with `--feature-gates=MutatingAdmissionPolicy=true` and
  `--runtime-config=admissionregistration.k8s.io/v1beta1=true`; 1.36 and later need neither,
  because MutatingAdmissionPolicy is GA and on by default there. This release does not yet create
  any admission policy; the requirement is set now so that the release that injects sidecars does
  not raise the minimum again. The envtest suite runs against Kubernetes 1.34.1 and the kind
  e2e on a 1.34.11 node, both with that beta enabled.
- **Privileged pods allowed in the gateway's namespace.** The server pod has a privileged `sysctl`
  init container, an `agent` container with `NET_ADMIN`, and a `gluetun` container with `NET_ADMIN`
  and a writable root filesystem; Pod Security `baseline` forbids the privileged container and the
  added capability. If your cluster enforces Pod Security admission, label that namespace
  `pod-security.kubernetes.io/enforce: privileged`.
- **Go 1.26 and `make`** on your workstation. `make deploy` regenerates the CRDs and RBAC and
  downloads `controller-gen` and `kustomize` into `./bin`.
- **Docker** — only if you build your own images.
- **`wireguard-tools`** — for `wg genkey` / `wg pubkey` when you register peers.

## Install from source

```sh
git clone https://github.com/jacaudi/wireguard-operator.git
cd wireguard-operator
make deploy IMG=ghcr.io/jacaudi/wireguard-operator/manager:latest
```

**`IMG` is required.** It is the manager image, and the [`Makefile`](../Makefile) defines no
default for it. `make deploy` writes it into
[`config/manager/kustomization.yaml`](../config/manager/kustomization.yaml), then applies
`config/default` — CRDs, RBAC and the manager — to the `wireguard-system` namespace, with every
name prefixed `wireguard-`.

The agent image is not `IMG`. The manager takes it as `--agent-image` and uses it for every server
pod;  [`config/default/manager_args_patch.yaml`](../config/default/manager_args_patch.yaml) sets to
`ghcr.io/jacaudi/wireguard-operator/agent:latest`.

CI publishes both images from `main` as `:latest` and `:sha-<short>`. No release is published yet,
so there is no `:v<version>` image to pin; use a `:sha-<short>` tag for anything you want to keep
stable.

> `make deploy` leaves `config/manager/kustomization.yaml` modified in your checkout. Run
> `git restore config/manager/kustomization.yaml` afterwards if you want a clean tree.

Check that the manager is up:

```sh
kubectl -n wireguard-system rollout status deployment/wireguard-controller-manager
```

### Build your own images

Set both image variables, build, push to a registry your cluster pulls from, write the agent image
into the manager's arguments, then deploy:

```sh
export AGENT_IMAGE=<registry>/wireguard-operator/agent:dev
export MANAGER_IMAGE=<registry>/wireguard-operator/manager:dev

make docker-build-agent docker-build-manager
docker push "$AGENT_IMAGE"
docker push "$MANAGER_IMAGE"

make update-agent-image            # renders $AGENT_IMAGE into config/default/manager_args_patch.yaml
make deploy IMG="$MANAGER_IMAGE"
```

`make update-agent-image` overwrites the tracked
`config/default/manager_args_patch.yaml` from its `.template`; `git restore` it afterwards. On kind,
`kind load docker-image "$AGENT_IMAGE" "$MANAGER_IMAGE"` replaces the two `docker push` lines.

### Run the manager on your workstation

`make install` applies only the CRDs. `make run` then starts the manager against your current
kubeconfig, but it passes no `--agent-image`, so the manager exits at startup. Run it directly
instead:

```sh
make install
go run ./cmd/manager/main.go --agent-image=ghcr.io/jacaudi/wireguard-operator/agent:latest
```

## Install with Helm (OCI)

Not yet available. Install from source (above). Tracked in
[#48](https://github.com/jacaudi/wireguard-operator/issues/48).

## Manager flags

Source of truth: [`cmd/manager/main.go`](../cmd/manager/main.go). `config/default` passes
`--health-probe-bind-address=:8081`, `--metrics-bind-address=:8080`, `--leader-elect` and
`--agent-image`.

| Flag | Default | Purpose |
|---|---|---|
| `--agent-image` | — | **Required.** Image for the server pod's `agent` and `sysctl` containers. Without it the manager exits at startup. |
| `--agent-image-pull-policy` | `IfNotPresent` | Pull policy for those two containers. |
| `--leader-elect` | `false` | Enable leader election (lease `a6d3bffc.wireguard-operator.io`). |
| `--leader-election-namespace` | `""` | Namespace for the lease. Empty → `POD_NAMESPACE`, then the pod's service-account namespace. |
| `--metrics-bind-address` | `:8080` | Metrics endpoint, behind Kubernetes authentication and authorization. |
| `--health-probe-bind-address` | `:8081` | `/healthz` and `/readyz`. |

controller-runtime's `--zap-*` logging flags are also accepted.

## Uninstall

Delete your `Wireguard` objects first; each one takes its Deployment, Service, Secret and peers
with it. Then remove the operator:

```sh
make undeploy
```

`make undeploy` deletes everything `config/default` renders, **including the CRDs**, so any
`Wireguard` or `WireguardPeer` still in the cluster is deleted too. To remove only the CRDs from a
workstation install, run `make uninstall`.
