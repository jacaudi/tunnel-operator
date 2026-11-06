# Installation

Check the [prerequisites](prerequisites.md) first: Kubernetes 1.34 or later (with the
`MutatingAdmissionPolicy` beta enabled on 1.34 and 1.35), Pod Security `privileged` for the
gateway's namespace, and Go 1.26 and `make` on your workstation.

## Install from source

```sh
git clone https://github.com/jacaudi/wireguard-operator.git
cd wireguard-operator
make deploy IMG=ghcr.io/jacaudi/wireguard-operator/manager:latest
```

**`IMG` is required.** It is the manager image, and the [`Makefile`](../Makefile) defines no
default for it. `make deploy` writes it into
[`config/manager/kustomization.yaml`](../config/manager/kustomization.yaml), then applies
`config/default` — the CRDs, RBAC, the manager and the injection backstop
(`ValidatingAdmissionPolicy` `wireguard-operator-require-injection`) — to the `wireguard-system`
namespace, with every name prefixed `wireguard-`.

The agent image is not `IMG`. The manager takes it as `--agent-image` and uses it for every server
pod and every injected sidecar;
[`config/default/manager_args_patch.yaml`](../config/default/manager_args_patch.yaml) sets it to
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

### Install into another namespace

`config/default` sets the namespace. To install into `network`, for example, change it before
`make deploy`:

```sh
make kustomize
(cd config/default && ../../bin/kustomize edit set namespace network)
make deploy IMG=ghcr.io/jacaudi/wireguard-operator/manager:latest
kubectl -n network rollout status deployment/wireguard-controller-manager
```

kustomize renames the rendered `Namespace` and every object in it, and points the role bindings at
the new namespace. The operator reads its namespace from `POD_NAMESPACE`, so nothing else changes,
except that the [default gateway](injection.md#the-default-gateway) must now live in `network`.
Keep the edit while the operator is installed: `make undeploy` renders the same files to know what
to delete.

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
instead. The manager also requires `POD_NAMESPACE`, the namespace it treats as its own (see
[injection.md](injection.md#the-default-gateway)); set it to the namespace you run it for:

```sh
make install
POD_NAMESPACE=wireguard-system go run ./cmd/manager/main.go --agent-image=ghcr.io/jacaudi/wireguard-operator/agent:latest
```

## Install with Helm (OCI)

Not yet available. Install from source (above).

## Manager flags

Source of truth: [`cmd/manager/main.go`](../cmd/manager/main.go). `config/default` passes
`--health-probe-bind-address=:8081`, `--metrics-bind-address=:8080`, `--leader-elect` and
`--agent-image`.

| Flag | Default | Purpose |
|---|---|---|
| `--agent-image` | — | **Required.** Image for the server pod's `agent` and `sysctl` containers, and for the client sidecar the operator injects into labelled pods. Without it the manager exits at startup. |
| `--agent-image-pull-policy` | `IfNotPresent` | Pull policy for those two server-pod containers. The injected sidecar sets none. |
| `--leader-elect` | `false` | Enable leader election (lease `a6d3bffc.wireguard-operator.io`). |
| `--leader-election-namespace` | `""` | Namespace for the lease. Empty → `POD_NAMESPACE`, which the manager requires. |
| `--metrics-bind-address` | `:8080` | Metrics endpoint, behind Kubernetes authentication and authorization. |
| `--health-probe-bind-address` | `:8081` | `/healthz` and `/readyz`. |

controller-runtime's `--zap-*` logging flags are also accepted.

## Uninstall

Delete your `Wireguard` objects first; each one takes its Deployment, Service and Secret with it.
Its peers stay: a sidecar's peer goes with its pod, and one you created by hand is yours to delete.
Then remove the operator:

```sh
make undeploy
```

`make undeploy` deletes everything `config/default` renders, **including the CRDs and the
operator's namespace**, so any `Wireguard` or `WireguardPeer` still in the cluster is deleted
too. To remove only the CRDs from a workstation install, run `make uninstall`.

The operator also writes objects at runtime that `make undeploy` and `kubectl delete -f release.yaml`
do not remove, because a cluster-scoped policy cannot be owned by the namespaced operator: the
sidecar-injection `MutatingAdmissionPolicy` and its binding, and a `RoleBinding` in each namespace
that had labelled pods. Remove them with:

```sh
kubectl delete mutatingadmissionpolicy,mutatingadmissionpolicybinding,rolebinding -A \
  -l app.kubernetes.io/managed-by=wireguard-operator
```

See [injection.md](injection.md#uninstall).
