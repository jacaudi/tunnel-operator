# Installation

Check the [prerequisites](prerequisites.md) first.

## Install with Helm (OCI)

The chart is published to GHCR as an OCI artifact. Pin `--version`: the images and the chart share
one version, and the chart's `appVersion` picks the matching images.

```sh
helm install tunnel-operator oci://ghcr.io/jacaudi/charts/tunnel-operator --version 0.1.0 -n network --create-namespace
kubectl label namespace network pod-security.kubernetes.io/enforce=privileged --overwrite
kubectl -n network rollout status deployment/tunnel-operator-manager
```

The label is the Pod Security step from the [prerequisites](prerequisites.md#pod-security-privileged):
the gateway's server pod needs `NET_ADMIN`, so the operator's namespace must allow `privileged`. The
operator reads its own namespace from the pod, so any `-n <namespace>` works, but the
[default gateway](injection.md#the-default-gateway) must then live in that namespace. These docs use
`network`. The commands here assume the release name `tunnel-operator`; another name changes the
Deployment's name.

The chart installs the CRDs, RBAC, the manager and the injection backstop
(`ValidatingAdmissionPolicy` `tunnel-operator-require-injection`).

**One install per cluster.** The CRDs, ClusterRoles, ClusterRoleBindings and the admission policy
are cluster-scoped and have fixed names (the operator itself depends on the names
`tunnel-operator-client` and `tunnel-operator-require-injection`), so a second release in another
namespace collides with the first.

**Tested with Helm 4** (4.3.1).

### Values

The chart has six values; everything else is fixed.

| Key | Default | Meaning |
|---|---|---|
| `manager.image.repository` | `ghcr.io/jacaudi/tunnel-operator/manager` | The manager's image repository. |
| `manager.image.tag` | `""` | The manager's image tag. Empty means `v` plus the chart's `appVersion`. |
| `manager.image.pullPolicy` | `IfNotPresent` | The manager container's pull policy. |
| `manager.resources` | `{}` | The manager's resources. Empty means requests of `10m` CPU and `64Mi` memory, and limits of `500m` CPU and `128Mi` memory. |
| `agent.image.repository` | `ghcr.io/jacaudi/tunnel-operator/agent` | The agent's image repository. The manager injects this image as the client sidecar and runs it in every server pod; the chart passes it as `--agent-image`. |
| `agent.image.tag` | `""` | The agent's image tag. Empty means `v` plus the chart's `appVersion`. |

For example, to pin the manager to a different image tag:

```sh
helm install tunnel-operator oci://ghcr.io/jacaudi/charts/tunnel-operator --version 0.1.0 -n network --create-namespace \
  --set manager.image.tag=v0.1.0
```

## Install from source

The developer path: it builds the manifests from this checkout with kustomize and needs Go 1.26 and
`make`. Most users want the Helm chart above.

```sh
git clone https://github.com/jacaudi/tunnel-operator.git
cd tunnel-operator
make deploy IMG=ghcr.io/jacaudi/tunnel-operator/manager:latest
```

**`IMG` is required.** It is the manager image, and the [`Makefile`](../Makefile) defines no
default for it. `make deploy` writes it into
[`config/manager/kustomization.yaml`](../config/manager/kustomization.yaml), then applies
`config/default` — the CRDs, RBAC, the manager and the injection backstop
(`ValidatingAdmissionPolicy` `tunnel-operator-require-injection`) — to the `tunnel-system`
namespace, with every name prefixed `tunnel-`.

The agent image is not `IMG`. The manager takes it as `--agent-image` and uses it for every server
pod and every injected sidecar;
[`config/default/manager_args_patch.yaml`](../config/default/manager_args_patch.yaml) sets it to
`ghcr.io/jacaudi/tunnel-operator/agent:latest`.

CI publishes both images from `main` as `:latest` and `:sha-<short>`, and each release as
`:v<version>` (for example `:v0.1.0`). Pin a `:v<version>` tag, or a `:sha-<short>` tag, for anything
you want to keep stable.

> `make deploy` leaves `config/manager/kustomization.yaml` modified in your checkout. Run
> `git restore config/manager/kustomization.yaml` afterwards if you want a clean tree.

Check that the manager is up:

```sh
kubectl -n tunnel-system rollout status deployment/tunnel-controller-manager
```

### Install into another namespace

`config/default` sets the namespace. To install into `network`, for example, change it before
`make deploy`:

```sh
make kustomize
(cd config/default && ../../bin/kustomize edit set namespace network)
make deploy IMG=ghcr.io/jacaudi/tunnel-operator/manager:latest
kubectl -n network rollout status deployment/tunnel-controller-manager
```

> **`make undeploy` deletes the install namespace and everything in it**, because `config/default`
> renders the `Namespace` object. If `network` holds other workloads, uninstall with the
> [namespace-preserving command](#uninstalling-a-source-install) instead.

kustomize renames the rendered `Namespace` and every object in it, and points the role bindings at
the new namespace. The operator reads its namespace from `POD_NAMESPACE`, so nothing else changes,
except that the [default gateway](injection.md#the-default-gateway) must now live in `network`.
Keep the edit while the operator is installed: uninstalling renders the same files to know what to
delete.

### Build your own images

Set both image variables, build, push to a registry your cluster pulls from, write the agent image
into the manager's arguments, then deploy:

```sh
export AGENT_IMAGE=<registry>/tunnel-operator/agent:dev
export MANAGER_IMAGE=<registry>/tunnel-operator/manager:dev

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
POD_NAMESPACE=tunnel-system go run ./cmd/manager/main.go --agent-image=ghcr.io/jacaudi/tunnel-operator/agent:latest
```

## Manager flags

Source of truth: [`cmd/manager/main.go`](../cmd/manager/main.go). `config/default` and the chart pass
`--health-probe-bind-address=:8081`, `--metrics-bind-address=:8080`, `--leader-elect` and
`--agent-image`.

| Flag | Default | Purpose |
|---|---|---|
| `--agent-image` | — | **Required.** Image for the server pod's `agent` and `sysctl` containers, and for the client sidecar the operator injects into labelled pods. Without it the manager exits at startup. |
| `--agent-image-pull-policy` | `IfNotPresent` | Pull policy for those two server-pod containers. The injected sidecar sets none. |
| `--leader-elect` | `false` | Enable leader election (lease `a6d3bffc.tunnel-operator.io`). |
| `--leader-election-namespace` | `""` | Namespace for the lease. Empty → `POD_NAMESPACE`, which the manager requires. |
| `--metrics-bind-address` | `:8080` | Metrics endpoint, behind Kubernetes authentication and authorization. |
| `--health-probe-bind-address` | `:8081` | `/healthz` and `/readyz`. |

controller-runtime's `--zap-*` logging flags are also accepted.

## Uninstall

1. **Delete your `Wireguard` objects.** Each one takes its Deployment, Service and Secret with it. Its
   peers stay: a sidecar's peer goes with its pod, and one you created by hand is yours to delete.
2. **Uninstall the release:**

   ```sh
   helm uninstall tunnel-operator -n network
   ```

   This leaves the namespace, which the chart never deletes. It also leaves the CRDs and every
   `Wireguard` and `WireguardPeer` still in the cluster, because the CRDs carry
   `helm.sh/resource-policy: keep`.
3. **Remove the runtime-written objects.** The operator writes objects at runtime that Helm does not
   own, because a cluster-scoped policy cannot be owned by the namespaced operator: the
   sidecar-injection `MutatingAdmissionPolicy` and its binding, and a `RoleBinding` in each namespace
   that had labelled pods. Remove them with:

   ```sh
   kubectl delete mutatingadmissionpolicy,mutatingadmissionpolicybinding,rolebinding -A \
     -l app.kubernetes.io/managed-by=tunnel-operator
   ```

4. **Optionally, remove the CRDs:**

   ```sh
   kubectl delete crd wireguards.vpn.tunnel-operator.io wireguardpeers.vpn.tunnel-operator.io
   ```

   **This deletes every remaining `Wireguard` and `WireguardPeer` in the cluster.**

### Reinstalling, or moving from `make deploy`

Helm refuses to adopt an existing object unless it carries the label
`app.kubernetes.io/managed-by: Helm` and the annotations `meta.helm.sh/release-name` and
`meta.helm.sh/release-namespace` that match the release being installed. Two cases hit this:

- **Reinstalling under another release name or namespace.** The CRDs `helm uninstall` kept belong to
  the old release, so the new `helm install` fails on them. To hand them to the new release, keeping
  them and every custom resource, run:

  ```sh
  kubectl label crd wireguards.vpn.tunnel-operator.io wireguardpeers.vpn.tunnel-operator.io \
    app.kubernetes.io/managed-by=Helm --overwrite
  kubectl annotate crd wireguards.vpn.tunnel-operator.io wireguardpeers.vpn.tunnel-operator.io \
    meta.helm.sh/release-name=<release> meta.helm.sh/release-namespace=<ns> --overwrite
  ```

  Reinstalling under the same release name and namespace needs neither.
- **Moving from a source install.** The objects `make deploy` created carry no Helm metadata, so a
  first `helm install` fails on them. Run `make undeploy` first (see below). It deletes the CRDs and
  every `Wireguard` and `WireguardPeer` with them.

### Uninstalling a source install

Delete your `Wireguard` objects first, as in step 1 above. Then remove the operator:

```sh
make undeploy
```

`make undeploy` deletes everything `config/default` renders, **including the CRDs and the
operator's namespace with everything in it**, so any `Wireguard` or `WireguardPeer` still in the
cluster is deleted too. To keep the namespace, delete the same objects without the `Namespace`:

```sh
bin/kustomize build config/default |
  awk '/^---$/{if(!ns)printf "%s",d; d=""; ns=0} {d=d $0 "\n"} /^kind: Namespace$/{ns=1} END{if(!ns)printf "%s",d}' |
  kubectl delete -f -
```

To remove only the CRDs from a workstation install, run `make uninstall`.

Then remove the runtime-written objects with the command in step 3 above; neither `make undeploy`
nor the namespace-preserving command removes them.
