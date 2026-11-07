# Sidecar injection

Label a workload's pod template `tunnel-operator.io/enabled: "true"` and every pod created from
it comes up with the [client sidecar](client-sidecar.md) already in place, attached to the cluster's
default gateway, with its internet traffic leaving through the VPN. Nobody pastes the sidecar block,
creates a `ServiceAccount` binding, or names a gateway. A labelled pod that cannot be tunnelled is
**rejected with a reason**; it never runs in the clear.
[`examples/injected-client.yaml`](../examples/injected-client.yaml) is a complete Deployment.

```yaml
template:
  metadata:
    labels:
      tunnel-operator.io/enabled: "true"
```

Only the value `"true"` opts a pod in. Both policies match pod creation only, so the label takes effect
when a pod is created: roll an existing workload for it to be injected. Labelling a running pod neither
injects nor rejects it, though it does make the operator create the namespace's `RoleBinding`.
Removing the label from a running injected pod is no safer: if it was the last labelled pod, the operator
deletes the namespace's `RoleBinding`, and that pod's sidecar keeps running but loses its API access. Roll
the workload instead of unlabelling running pods.

## How it works

Two admission policies, both evaluated by the API server. The operator runs no webhook and needs no
certificates.

| Policy | Written by | Does |
|---|---|---|
| `tunnel-operator-inject` (`MutatingAdmissionPolicy`, and its binding) | The operator, at runtime | Inserts the sidecar into each labelled pod |
| `tunnel-operator-require-injection` (`ValidatingAdmissionPolicy`, and its binding) | The Helm chart, generated from [`config/admission`](../config/admission); `make deploy` applies the source | Rejects a labelled pod that does not carry the sidecar |

The second is the fail-closed backstop. It is installed with the operator, so it protects the cluster
from install, before the operator has started, and it holds on a cluster that does not serve
`MutatingAdmissionPolicy`. Both policies skip any pod carrying the `tunnel-operator.io/component`
label (the gateway and the operator itself) and any pod in `kube-system`. The operator's own
namespace is not skipped, so a labelled workload there is injected.

Because admission runs in the API server, injection keeps working while the operator is down. Two
things wait for it: a change of default gateway, and the first labelled pod in a namespace, because the
operator creates that namespace's `RoleBinding` when the pod appears (the sidecar cannot register its
peer until then).

## The default gateway

Injected sidecars attach to the one `Wireguard` in **the operator's own namespace** annotated
`tunnel-operator.io/default: "true"`:

```sh
kubectl annotate wireguard vpn -n <operator-namespace> tunnel-operator.io/default=true
```

The operator learns its namespace from `POD_NAMESPACE`, which the manager Deployment sets through the
downward API, and exits at startup without it. The annotation on a `Wireguard` in any other
namespace is ignored, and the operator logs it. Choosing the default is therefore an act of whoever
controls the operator's namespace, never of a tenant who can edit a `Wireguard` elsewhere: a tenant
cannot steer every labelled pod through their own gateway, or break injection cluster-wide by
adding a second default.

With zero defaults, or more than one, the operator deletes `tunnel-operator-inject` and logs the
cause (no default, or the names of the defaults). Labelled pods are then rejected until exactly one
remains.

A namespace the default gateway does not allow through [`allowedNamespaces`](crd-wireguard.md) gets
its peers refused as usual, and the sidecar's startup probe keeps failing. The sidecar's log names
the reason.

## Prerequisites

Kubernetes 1.34 or later with `MutatingAdmissionPolicy` served, and Pod Security `privileged` in the
workload's namespace: see [prerequisites.md](prerequisites.md). Two details matter for injection:

- **The policy version follows the cluster.** The operator writes
  `admissionregistration.k8s.io/v1` when the cluster serves it, else `v1beta1`. When neither is
  served it writes nothing and logs that, and the backstop rejects labelled pods. It asks again every
  ten minutes, so enabling the beta later is picked up without restarting the operator.
- **No `hostNetwork`.** The sidecar refuses a pod in the host network, and so does
  the backstop.

## What gets injected

Exactly the sidecar of [`examples/client.yaml`](../examples/client.yaml), as the first init
container, so later init containers run inside the tunnel:

- container `wg-client` with `restartPolicy: Always`, running the operator's own agent image
  (`--agent-image`) as `agent client --wireguard <namespace>/<name>` for the default gateway;
- the downward-API environment `POD_NAME`, `POD_NAMESPACE`, `POD_UID`, `POD_IP` and `HOST_IP`, and
  `NET_ADMIN`;
- a memory-backed `emptyDir` volume `wg-key` at `/var/run/wireguard`;
- the startup probe `agent client --check`, which holds the application containers until the tunnel
  is up.

One thing differs from the example: a projected volume, `wg-token`, mounted read-only into `wg-client`
at `/var/run/secrets/kubernetes.io/serviceaccount`. It holds a `ServiceAccount` token, the cluster CA
and the namespace, so the sidecar can reach the API server whatever the pod's
`automountServiceAccountToken` says. The application containers never mount it. The pod's own
`serviceAccountName`, init containers and volumes are left as they are.

The operator also creates the client RBAC. When the first labelled pod appears in a namespace it
creates the `RoleBinding` `tunnel-operator-client` there, binding the `tunnel-operator-client`
`ClusterRole` to the group `system:serviceaccounts:<namespace>`, and it deletes the `RoleBinding`
after the last labelled pod is gone. It only touches a `RoleBinding` it labelled
`app.kubernetes.io/managed-by: tunnel-operator`: if another object already holds that name, it
leaves it alone, logs once for the namespace, and the pods there cannot register their peers.

## Rejections

A pod labelled `tunnel-operator.io/enabled=true` is refused at creation, by the backstop, when:

| Cause | Message |
|---|---|
| `hostNetwork: true` | `hostNetwork pods cannot be tunnelled` |
| `wg-client` is not the first init container with `restartPolicy: Always` | `the pod is labelled tunnel-operator.io/enabled=true but was not injected with the WireGuard sidecar. Check that exactly one Wireguard in the operator's namespace is annotated tunnel-operator.io/default=true, that the operator is running, and that the cluster serves MutatingAdmissionPolicy (Kubernetes 1.34 and 1.35 need the beta enabled). The operator's log names the cause.` |

For a Deployment, the refusal shows as a failed `ReplicaSet` event, not on the Deployment:

```sh
kubectl describe replicaset <name>
```

A pod that already carries a hand-written `wg-client` first, as in `examples/client.yaml`, is not
injected again and passes the backstop.

## Upgrades and restarts

- **The sidecar follows the operator.** The injected image is always the operator's `--agent-image`,
  so upgrading the operator upgrades the sidecar of every new pod. Running pods keep the sidecar they
  were created with until you roll them.
- **A restart of the operator changes nothing.** The policies stay in the cluster. On startup the
  operator reconciles them against the current default gateway, and removes the `RoleBinding` of any
  namespace whose labelled pods were deleted while it was down. It also recreates a `RoleBinding`
  deleted by hand while labelled pods run.
- **Gateway pods carry a label now.** The upgrade that introduced injection adds
  `tunnel-operator.io/component: gateway` to each gateway pod template, so each gateway rolls
  once.

## Trust model

The label is an opt-in by whoever can create pods in a namespace, and it is as strong as the
gateway's [`allowedNamespaces`](crd-wireguard.md): a labelled pod in a namespace the default
gateway admits can register a peer there. The default gateway is chosen only by whoever controls the
operator's namespace. A pod that is not labelled is never touched, and one that is labelled never
runs untunnelled.

## Uninstall

Uninstalling the operator removes the backstop, but not what the operator wrote at runtime: a
cluster-scoped policy cannot be owned by the namespaced operator, and the `RoleBinding`s sit in other
namespaces. [installation.md](installation.md#uninstall) has the command that removes them.

## Without injection

The unlabelled path is unchanged: add the sidecar block yourself, as in
[client-sidecar.md](client-sidecar.md#the-pod-spec). A pod that is not labelled is never injected.
