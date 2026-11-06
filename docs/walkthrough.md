# Walkthrough

From an empty cluster to a workload whose internet traffic leaves through your VPN provider. The
operator and its default gateway, `vpn`, run in `network`; the workload is a plain Deployment in
`default`, labelled for injection.

You need a cluster that meets the [prerequisites](prerequisites.md) (for a local kind cluster, use
the config there), an account with a VPN provider that [gluetun supports](https://github.com/qdm12/gluetun-wiki)
over WireGuard, and a clone of this repository as your working directory:

```sh
git clone https://github.com/jacaudi/wireguard-operator.git
cd wireguard-operator
```

## 1. Install the operator into `network`

```sh
make kustomize
(cd config/default && ../../bin/kustomize edit set namespace network)
make deploy IMG=ghcr.io/jacaudi/wireguard-operator/manager:latest
kubectl label namespace network pod-security.kubernetes.io/enforce=privileged
kubectl -n network rollout status deployment/wireguard-controller-manager
```

The install already refuses labelled pods, before any gateway exists: the backstop policy ships
with it.

```sh
kubectl get validatingadmissionpolicy wireguard-operator-require-injection
```

See [installation.md](installation.md#install-into-another-namespace) for what the namespace edit
changes.

## 2. Create the default gateway

Edit [`examples/01-server.yaml`](../examples/01-server.yaml):

- **`localCIDRs`** — replace the three placeholders with your cluster's pod, Service and node
  ranges. [Prerequisites](prerequisites.md#localcidrs) has the commands that find them.
- **The `vpn-provider` Secret** — replace `VPN_SERVICE_PROVIDER` and `WIREGUARD_PRIVATE_KEY` with
  your provider's values, and add any other gluetun variable your provider needs (for example
  `SERVER_COUNTRIES`). Leave the variables in
  [crd-wireguard.md](crd-wireguard.md#reserved-gluetun-variables) out; the operator sets them.

The file already carries `wireguard-operator.io/default: "true"`, so applied in `network` it becomes
the gateway injected pods attach to:

```sh
kubectl -n network apply -f examples/01-server.yaml
kubectl -n network get wireguard vpn
```

`STATUS` reads `pending` until gluetun has connected to your provider, then `ready`. If it reads
`error`, `kubectl -n network describe wireguard vpn` names the problem; most often a `localCIDRs`
entry. The operator now writes the injection policy:

```sh
kubectl get mutatingadmissionpolicy wireguard-operator-inject
```

## 3. Label a workload

[`examples/injected-client.yaml`](../examples/injected-client.yaml) is a plain Deployment, `app`,
whose pod template carries only the label `wireguard-operator.io/enabled: "true"`. Its container is
`curl`, kept running so you can test from it.

```sh
kubectl label namespace default pod-security.kubernetes.io/enforce=privileged
kubectl -n default apply -f examples/injected-client.yaml
kubectl -n default rollout status deployment/app
```

The rollout finishes once the sidecar's startup check passes: the tunnel has a handshake and the
pod's default route points into it.

## 4. Verify

**The pod was injected.** Its first init container is the sidecar:

```sh
kubectl -n default get pod -l app=app -o jsonpath='{.items[0].spec.initContainers[0].name}{"\n"}'
```

```text
wg-client
```

**The pod registered a peer** in its own namespace, named after the pod:

```sh
kubectl get wireguardpeer -A
```

```text
NAMESPACE   NAME                  STATUS   AGE
default     app-6d8f7c9b5-x2k4q   ready    40s
```

**Its traffic leaves through the VPN.** Ask any what's-my-IP service from the tunnelled pod, then
from a pod without the label:

```sh
kubectl -n default exec deploy/app -c app -- curl -s https://ifconfig.me
kubectl -n default run direct --rm -i --restart=Never --image=curlimages/curl:8.17.0 -- curl -s https://ifconfig.me
```

The first prints your VPN's exit address, the second your cluster's own. In-cluster names still
resolve from `app`, because cluster DNS is inside `localCIDRs`.

## 5. See it fail closed

Remove the default annotation. With no default gateway, the operator deletes its injection policy,
so a new labelled pod cannot be injected and the backstop refuses it:

```sh
kubectl -n network annotate wireguard vpn wireguard-operator.io/default-
kubectl -n default rollout restart deployment/app
kubectl -n default get events --field-selector reason=FailedCreate
```

The ReplicaSet's event carries the refusal:

```text
... the pod is labelled wireguard-operator.io/enabled=true but was not injected with the WireGuard
sidecar. Check that exactly one Wireguard in the operator's namespace is annotated
wireguard-operator.io/default=true, that the operator is running, and that the cluster serves
MutatingAdmissionPolicy (Kubernetes 1.34 and 1.35 need the beta enabled). The operator's log names
the cause.
```

The operator's log names the cause:

```sh
kubectl -n network logs deployment/wireguard-controller-manager | grep 'injection is off'
```

The running pod is not touched: the policies act only when a pod is created, and the rollout keeps
the old pod until a new one starts. Restore the annotation, and the ReplicaSet's next retry is
injected and the rollout completes:

```sh
kubectl -n network annotate wireguard vpn wireguard-operator.io/default=true
kubectl -n default rollout status deployment/app
```

The other refusals are listed in [injection.md](injection.md#rejections).

## 6. Clean up

```sh
kubectl -n default delete -f examples/injected-client.yaml
kubectl label namespace default pod-security.kubernetes.io/enforce-
make undeploy
kubectl delete mutatingadmissionpolicy,mutatingadmissionpolicybinding,rolebinding -A \
  -l app.kubernetes.io/managed-by=wireguard-operator
git restore config/default/kustomization.yaml config/manager/kustomization.yaml
```

Deleting the workload deletes its pods, their peers and, once the last labelled pod is gone, the
`RoleBinding` the operator made in `default`. `make undeploy` deletes the CRDs, and with them the
gateway, and the `network` namespace. The `kubectl delete` removes what the operator wrote at
runtime that nothing else owns ([why](installation.md#uninstall)). Run `git restore` last:
`make undeploy` needs the namespace edit to find what to delete.
