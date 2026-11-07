# Walkthrough

From an empty cluster to a workload whose internet traffic leaves through your VPN provider. The
operator and its default gateway, `vpn`, run in `network`; the workload is a plain Deployment in
`default`, labelled for injection.

You need a cluster that meets the [prerequisites](prerequisites.md) (for a local kind cluster, use
the config there), an account with a VPN provider that [gluetun supports](https://github.com/qdm12/gluetun-wiki)
over WireGuard, and a clone of this repository as your working directory:

```sh
git clone https://github.com/jacaudi/tunnel-operator.git
cd tunnel-operator
```

## 1. Install the operator into `network`

```sh
helm install tunnel-operator oci://ghcr.io/jacaudi/charts/tunnel-operator --version 0.1.0 -n network --create-namespace
kubectl label namespace network pod-security.kubernetes.io/enforce=privileged --overwrite
kubectl -n network rollout status deployment/tunnel-operator-manager
```

The install already refuses labelled pods, before any gateway exists: the backstop policy comes
with it.

```sh
kubectl get validatingadmissionpolicy tunnel-operator-require-injection
```

## 2. Create the default gateway

Copy [`examples/01-server.yaml`](../examples/01-server.yaml) out of the clone, so your provider key
never sits in it:

```sh
cp examples/01-server.yaml ~/vpn-gateway.yaml
```

Then edit the copy:

- **`localCIDRs`** — replace the three placeholders with your cluster's pod, Service and node
  ranges. [Prerequisites](prerequisites.md#localcidrs) has the commands that find them.
- **The `vpn-provider` Secret** — replace `VPN_SERVICE_PROVIDER` and `WIREGUARD_PRIVATE_KEY` with
  your provider's values, and add any other gluetun variable your provider needs (for example
  `SERVER_COUNTRIES`). Leave the variables in
  [crd-wireguard.md](crd-wireguard.md#reserved-gluetun-variables) out; the operator sets them.

The file carries `tunnel-operator.io/default: "true"`, so applied in `network` it becomes the
gateway injected pods attach to. Apply it and wait until gluetun has connected to your provider:

```sh
kubectl -n network apply -f ~/vpn-gateway.yaml
kubectl -n network wait wireguard/vpn --for=jsonpath='{.status.status}'=ready --timeout=10m
```

If it reads `error` instead, `kubectl -n network describe wireguard vpn` names the problem; most
often a `localCIDRs` entry. The operator now writes the injection policy:

```sh
kubectl get mutatingadmissionpolicy tunnel-operator-inject
```

## 3. Label a workload

[`examples/injected-client.yaml`](../examples/injected-client.yaml) is a plain Deployment, `app`,
whose pod template carries only the label `tunnel-operator.io/enabled: "true"`. Its container is
`curl`, kept running so you can test from it.

```sh
kubectl label namespace default pod-security.kubernetes.io/enforce=privileged --overwrite
kubectl -n default apply -f examples/injected-client.yaml
kubectl -n default rollout status deployment/app
```

The rollout finishes once the sidecar's startup check passes: the tunnel has a handshake and the
pod's default route points into it.

## 4. Verify

**The pod registered a peer** in its own namespace, named after the pod. Only the injected sidecar
creates it:

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

Remove the default annotation and wait for the operator to delete its injection policy. A labelled
pod then cannot be injected, and the backstop refuses it. A server-side dry run shows the refusal
without creating anything:

```sh
kubectl -n network annotate wireguard vpn tunnel-operator.io/default-
kubectl wait --for=delete mutatingadmissionpolicy/tunnel-operator-inject --timeout=1m
kubectl -n default run refused --image=curlimages/curl:8.17.0 \
  --labels=tunnel-operator.io/enabled=true --dry-run=server -- true
```

```text
... the pod is labelled tunnel-operator.io/enabled=true but was not injected with the WireGuard
sidecar. Check that exactly one Wireguard in the operator's namespace is annotated
tunnel-operator.io/default=true, that the operator is running, and that the cluster serves
MutatingAdmissionPolicy (Kubernetes 1.34 and 1.35 need the beta enabled). The operator's log names
the cause.
```

If it is admitted, the API server has not caught up with the deleted policy yet; wait a few seconds
and re-run it. The running `app` pod is not touched: the policies act only when a pod is created.
Restore the annotation, and the operator writes the policy again:

```sh
kubectl -n network annotate wireguard vpn tunnel-operator.io/default=true
kubectl get mutatingadmissionpolicy tunnel-operator-inject
```

The other refusals are listed in [injection.md](injection.md#rejections).

## 6. Clean up

```sh
kubectl -n default delete -f examples/injected-client.yaml
kubectl label namespace default pod-security.kubernetes.io/enforce-
kubectl -n network delete -f ~/vpn-gateway.yaml
helm uninstall tunnel-operator -n network
kubectl delete mutatingadmissionpolicy,mutatingadmissionpolicybinding,rolebinding -A \
  -l app.kubernetes.io/managed-by=tunnel-operator
kubectl label namespace network pod-security.kubernetes.io/enforce-
rm ~/vpn-gateway.yaml
```

`helm uninstall` leaves the `network` namespace and, by design, the two CRDs. To remove the CRDs
too, and to reinstall under another release name or namespace, see
[installation.md](installation.md#uninstall).
