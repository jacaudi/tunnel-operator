#!/usr/bin/env sh
# Asserts `helm template` renders the manager Deployment, the two
# ServiceAccounts and the metrics Service the operator needs to start.
#
# WHY THESE FIELDS: each one is a way the manager silently fails to run or
# fails to reach the API. automountServiceAccountToken defaults to FALSE in
# bjw-s common v5, so without the explicit override the pod has no token;
# POD_NAMESPACE and --agent-image are read at startup and the manager exits
# without them; fsGroup/runAsUser/readOnlyRootFilesystem mirror config/manager.
#
# The default image tag is COMPUTED from Chart.yaml's appVersion, never
# hard-coded: release-please rewrites appVersion on every release PR and this
# test runs in CI, so a literal would break the release PR it should gate.
#
# NO `cd` HERE, deliberately: the chart path resolves against $PWD, the repo
# root, like the scripts themselves.
#
# POSIX sh — runs identically on a runner and on macOS.
set -eu

chart=charts
rel=tunnel-operator
ns=render-test
fail=0
out=$(mktemp)
out2=$(mktemp)
out3=$(mktemp)
trap 'rm -f "${out}" "${out2}" "${out3}"' EXIT

# $1 description, $2 want, $3 got.
check() {
  if [ "$3" = "$2" ]; then
    printf 'PASS %s\n' "$1"
  else
    printf 'FAIL %s: want %s got %s\n' "$1" "$2" "$3"
    fail=1
  fi
}

# $1 file, $2 yq selector for one document, $3 yq expression on it. Compact,
# key-sorted JSON so object comparisons do not depend on render order.
q() {
  yq -o=json -I=0 "select($2) | $3 | sort_keys(..)" "$1"
}

if ! helm template "${rel}" "${chart}" -n "${ns}" > "${out}"; then
  printf 'FAIL helm template %s\n' "${chart}"
  exit 1
fi

V=v$(yq '.appVersion' "${chart}/Chart.yaml" | sed 's/^v//')

dep='.kind == "Deployment" and .metadata.name == "tunnel-operator-manager"'
pod='.spec.template'
c="${pod}.spec.containers[0]"

check 'deployment namespace' '"render-test"' "$(q "${out}" "${dep}" .metadata.namespace)"
check 'deployment replicas' 1 "$(q "${out}" "${dep}" .spec.replicas)"
check 'deployment strategy' '"RollingUpdate"' "$(q "${out}" "${dep}" .spec.strategy.type)"

check 'pod automountServiceAccountToken' true "$(q "${out}" "${dep}" "${pod}.spec.automountServiceAccountToken")"
check 'pod serviceAccountName' '"tunnel-operator-manager"' "$(q "${out}" "${dep}" "${pod}.spec.serviceAccountName")"
check 'pod terminationGracePeriodSeconds' 10 "$(q "${out}" "${dep}" "${pod}.spec.terminationGracePeriodSeconds")"
check 'pod securityContext' '{"fsGroup":65534,"runAsNonRoot":true}' "$(q "${out}" "${dep}" "${pod}.spec.securityContext")"
check 'pod component label' '"operator"' "$(q "${out}" "${dep}" "${pod}.metadata.labels[\"tunnel-operator.io/component\"]")"
check 'pod default-container annotation' '"manager"' "$(q "${out}" "${dep}" "${pod}.metadata.annotations[\"kubectl.kubernetes.io/default-container\"]")"

check 'one container' 1 "$(q "${out}" "${dep}" "${pod}.spec.containers | length")"
check 'container name' '"manager"' "$(q "${out}" "${dep}" "${c}.name")"
check 'container image' "\"ghcr.io/jacaudi/tunnel-operator/manager:${V}\"" "$(q "${out}" "${dep}" "${c}.image")"
check 'container imagePullPolicy' '"IfNotPresent"' "$(q "${out}" "${dep}" "${c}.imagePullPolicy")"
check 'container command' '["/manager"]' "$(q "${out}" "${dep}" "${c}.command")"
check 'container args' "[\"--health-probe-bind-address=:8081\",\"--metrics-bind-address=:8080\",\"--leader-elect\",\"--agent-image=ghcr.io/jacaudi/tunnel-operator/agent:${V}\"]" "$(q "${out}" "${dep}" "${c}.args")"
check 'container env' '[{"name":"POD_NAMESPACE","valueFrom":{"fieldRef":{"fieldPath":"metadata.namespace"}}}]' "$(q "${out}" "${dep}" "${c}.env")"
check 'container securityContext' '{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsGroup":65534,"runAsUser":65534}' "$(q "${out}" "${dep}" "${c}.securityContext")"
check 'container livenessProbe' '{"httpGet":{"path":"/healthz","port":8081},"initialDelaySeconds":15,"periodSeconds":20}' "$(q "${out}" "${dep}" "${c}.livenessProbe")"
check 'container readinessProbe' '{"httpGet":{"path":"/readyz","port":8081},"initialDelaySeconds":5,"periodSeconds":10}' "$(q "${out}" "${dep}" "${c}.readinessProbe")"
check 'container resources default' '{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}}' "$(q "${out}" "${dep}" "${c}.resources")"

check 'ServiceAccount manager' '"tunnel-operator-manager"' "$(q "${out}" '.kind == "ServiceAccount" and .metadata.name == "tunnel-operator-manager"' .metadata.name)"
check 'ServiceAccount metrics-reader' '"tunnel-operator-metrics-reader"' "$(q "${out}" '.kind == "ServiceAccount" and .metadata.name == "tunnel-operator-metrics-reader"' .metadata.name)"

svc='.kind == "Service" and .metadata.name == "tunnel-operator-metrics"'
check 'Service metrics port' '{"name":"metrics","port":8080,"protocol":"TCP"}' "$(q "${out}" "${svc}" '.spec.ports[0] | pick(["name","port","protocol"])')"

check 'no Namespace object' 0 "$(yq 'select(.kind == "Namespace") | .kind' "${out}" | wc -l | tr -d ' ')"

helm template "${rel}" "${chart}" -n "${ns}" \
  --set manager.image.tag=t1 --set agent.image.repository=r/a --set agent.image.tag=t2 > "${out2}"
check 'override manager image tag' '"ghcr.io/jacaudi/tunnel-operator/manager:t1"' "$(q "${out2}" "${dep}" "${c}.image")"
check 'override agent image arg' '"--agent-image=r/a:t2"' "$(q "${out2}" "${dep}" "${c}.args[3]")"

helm template "${rel}" "${chart}" -n "${ns}" \
  --set-json 'manager.resources={"requests":{"cpu":"1m"}}' > "${out3}"
check 'override resources' '{"requests":{"cpu":"1m"}}' "$(q "${out3}" "${dep}" "${c}.resources")"

exit "${fail}"
