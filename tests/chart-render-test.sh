#!/usr/bin/env sh
# Asserts `helm template` renders the manager Deployment, the two
# ServiceAccounts and the metrics Service the operator needs to start, the
# exact 15-object set, the CRDs and their keep annotation, the RBAC rules
# against config/rbac, and the VAP/VAPB specs against config/admission.
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


# The whole object set, exactly: a missing object (the client ClusterRole, the
# admission binding) or an extra one both fail here. Sorted in C locale on both
# sides so the comparison never depends on the runner's collation.
want_objects=$(printf '%s\n' \
  ClusterRole/tunnel-operator-client \
  ClusterRole/tunnel-operator-manager \
  ClusterRole/tunnel-operator-metrics-reader \
  ClusterRoleBinding/tunnel-operator-manager \
  ClusterRoleBinding/tunnel-operator-metrics-reader \
  CustomResourceDefinition/wireguardpeers.vpn.tunnel-operator.io \
  CustomResourceDefinition/wireguards.vpn.tunnel-operator.io \
  Deployment/tunnel-operator-manager \
  Role/tunnel-operator-leader-election \
  RoleBinding/tunnel-operator-leader-election \
  Service/tunnel-operator-metrics \
  ServiceAccount/tunnel-operator-manager \
  ServiceAccount/tunnel-operator-metrics-reader \
  ValidatingAdmissionPolicy/tunnel-operator-require-injection \
  ValidatingAdmissionPolicyBinding/tunnel-operator-require-injection | LC_ALL=C sort)
got_objects=$(yq -N 'select(.kind != null) | .kind + "/" + .metadata.name' "${out}" | LC_ALL=C sort)
check 'rendered object set' "${want_objects}" "${got_objects}"

# CRDs: kept on uninstall, and exactly the set in config/crd/bases (both ways,
# so a CRD added to config/ but not synced fails).
crd='.kind == "CustomResourceDefinition"'
check 'CRD names match config/crd/bases' \
  "$(yq -N '.metadata.name' config/crd/bases/*.yaml | LC_ALL=C sort)" \
  "$(yq -N "select(${crd}) | .metadata.name" "${out}" | LC_ALL=C sort)"
for n in wireguardpeers wireguards; do
  check "CRD ${n} resource-policy keep" '"keep"' \
    "$(q "${out}" "${crd} and .metadata.name == \"${n}.vpn.tunnel-operator.io\"" '.metadata.annotations["helm.sh/resource-policy"]')"
done

# $1 config/ source file, $2 yq expression: its rules or spec, normalised
# exactly like q().
src() {
  yq -o=json -I=0 "$2 | sort_keys(..)" "$1"
}

check 'ClusterRole manager rules' "$(src config/rbac/role.yaml .rules)" \
  "$(q "${out}" '.kind == "ClusterRole" and .metadata.name == "tunnel-operator-manager"' .rules)"
check 'Role leader-election rules' "$(src config/rbac/leader_election_role.yaml .rules)" \
  "$(q "${out}" '.kind == "Role" and .metadata.name == "tunnel-operator-leader-election"' .rules)"
check 'ClusterRole client rules' "$(src config/rbac/client_clusterrole.yaml .rules)" \
  "$(q "${out}" '.kind == "ClusterRole" and .metadata.name == "tunnel-operator-client"' .rules)"
check 'ClusterRole metrics-reader rules' "$(src config/rbac/metrics_reader_clusterrole.yaml .rules)" \
  "$(q "${out}" '.kind == "ClusterRole" and .metadata.name == "tunnel-operator-metrics-reader"' .rules)"

check 'ClusterRoleBinding manager subjects' '[{"kind":"ServiceAccount","name":"tunnel-operator-manager","namespace":"render-test"}]' \
  "$(q "${out}" '.kind == "ClusterRoleBinding" and .metadata.name == "tunnel-operator-manager"' .subjects)"
check 'ClusterRoleBinding manager roleRef' '{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"tunnel-operator-manager"}' \
  "$(q "${out}" '.kind == "ClusterRoleBinding" and .metadata.name == "tunnel-operator-manager"' .roleRef)"

check 'VAP spec' "$(src config/admission/require_injection_policy.yaml .spec)" \
  "$(q "${out}" '.kind == "ValidatingAdmissionPolicy"' .spec)"
check 'VAPB spec' "$(src config/admission/require_injection_binding.yaml '.spec | .policyName = "tunnel-operator-require-injection"')" \
  "$(q "${out}" '.kind == "ValidatingAdmissionPolicyBinding"' .spec)"

helm template "${rel}" "${chart}" -n "${ns}" \
  --set manager.image.tag=t1 --set agent.image.repository=r/a --set agent.image.tag=t2 > "${out2}"
check 'override manager image tag' '"ghcr.io/jacaudi/tunnel-operator/manager:t1"' "$(q "${out2}" "${dep}" "${c}.image")"
check 'override agent image arg' '"--agent-image=r/a:t2"' "$(q "${out2}" "${dep}" "${c}.args[3]")"

helm template "${rel}" "${chart}" -n "${ns}" \
  --set-json 'manager.resources={"requests":{"cpu":"1m"}}' > "${out3}"
check 'override resources' '{"requests":{"cpu":"1m"}}' "$(q "${out3}" "${dep}" "${c}.resources")"

exit "${fail}"
