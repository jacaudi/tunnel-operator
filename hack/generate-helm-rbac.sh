#!/usr/bin/env bash
# Generates the chart's RBAC values (bjw-s rbac.roles / rbac.bindings) from
# config/rbac/.
#
# Usage: ./hack/generate-helm-rbac.sh    (scripts/chart-drift.sh runs it in CI)
#
# WHY: the manager's ClusterRole is written by controller-gen from the
# kubebuilder markers; the others are hand-written beside it. The chart takes
# only their `rules`, so the rules cannot drift from config/.
#
# Every cluster-scoped object uses forceRename, so its name never depends on the
# release name. That matters for tunnel-operator-client: the operator binds it
# by that literal name at runtime (resources.ClientRoleName), and its own RBAC
# rule only allows binding that name.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${root}/config/rbac"
out="${root}/charts/templates/_values-rbac.tpl"

command -v yq >/dev/null || { echo "::error::yq is required (brew install yq)" >&2; exit 1; }

# $1 role id, $2 type, $3 source file, $4 forceRename (empty: none, the name is
# fullname + id like the Role's).
role() {
  echo "    $1:"
  echo "      type: $2"
  [ -z "$4" ] || echo "      forceRename: $4"
  echo "      rules:"
  yq '.rules | ... comments=""' "${src}/$3" | sed 's/^/        /'
}

{
  cat <<'EOF'
{{/*
AUTO-GENERATED from config/rbac/ by hack/generate-helm-rbac.sh — DO NOT EDIT
*/}}
{{- define "tunnel-operator.values.rbac" -}}
rbac:
  roles:
EOF
  role manager ClusterRole role.yaml tunnel-operator-manager
  role leader-election Role leader_election_role.yaml ""
  role client ClusterRole client_clusterrole.yaml tunnel-operator-client
  role metrics-reader ClusterRole metrics_reader_clusterrole.yaml tunnel-operator-metrics-reader
  cat <<'EOF'
  bindings:
    manager:
      type: ClusterRoleBinding
      forceRename: tunnel-operator-manager
      roleRef:
        identifier: manager
      subjects:
        - identifier: manager
    leader-election:
      type: RoleBinding
      roleRef:
        identifier: leader-election
      subjects:
        - identifier: manager
    metrics-reader:
      type: ClusterRoleBinding
      forceRename: tunnel-operator-metrics-reader
      roleRef:
        identifier: metrics-reader
      subjects:
        - identifier: metrics-reader
{{- end -}}
EOF
} > "${out}"

echo "Generated ${out#"${root}"/} from config/rbac/"
