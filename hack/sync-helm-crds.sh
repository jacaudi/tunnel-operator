#!/usr/bin/env bash
# Copies the CRDs and the admission policy/binding from config/ into the chart.
#
# Usage: ./hack/sync-helm-crds.sh        (scripts/chart-drift.sh runs it in CI)
#
# WHY: config/ is the source of truth (controller-gen writes the CRDs, the
# admission objects are hand-written). A chart that carries its own copy
# silently falls behind it, so the chart's copy is generated and the drift gate
# fails on any difference.
#
#   - CRDs go to charts/templates/crds/ as plain templates (not Helm's crds/
#     directory, which is never upgraded) with `helm.sh/resource-policy: keep`
#     so `helm uninstall` leaves the CRs' definitions, and the CRs, in place.
#   - The ValidatingAdmissionPolicy and its binding go into a values helper as
#     bjw-s rawResources. Both are named by one helper, because they are linked
#     only by that string; a binding naming a policy that is not rendered fails
#     open.
#
# Everything is rewritten from scratch, so a second run changes nothing.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crd_src="${root}/config/crd/bases"
crd_dst="${root}/charts/templates/crds"
adm_src="${root}/config/admission"
adm_out="${root}/charts/templates/_values-admission.tpl"

command -v yq >/dev/null || { echo "::error::yq is required (brew install yq)" >&2; exit 1; }

# Helm would evaluate a `{{` in any of these as a template action.
for f in "${crd_src}"/*.yaml "${adm_src}/require_injection_policy.yaml" "${adm_src}/require_injection_binding.yaml"; do
  if grep -q '{{' "${f}"; then
    echo "::error::${f#"${root}"/} contains '{{', which Helm would evaluate" >&2
    exit 1
  fi
done

mkdir -p "${crd_dst}"
for f in "${crd_dst}"/*.yaml; do
  [ -e "${f}" ] || continue
  [ -e "${crd_src}/$(basename "${f}")" ] || rm "${f}"
done
for f in "${crd_src}"/*.yaml; do
  yq '.metadata.annotations."helm.sh/resource-policy" = "keep"' "${f}" > "${crd_dst}/$(basename "${f}")"
done

# $1 source file: its manifest without metadata (the rawResource's name comes
# from forceRename) or comments, indented under `manifest:`.
manifest() {
  yq '... comments="" | del(.metadata)' "$1" | sed 's/^/      /'
}

{
  cat <<'EOF'
{{/*
AUTO-GENERATED from config/admission/ by hack/sync-helm-crds.sh — DO NOT EDIT
*/}}
{{- define "tunnel-operator.values.admission" -}}
rawResources:
  require-injection-policy:
    forceRename: {{ include "tunnel-operator.requireInjectionName" . }}
    manifest:
EOF
  manifest "${adm_src}/require_injection_policy.yaml"
  cat <<'EOF'
  require-injection-binding:
    forceRename: {{ include "tunnel-operator.requireInjectionName" . }}
    manifest:
EOF
  # The binding's policyName must be the same helper, not the source's literal.
  manifest "${adm_src}/require_injection_binding.yaml" |
    sed 's/^\( *policyName:\) .*/\1 {{ include "tunnel-operator.requireInjectionName" . }}/'
  echo '{{- end -}}'
} > "${adm_out}"

echo "Synced ${crd_dst#"${root}"/} and ${adm_out#"${root}"/} from config/"
