#!/usr/bin/env sh
# Check the invariants of the rendered manifests that no schema validator sees.
#
#   usage: chart-invariants.sh                              render both, check both
#          chart-invariants.sh check <rendered.yaml> <chart|kustomize>
#
# WHY THESE CHECKS: each is a failure that applies cleanly and breaks at runtime.
#
#   1. FAIL-OPEN BINDING. The admission binding names its policy only by a string.
#      A binding whose spec.policyName names a policy that was not rendered is
#      accepted by the API server, and then admits every pod it was meant to
#      refuse. Exactly one policy and one binding must exist, and they must agree.
#   2. CLIENT ROLE NAME. The operator writes a RoleBinding at runtime to the
#      ClusterRole named by resources.ClientRoleName, a literal in the Go source.
#      A render that names the role anything else installs cleanly and then breaks
#      every namespace with injected pods. The expected name is READ from the
#      source, not repeated here, so the two cannot drift apart.
#   3. NO NAMESPACE ON CLUSTER-SCOPED OBJECTS (chart mode only). Kustomize's
#      bundled v1.21.2 OpenAPI schema does not know the admission kinds are
#      cluster-scoped, so it stamps metadata.namespace on the policy and binding.
#      That is a property of the kustomize render, not a defect in it, so the
#      check applies to the chart alone.
#
# The no-argument form renders `helm template tunnel-operator charts -n
# invariant-check` and `bin/kustomize build config/default` into a temp dir and
# checks each in its own mode. It stops at the first failure.
#
# Each file is a multi-document stream, queried with `yq ea` and a select per
# kind. Never join documents with `+`: it builds a cross product.
#
# NO `cd` HERE, deliberately — the same trap chart-deps.sh documents. Every path
# resolves against $PWD, which is $GITHUB_WORKSPACE in CI and the repo root under
# Task.
#
# POSIX sh — runs identically on a runner and on macOS.
set -eu

usage() {
  echo "usage: chart-invariants.sh [check <rendered.yaml> <chart|kustomize>]" >&2
  exit 2
}

case $# in
  0) ;;
  3) [ "$1" = check ] || usage
     case $3 in chart|kustomize) ;; *) usage ;; esac ;;
  *) usage ;;
esac

# THE TOOL GUARDS ARE NOT CEREMONY. An absent yq would otherwise surface as a
# yq failure or an empty count, and the script would blame the MANIFESTS.
command -v yq >/dev/null || { echo "yq not installed: brew install yq" >&2; exit 1; }
if [ $# -eq 0 ]; then
  command -v helm >/dev/null || { echo "helm not installed" >&2; exit 1; }
  [ -x bin/kustomize ] || { echo "bin/kustomize not installed: make kustomize" >&2; exit 1; }
fi

fail() { echo "::error::$1" >&2; exit 1; }

check() {
  file=$1
  mode=$2

  # Check 1.
  policies=$(yq ea '[select(.kind == "ValidatingAdmissionPolicy")] | length' "${file}")
  bindings=$(yq ea '[select(.kind == "ValidatingAdmissionPolicyBinding")] | length' "${file}")
  [ "${policies}" = 1 ] && [ "${bindings}" = 1 ] ||
    fail "admission: want exactly one ValidatingAdmissionPolicy and one ValidatingAdmissionPolicyBinding in ${file}, got ${policies} and ${bindings}"
  policy=$(yq ea 'select(.kind == "ValidatingAdmissionPolicy") | .metadata.name' "${file}")
  bound=$(yq ea 'select(.kind == "ValidatingAdmissionPolicyBinding") | .spec.policyName' "${file}")
  [ "${bound}" = "${policy}" ] ||
    fail "admission: binding spec.policyName \"${bound}\" does not name the rendered policy \"${policy}\""

  # Check 2.
  # `|| true`: an unreadable source file takes the `fail` below, not sed's own error.
  role=$(sed -n 's/^const ClientRoleName = "\([^"]*\)".*$/\1/p' internal/resources/injection.go 2>/dev/null || true)
  case ${role} in
    ''|*'
'*) fail "cannot read ClientRoleName" ;;
  esac
  found=$(ROLE=${role} yq ea '[select(.kind == "ClusterRole" and .metadata.name == strenv(ROLE))] | length' "${file}")
  [ "${found}" != 0 ] ||
    fail "client-role: no ClusterRole named \"${role}\" in ${file}"

  # Check 3.
  if [ "${mode}" = chart ]; then
    # Collect, then `map`: NOT `+` (under `ea`, `.kind + "/" + .metadata.name`
    # evaluates each operand against the whole stream and prints a cross product,
    # measured as 16 copies of one line) and NOT a bare string after the select
    # (an empty select still emits that string once, a phantom failure on a clean
    # render). `map` over an empty array yields nothing.
    stray=$(yq ea '[select(.kind == "CustomResourceDefinition" or .kind == "ClusterRole" or .kind == "ClusterRoleBinding" or .kind == "ValidatingAdmissionPolicy" or .kind == "ValidatingAdmissionPolicyBinding") | select((.metadata.namespace // "") != "")] | map("::error::cluster-scoped: \(.kind)/\(.metadata.name) has metadata.namespace \(.metadata.namespace)") | .[]' "${file}")
    [ -z "${stray}" ] || { printf '%s\n' "${stray}" >&2; exit 1; }
  fi

  echo "ok: ${file} (${mode})"
}

if [ $# -eq 3 ]; then
  check "$2" "$3"
  exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT
helm template tunnel-operator charts -n invariant-check > "${tmp}/chart.yaml"
bin/kustomize build config/default > "${tmp}/kustomize.yaml"
check "${tmp}/chart.yaml" chart
check "${tmp}/kustomize.yaml" kustomize
