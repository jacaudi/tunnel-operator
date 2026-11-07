#!/usr/bin/env sh
# Asserts scripts/chart-invariants.sh accepts the rendered shape the operator
# depends on and refuses each way that shape can silently break.
#
# WHY THESE CASES: the two admission objects are linked only by a name string, so
# a binding that names a policy that was never rendered FAILS OPEN; the operator
# writes a RoleBinding at runtime to the literal client ClusterRole name, so a
# renamed role breaks every injected namespace; and a cluster-scoped object that
# carries metadata.namespace in the CHART is a rendering bug. Each bad-* fixture
# differs from good-chart.yaml in exactly the one way its name says
# (tests/fixtures/chart-invariants/), so a case that fails for the wrong reason
# is caught by the stderr needle, not just the exit code.
#
# kustomize-namespace-in-chart-mode and good-kustomize are a pair: the same file
# is correct under one mode and wrong under the other, which proves the mode
# argument is what switches check 3.
#
# NO `cd` HERE, deliberately: the script path and fixtures resolve against $PWD,
# the repo root, like the scripts themselves.
#
# `yq` is NOT stubbed: it is the thing being trusted to read the manifests.
#
# POSIX sh — runs identically on a runner and on macOS.
set -eu

script=scripts/chart-invariants.sh
fix=tests/fixtures/chart-invariants
fail=0

report() {
  desc=$1; want=$2; got=$3; needle=$4; out=$5
  if [ "${got}" != "${want}" ]; then
    printf 'FAIL %s: want exit=%s got=%s: %s\n' "${desc}" "${want}" "${got}" "${out}"
    fail=1
    return
  fi
  case "${out}" in
    *"${needle}"*) printf 'PASS %s\n' "${desc}" ;;
    *) printf 'FAIL %s: exit=%s but no "%s" in: %s\n' "${desc}" "${got}" "${needle}" "${out}"
       fail=1 ;;
  esac
}

# $1 case, $2 fixture, $3 mode, $4 want exit, $5 needle ("" matches anything).
# `if out=$( … )` rather than a bare substitution: under `set -e` the assignment
# inherits the substitution's status and the cases that correctly exit non-zero
# would abort this harness before printing a single result.
run_case() {
  if out=$( sh "${script}" check "${fix}/$2" "$3" 2>&1 ); then got=0; else got=$?; fi
  report "$1" "$4" "${got}" "$5" "${out}"
}

run_case good-chart                       good-chart.yaml                chart     0 ""
run_case good-kustomize                   good-kustomize.yaml            kustomize 0 ""
run_case kustomize-namespace-in-chart-mode good-kustomize.yaml           chart     1 "metadata.namespace"
run_case bad-policyname                   bad-policyname.yaml            chart     1 "policyName"
run_case bad-client-role                  bad-client-role.yaml           chart     1 "tunnel-operator-client"
run_case bad-namespaced-clusterrole       bad-namespaced-clusterrole.yaml chart    1 "metadata.namespace"
run_case bad-two-policies                 bad-two-policies.yaml          chart     1 "exactly one"

# --- missing tooling must say so ---------------------------------------------
# PATH is replaced with an EMPTY directory, not trimmed to system dirs: the
# runner installs yq at /usr/bin/yq, so a trimmed PATH would still find it and
# the case would pass for the wrong reason. The interpreter is named by ABSOLUTE
# path because a bare `sh` is itself unresolvable under the replaced PATH.
tmp=$(mktemp -d)
mkdir "${tmp}/bin"
if out=$( PATH="${tmp}/bin" /bin/sh "${script}" check "${fix}/good-chart.yaml" chart 2>&1 ); then got=0; else got=$?; fi
rm -rf "${tmp}"
report missing-yq 1 "${got}" "yq not installed" "${out}"

[ "${fail}" = 0 ] || exit 1
