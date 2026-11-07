#!/usr/bin/env sh
# Asserts scripts/chart-release-version.sh accepts a chart whose appVersion is
# the release and refuses every other shape.
#
# WHY THESE CASES: release-please bumps appVersion through an x-release-please
# marker. A missed marker would publish chart X.Y.Z rendering the PREVIOUS
# images, and the image-existence gate cannot see it because those tags exist.
# The v-prefix cases pin the comparison to the same normalisation chart-appversion.sh
# applies: appVersion may be written with or without a leading `v`, and the
# release version arrives bare. The absent-key case matters because yq prints the
# string `null` for a missing key, which an emptiness check alone lets through.
#
# Each case runs against its own throwaway chart directory holding only a
# Chart.yaml, so a case that fails for the wrong reason is caught by the stderr
# needle, not just the exit code.
#
# NO `cd` HERE, deliberately: the script path resolves against $PWD, the repo root.
#
# `yq` is NOT stubbed: it is the thing being trusted to read Chart.yaml.
#
# POSIX sh — runs identically on a runner and on macOS.
set -eu

script=scripts/chart-release-version.sh
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT

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

# $1 case, $2 Chart.yaml appVersion line ("" for no key), $3 release version,
# $4 want exit, $5 needle.
# `if out=$( … )` rather than a bare substitution: under `set -e` the assignment
# inherits the substitution's status and the cases that correctly exit non-zero
# would abort this harness before printing a single result.
run_case() {
  dir="${tmp}/$1"
  mkdir "${dir}"
  printf 'name: demo\nversion: 0.1.0\n%s\n' "$2" > "${dir}/Chart.yaml"
  if out=$( sh "${script}" "${dir}" "$3" 2>&1 ); then got=0; else got=$?; fi
  report "$1" "$4" "${got}" "$5" "${out}"
}

run_case bare-matches      'appVersion: "0.1.0"'  0.1.0 0 "ok: appVersion 0.1.0 matches 0.1.0"
run_case v-prefix-matches  'appVersion: "v0.1.0"' 0.1.0 0 "ok: appVersion v0.1.0 matches 0.1.0"
run_case mismatch          'appVersion: "0.1.0"'  0.2.0 1 "appVersion 0.1.0 != release 0.2.0"
run_case no-appversion     ''                     0.1.0 1 "has no appVersion"

# --- missing tooling must say so ---------------------------------------------
# PATH is replaced with an EMPTY directory, not trimmed to system dirs: the
# runner installs yq at /usr/bin/yq, so a trimmed PATH would still find it and
# the case would pass for the wrong reason. The interpreter is named by ABSOLUTE
# path because a bare `sh` is itself unresolvable under the replaced PATH.
mkdir "${tmp}/bin"
if out=$( PATH="${tmp}/bin" /bin/sh "${script}" "${tmp}/bare-matches" 0.1.0 2>&1 ); then got=0; else got=$?; fi
report missing-yq 1 "${got}" "yq not installed" "${out}"

[ "${fail}" = 0 ] || exit 1
