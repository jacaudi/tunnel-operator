#!/usr/bin/env sh
# Refuse to publish a chart whose appVersion is not the release being cut.
#
#   usage: chart-release-version.sh <chart-dir> <version>
#
# WHY THIS GATE EXISTS: release-please bumps Chart.yaml's appVersion through an
# x-release-please-version marker. A missed marker would ship chart X.Y.Z
# rendering the PREVIOUS release's images, and chart-appversion.sh cannot see it:
# those image tags exist, so its existence check passes. Comparing appVersion to
# the release version is the only check that catches it.
#
# THE `v` IS TRIMMED FROM BOTH SIDES. The chart version arrives bare (SemVer
# forbids the `v`), and appVersion may be written either way, so the comparison
# ignores the prefix rather than guessing which spelling a repo uses.
#
# NO `cd` HERE, deliberately — the same trap chart-appversion.sh documents. The
# chart directory arrives as an ARGUMENT and is resolved against $PWD.
#
# POSIX sh — runs identically on a runner and on macOS.
set -eu

[ $# -eq 2 ] || { echo "usage: chart-release-version.sh <chart-dir> <version>" >&2; exit 2; }

command -v yq >/dev/null || { echo "yq not installed: brew install yq" >&2; exit 1; }

# BOTH TESTS ARE LOAD-BEARING: an ABSENT key prints the string `null`, a present
# but empty one prints nothing (see chart-appversion.sh).
app=$(yq '.appVersion' "$1/Chart.yaml")
if [ -z "${app}" ] || [ "${app}" = "null" ]; then
  echo "::error::$1/Chart.yaml has no appVersion" >&2
  exit 1
fi

if [ "${app#v}" != "${2#v}" ]; then
  echo "::error::appVersion ${app#v} != release ${2#v}; refusing to publish a chart that renders the wrong image" >&2
  exit 1
fi

echo "ok: appVersion ${app} matches ${2}"
