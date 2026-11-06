#!/bin/sh
# Assert the committed release.yaml still matches what config/ renders to.
#
# release.yaml is a GENERATED file: `make generate-release-file` renders it with
# kustomize from config/default. Its two image pins carry release-please's
# `x-release-please-version` marker, so each release PR bumps them (see
# release-please-config.json). So it can silently fall behind the CRDs, RBAC and
# Deployment it is supposed to ship, and nothing would say so until someone
# applied a stale manifest.
#
# This regenerates and FAILS on any diff. It never fixes the tree: a CI step that
# mutates what it is checking hides the problem it exists to surface. Same
# contract as the codegen gate in ci-lint.yml, and as scripts/chart-drift.sh for
# repos that ship a chart.
#
# WHY THE IMAGE PINS ARE READ BACK OUT OF THE FILE rather than passed in:
# generate-release-file bakes an image:tag into the output, and its Makefile
# defaults are the local dev values (agent:dev / manager:dev). Regenerating with
# those would report drift on every single run. The committed pins are also
# release-scoped — they name the version last released, which a push to a branch
# has no way to know and must not "correct". So this gate checks the STRUCTURE
# (CRDs, RBAC, Deployment shape) against config/, holding the pins fixed at
# whatever is committed. Bumping them is release-time work, not gate work.
set -eu

cd "$(git rev-parse --show-toplevel)"

if [ ! -f release.yaml ]; then
  echo "::error::release.yaml is missing — it is a committed, generated file"
  exit 1
fi

# `- --agent-image=<ref>` inside the manager container's args.
agent=$(sed -n -e 's/ # x-release-please-version$//' -e 's/^[[:space:]]*- --agent-image=//p' release.yaml | head -1)
# `image: <ref>` at exactly eight spaces — the manager container. The other two
# `image:` matches in this file are CRD schema PROPERTY NAMES with no value on
# the line, so they cannot collide.
manager=$(sed -n -e 's/ # x-release-please-version$//' -e 's/^        image: //p' release.yaml | head -1)

if [ -z "${agent}" ] || [ -z "${manager}" ]; then
  echo "::error::could not read the agent/manager image pins out of release.yaml"
  echo "::error::agent='${agent}' manager='${manager}'"
  echo "::error::if the manifest layout changed, this script's patterns need updating"
  exit 1
fi

echo "regenerating release.yaml with the committed pins:"
echo "  agent:   ${agent}"
echo "  manager: ${manager}"

make generate-release-file AGENT_IMAGE="${agent}" MANAGER_IMAGE="${manager}" >/dev/null

if ! git diff --exit-code -- release.yaml; then
  echo "::error::release.yaml is out of date with config/"
  echo "::error::run: make generate-release-file AGENT_IMAGE=${agent} MANAGER_IMAGE=${manager}"
  echo "::error::then commit the result"
  exit 1
fi

echo "release.yaml matches config/"
