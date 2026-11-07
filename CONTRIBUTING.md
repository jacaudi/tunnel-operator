# Contributing

Thanks for your interest in tunnel-operator. This document covers the conventions that the
release tooling and CI depend on, and the engineering practices every change follows.

## Before you start

- Open an issue describing the change before writing code, unless it is a small fix. The design
  specs and implementation plans are working documents kept outside this repository, so the issue
  thread is where design intent gets shared — ask there if the reasoning behind an area is not
  obvious from the code. Open work is tracked under
  [#37](https://github.com/jacaudi/tunnel-operator/issues/37).
- The project is built with [Kubebuilder](https://github.com/kubernetes-sigs/kubebuilder); read
  about that first if it is new to you.

## Local development

```sh
task --list      # see available tasks
task ci          # everything the lint stage of CI runs; run it before pushing
make test        # manifests, generate, fmt, vet, then the envtest suite
make manifests   # regenerate CRDs and RBAC after changing api/
make generate    # regenerate deepcopy functions after changing api/
```

`make test` regenerates before running, so a stale CRD or an unformatted file fails locally rather
than in CI. It passes `-tags=integration`; without that tag `go test ./...` skips the envtest suite
and still reports success.

The kind tier runs the operator in a real cluster. Build the two images, then run the suite:

```sh
make docker-build-integration-test MANAGER_IMAGE=tunnel-operator/manager:test AGENT_IMAGE=tunnel-operator/agent:test
make run-e2e MANAGER_IMAGE=tunnel-operator/manager:test AGENT_IMAGE=tunnel-operator/agent:test
```

The tier needs Docker, `kubectl` and `helm` (v4) on `PATH`, and network access for
`helm dependency build`. It creates a kind cluster named `wg-kind-test` and deletes it
when the run ends. The default `E2E_KUBECONFIG` is a scratch file, `/tmp/wg-e2e-kubeconfig`, so
kind never edits `~/.kube/config`; set it to `~/.kube/config` to merge the cluster into your config.
`SKIP_CLEANUP=1` keeps the cluster for debugging, and the next run then fails at create until
`KUBECONFIG=/tmp/wg-e2e-kubeconfig bin/kind delete cluster --name wg-kind-test` removes it. CI runs
these two targets as the required `e2e` stage.

## Generated artifacts

Never hand-edit `zz_generated.deepcopy.go` or anything under `config/crd/bases` — regenerate
instead. The chart's CRDs and RBAC are copied from `config/` by `hack/sync-helm-crds.sh` and
`hack/generate-helm-rbac.sh`, and CI fails the build when `charts/` drifts from them.

## Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org/). Examples:

- `feat: add spec.localCIDRs to Wireguard`
- `fix(controller): keep allocating peers after one peer's status conflict`
- `refactor!: delete the wstunnel sidecar`
- `docs: describe the peer status messages`

[release-please](https://github.com/googleapis/release-please) reads the commit types on `main`
and maintains a release PR; merging that PR tags the release. `feat:` drives a minor release and
`fix:` a patch. The project is pre-1.0 and
[`.github/release-please-config.json`](.github/release-please-config.json) sets
`bump-minor-pre-major`, so a breaking change (`!` or a `BREAKING CHANGE:` footer) bumps the
**minor** version until `1.0.0`. A commit without a conventional type contributes nothing to the
changelog or the version.

## Pull requests

1. Branch from `main`: `git switch -c feat/<topic>`.
2. Keep PRs focused; one logical change per PR.
3. Run `task ci` and `make test` locally.
4. Get a cold review (see below), then open the PR against `main`.
5. The required check is `ci`; it must be green. PRs are merged, not squashed, so every commit
   subject must be a Conventional Commit.

## Engineering practices

These apply to every change.

### TDD

Write the test first, watch it fail for the right reason, then make it pass. A test that has never
failed has proven nothing.

For changes that add behaviour this is literal. For **pure refactors** it is not — there is no new
behaviour to drive out, so writing new tests first would be cargo-culting. On a refactor it means:
establish a green baseline before touching anything, keep it green after every step, and if an
existing test fails, the refactor changed behaviour. Fix the code, never the assertion.

### DRY

The hardest-won lesson in this codebase: `internal/resources` and the inline reconciler functions
were the same code twice, and they silently drifted apart. Do not create a second copy of anything
— a constant, a rendering path, a default value. One source of truth, referenced.

Note the limit: two things that look alike but change for different reasons are not duplication.
Do not collapse them to satisfy the acronym.

### 12-Factor

Most factors are satisfied by Kubernetes itself. The ones that bite here:

- **Config** — configuration comes from the CRD or the environment, never hardcoded in more than
  one place. A default belongs in the CRD's `+kubebuilder:default`, with any Go constant existing
  only as a nil-fallback.
- **Processes** — builders stay pure functions of their inputs. No caching on the reconciler, no
  hidden state between calls.
- **Logs** — event streams to stdout via `logr`. No log files, no rotation.
- **Disposability** — fast startup, graceful shutdown.

### YAGNI

Build what the issue asks for. Do not add a config knob because someone might want it, and do not
generalise for a second implementation that does not exist. If you are writing an abstraction with
exactly one caller, stop.

### KISS

Prefer the boring solution. If a reviewer needs the design doc open to understand the diff, it is
too clever. Explicit repetition of three short lines beats a helper that takes four parameters to
avoid it.

### Cold review before the PR

Before opening a PR, get a review from a reviewer with none of the context that produced the change
— a fresh session, colleague, or agent — given only:

- the diff
- the issue text, including its acceptance criteria
- the repository

and explicitly **not** the implementation plan, the discussion that produced it, or any reasoning
about why choices were made.

Ask it to answer:

1. Does the diff do what the acceptance criteria say, no more and no less?
2. Is there scope creep — anything changed that the issue did not ask for?
3. Is anything wrong, unclear, or surprising to someone seeing it for the first time?
4. Are the tests testing behaviour, or asserting on implementation details?

An author who has been reasoning about a change for an hour cannot see what is unexplained in it.
If the cold reviewer misreads the diff, that is a finding about the diff. Address the findings,
then open the PR.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.
