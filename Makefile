SHELL = /bin/bash


# setup

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

# Every tool rule below takes $(LOCALBIN) as an ORDER-ONLY prerequisite (the
# `|`), and that pipe is load-bearing. As a normal prerequisite, installing any
# one tool updates bin/'s mtime, which makes every OTHER tool look stale — make
# re-runs its installer, and kustomize's refuses outright:
#   .../bin/kustomize exists. Remove it first.
# ci-lint.yml runs `make manifests generate`, which installs controller-gen; a
# later target that needs kustomize (update-agent-image, run-e2e) would hit that
# refusal if its prerequisite were not order-only. Order-only means "ensure the
# directory exists" without comparing timestamps against it.

## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
KIND ?= $(LOCALBIN)/kind
ENVTEST ?= $(LOCALBIN)/setup-envtest

## Tool Versions
KUSTOMIZE_VERSION ?= v5.4.2
CONTROLLER_TOOLS_VERSION ?= v0.23.0
KIND_VERSION ?= v0.33.0


# images
AGENT_IMAGE ?= "agent:dev"
MANAGER_IMAGE ?= "manager:dev"

# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.34.1

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

manifests: controller-gen ## Generate ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

test: manifests generate fmt vet envtest ## Run tests.
# -tags=integration is REQUIRED, not optional. internal/controller carries
# //go:build integration, so without it `go test ./...` silently skips the
# entire envtest suite and still reports success.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" go test ./... -tags=integration -coverprofile cover.out

test-ci: manifests generate fmt vet envtest ## Run tests with JUnit output for CI.
# See the note on `test` above: -tags=integration or the envtest suite does
# not run and CI goes green having tested strictly less.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" go test -json ./... -tags=integration -coverprofile cover.out > test-report.json

TEST_RUNNER_IMAGE ?= tunnel-operator-test:local

test-in-docker: ## Build test runner image and execute tests inside it.
	docker build -t $(TEST_RUNNER_IMAGE) -f images/test/Dockerfile .
	docker run --rm \
	  -v $(PWD):/workspace \
	  -w /workspace \
	  -e GOFLAGS \
	  -e GOMODCACHE \
	  -e GOPATH \
	  $(TEST_RUNNER_IMAGE) /bin/bash -lc "bash hack/test-in-docker.sh $(ENVTEST_K8S_VERSION)"

##@ Build
build: build-agent build-manager

build-agent: generate fmt vet ## Build manager binary.
	go build -o bin/agent ./cmd/agent/main.go

build-manager: generate fmt vet ## Build manager binary.
	go build -o bin/manager ./cmd/manager/main.go

run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/manager/main.go



docker-build-agent:  ## Build docker image with the manager.
	docker build -t ${AGENT_IMAGE} . -f ./images/agent/Dockerfile

docker-build-manager:  ## Build docker image with the manager.
	docker build -t ${MANAGER_IMAGE} . -f ./images/manager/Dockerfile

docker-build-integration-test:  docker-build-manager
	$(MAKE) docker-build-agent
	$(MAKE) docker-build-manager


# kind writes its context here, never into ~/.kube/config. Set
# E2E_KUBECONFIG=~/.kube/config to merge the test cluster into your own config.
E2E_KUBECONFIG ?= /tmp/wg-e2e-kubeconfig
run-e2e: $(KIND)
	@for f in $(PINNED_AT_BUILD); do cp "$$f" "$$f.pre-build"; done
	@trap 'for f in $(PINNED_AT_BUILD); do mv "$$f.pre-build" "$$f"; done' EXIT; \
	  AGENT_IMAGE=${AGENT_IMAGE} $(MAKE) update-agent-image && \
	  MANAGER_IMAGE=${MANAGER_IMAGE} $(MAKE) update-manager-image && \
	  $(KUSTOMIZE) build config/default > release_it.yaml
	KUBECONFIG=$(E2E_KUBECONFIG) KUBE_CONFIG=$(E2E_KUBECONFIG) KIND_BIN=${KIND} WIREGUARD_OPERATOR_RELEASE_PATH="../../release_it.yaml" AGENT_IMAGE=${AGENT_IMAGE} MANAGER_IMAGE=${MANAGER_IMAGE} SKIP_CLEANUP=${SKIP_CLEANUP} go test -tags=e2e ./internal/it/ -v -count=1 -timeout 25m

docker-push: ## Push docker image with the manager.
	docker push ${IMG}

##@ Deployment

install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

# These two files are mutated in place by update-agent-image and
# update-manager-image so a build can stamp release-time image pins into them,
# then restored — they are not meant to carry those pins in the tree.
#
# RESTORED FROM A SAVED COPY, NOT `git checkout`. Both targets below used to run
# `git checkout ./config/default/manager_args_patch.yaml`, which restores from the
# INDEX and therefore silently discards any uncommitted edit to these files.
# `make run-e2e` runs both targets, so a developer running the e2e locally
# would lose in-progress work with no warning. Verified the hard way: it ate an
# image-rename edit exactly that way while this branch was being written.
PINNED_AT_BUILD := config/default/manager_args_patch.yaml config/manager/kustomization.yaml

update-agent-image: kustomize
	sed 's|$${AGENT_IMAGE}|$(AGENT_IMAGE)|g' ./config/default/manager_args_patch.yaml.template > ./config/default/manager_args_patch.yaml

update-manager-image: kustomize
	$(info MANAGER_IMAGE: "$(MANAGER_IMAGE)")
	cd config/manager && $(KUSTOMIZE) edit set image controller=${MANAGER_IMAGE}

deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/default | kubectl delete -f -

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): | $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

kind: $(KIND) ## Download kind locally if necessary.
$(KIND): | $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/kind/cmd/kind@$(KIND_VERSION)

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): | $(LOCALBIN)
	curl -s $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
# setup-envtest v0.25.2 has four copies: here, .github/workflows/ci-integration.yml,
# .taskfiles/go.yml (the install hint) and images/test/Dockerfile. Change all four together.
$(ENVTEST): | $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.2
