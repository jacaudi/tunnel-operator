FROM golang:1.26

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git curl bash && rm -rf /var/lib/apt/lists/*

# setup-envtest to fetch apiserver/etcd assets.
# PINNED, not @latest: an unpinned install makes this image's contents depend on
# the day it was built, which is the opposite of what a test image is for.
# tools/setup-envtest is a SEPARATE Go module with its own tags (the first is v0.24.0), so its
# version is independent of the sigs.k8s.io/controller-runtime version in go.mod. The apiserver
# version it fetches is chosen at run time (ENVTEST_K8S_VERSION), not by this pin.
# setup-envtest v0.25.2 has four copies: here, the Makefile's `$(ENVTEST)` recipe,
# .github/workflows/ci-integration.yml and .taskfiles/go.yml (the install hint). Change all four
# together.
# renovate: datasource=go depName=sigs.k8s.io/controller-runtime/tools/setup-envtest
ARG SETUP_ENVTEST_VERSION=v0.25.2
RUN go install "sigs.k8s.io/controller-runtime/tools/setup-envtest@${SETUP_ENVTEST_VERSION}"

WORKDIR /workspace

# Warm module cache (optional)
COPY go.mod go.sum ./
RUN go mod download

# We run tests with bind-mounted source, not copying sources into the image

# No entrypoint; caller will invoke /bin/bash explicitly

