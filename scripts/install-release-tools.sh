#!/bin/sh
# Installs the release tools at pinned versions into $GOBIN (default
# $(go env GOPATH)/bin): goreleaser builds and packages, syft writes the SBOMs,
# cosign signs the checksums. They are built from source with `go install`, so
# the Go checksum database authenticates every module, exactly as for the
# tool's own dependencies. The release workflow, the CI dry run and a local
# dry run all install the same versions from here.
set -eu

GORELEASER_VERSION=v2.20.2
SYFT_VERSION=v1.57.2
COSIGN_VERSION=v3.1.4

# The tools need a newer Go than saashound's minimum. Build them with a pinned,
# patched toolchain, which the go command fetches and verifies like a module;
# this leaves the toolchain that builds saashound itself untouched.
export GOTOOLCHAIN=go1.27.4

go install "github.com/goreleaser/goreleaser/v2@$GORELEASER_VERSION"
# syft reports the version it is given at link time (as its own release
# builds do), and names itself with it in every SBOM it writes.
go install -ldflags "-X main.version=${SYFT_VERSION#v}" "github.com/anchore/syft/cmd/syft@$SYFT_VERSION"
go install "github.com/sigstore/cosign/v3/cmd/cosign@$COSIGN_VERSION"
