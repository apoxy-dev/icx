#!/usr/bin/env bash
# Run the internal/xsk tests on a real Linux kernel with AF_XDP support.
#
# macOS has no AF_XDP; this runs the suite inside a privileged Linux container.
# It works with any Docker that exposes a real Linux kernel with
# CONFIG_XDP_SOCKETS=y — OrbStack and colima both do (and run an aarch64 kernel
# on Apple Silicon, i.e. the weak-memory arch where the old slavc/xdp broke).
#
# Usage:
#   scripts/test-xsk.sh                 # run all xsk tests (unit + integration), race on
#   scripts/test-xsk.sh -run TestAFXDP  # pass extra args through to `go test`
#
# --privileged + NET_ADMIN are required for veth creation and AF_XDP bind.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gomodcache="$(go env GOMODCACHE 2>/dev/null || echo "$HOME/go/pkg/mod")"
img="${XSK_TEST_IMAGE:-golang:1.24}"

extra_args=("$@")
if [ ${#extra_args[@]} -eq 0 ]; then
  extra_args=(./internal/xsk/...)
else
  # If the caller passed flags but no package, append the package.
  case "${extra_args[*]}" in
    *./internal/xsk*) : ;;
    *) extra_args+=(./internal/xsk/...) ;;
  esac
fi

exec docker run --rm \
  --privileged \
  --network host \
  -v "$repo_root":/src \
  -v "$gomodcache":/go/pkg/mod \
  -w /src \
  -e GOFLAGS=-mod=mod \
  -e GOCACHE=/tmp/gocache \
  "$img" \
  go test -race -count=1 -v "${extra_args[@]}"
