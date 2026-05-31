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

# The forwarder integration test sets up veth pairs + a network namespace and
# drives an HTTP request through the tunnel, so it needs `ip` (iproute2) and
# `curl` in the container. The bare golang image has neither; without `ip` the
# test t.Fatalf's during setup and the early teardown trips the race detector
# (an environment artifact, not a real data race). The internal/xsk tests need
# nothing extra, so only install when a package other than internal/xsk is
# requested, keeping the common xsk-only run fast.
script='exec go test -race -count=1 -v "$@"'
case "${extra_args[*]}" in
  *forwarder* | *"./..."*)
    script='apt-get update -qq && apt-get install -y -qq iproute2 curl >/dev/null && '"$script"
    ;;
esac

exec docker run --rm \
  --privileged \
  --network host \
  -v "$repo_root":/src \
  -v "$gomodcache":/go/pkg/mod \
  -w /src \
  -e GOFLAGS=-mod=mod \
  -e GOCACHE=/tmp/gocache \
  "$img" \
  bash -c "$script" bash "${extra_args[@]}"
