// Package main is the icx Dagger CI module.
//
// It replaces scripts/test-xsk.sh: the Test function runs the full Go suite —
// including the AF_XDP/XSK and forwarder integration tests that need a real
// Linux kernel, veth pairs and NET_ADMIN — inside a Dagger container with the
// full root capability set (InsecureRootCapabilities). CI invokes it on both an
// amd64 and an arm64 runner so the weak-memory aarch64 datapath (the arch the
// old slavc/xdp binding broke on) is exercised on every PR, not just locally.
package main

import (
	"context"

	"dagger/icx/internal/dagger"
)

const goImage = "golang:1.25-bookworm"

type Icx struct{}

// BuilderContainer is the base Go toolchain image with module/build caches and
// the iproute2 + curl tools the forwarder integration test shells out to (it
// builds veth pairs, a network namespace and an in-namespace HTTP server). The
// repo source is mounted at /src.
func (m *Icx) BuilderContainer(src *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(goImage).
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("icx-go-mod")).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("icx-go-build")).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		WithExec([]string{"apt-get", "update", "-qq"}).
		WithExec([]string{"apt-get", "install", "-y", "-qq", "iproute2", "curl"}).
		WithDirectory("/src", src).
		WithWorkdir("/src")
}

// Test runs the full Go test suite with the race detector on a real kernel.
//
// The AF_XDP/XSK setup, veth creation and XDP redirect-program load require the
// full root capability set (CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_BPF) and an
// unrestricted seccomp profile, so the exec runs with InsecureRootCapabilities.
// The privileged tests gate themselves at runtime (root + an AF_XDP socket
// probe) and skip cleanly where the kernel lacks CONFIG_XDP_SOCKETS, so this is
// also safe on a runner whose kernel does not support AF_XDP — it just covers
// less.
func (m *Icx) Test(ctx context.Context, src *dagger.Directory) (string, error) {
	return m.BuilderContainer(src).
		WithExec(
			[]string{"go", "test", "-race", "-count=1", "-v", "./..."},
			dagger.ContainerWithExecOpts{InsecureRootCapabilities: true},
		).
		Stdout(ctx)
}

// Lint runs golangci-lint over the module.
func (m *Icx) Lint(ctx context.Context, src *dagger.Directory) (string, error) {
	return dag.Container().
		From("golangci/golangci-lint:latest").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("icx-go-mod")).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("icx-go-build")).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		WithDirectory("/src", src).
		WithWorkdir("/src").
		WithExec([]string{"golangci-lint", "run", "--timeout=5m"}).
		Stdout(ctx)
}

// Build cross-compiles the icx CLI for the given GOARCH (amd64 or arm64) and
// returns the resulting static binary. Mirrors the build-cli job: CGO disabled,
// trimmed and stripped.
func (m *Icx) Build(src *dagger.Directory, arch string) *dagger.File {
	if arch == "" {
		arch = "amd64"
	}
	return m.BuilderContainer(src).
		WithWorkdir("/src/cli").
		WithEnvVariable("GOOS", "linux").
		WithEnvVariable("GOARCH", arch).
		WithEnvVariable("CGO_ENABLED", "0").
		WithExec([]string{"go", "build", "-trimpath", "-ldflags", "-s -w", "-o", "/icx"}).
		File("/icx")
}
