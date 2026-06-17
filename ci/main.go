// Package main is the icx Dagger CI/test harness.
//
// It is the single entry point for every kind of verification the repo runs —
// locally (`dagger call <fn>`) and in GitHub Actions — split into lanes that map
// onto the ways the code is exercised:
//
//   - Unit: the root module (minus the root-requiring datapath packages) plus
//     the cli module, unprivileged, race detector on — the fast feedback gate.
//   - Integration: the whole tree plus the cli module WITH the root capability
//     set, on a real kernel, so the veth/AF_XDP/forwarder tests actually run.
//   - Bench / Benchstat: `go test -bench -benchmem` and an A/B baseline diff,
//     feeding the performance thread (the open P-series findings).
//
// Both test lanes also run the SEPARATE `cli/` Go module (it has its own go.mod,
// so a root-module `./...` excludes it); the `ci/` module itself is tooling and
// is never under test. Every command is run as a real argv — no `sh -c` — so
// there is no shell-quoting surface; the one place package filtering is needed
// (Unit) is done in Go against `go list` output.
package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"dagger/icx/internal/dagger"
)

const goImage = "golang:1.25-bookworm"

// benchstatPkg is pinned-by-module benchstat; installed on demand by Benchstat
// so the common lanes don't pay for it.
const benchstatPkg = "golang.org/x/perf/cmd/benchstat@latest"

// privilegedPkgRe matches the packages whose tests HARD-FAIL without the root
// capability set: they create veth pairs / AF_XDP sockets and call t.Fatal on
// EPERM rather than skipping (unlike mac/queues/vtep, which skip cleanly). Unit
// filters them out of `go list`; Integration runs the whole tree with privilege,
// so it covers them. If a new root-requiring package is added and not listed
// here, Unit fails loudly with "operation not permitted" — a clear signal to
// extend this, and Integration still covers it in the meantime.
var privilegedPkgRe = regexp.MustCompile(`/(forwarder|internal/xsk|veth)($|/)`)

type Icx struct{}

// BuilderContainer is the base Go toolchain image with shared module/build
// caches and the userland tools the integration tests shell out to: iproute2 +
// curl (the forwarder test builds veth pairs, a netns and an in-namespace HTTP
// server) and git (Benchstat checks out a baseline worktree). The repo source
// is mounted at /src.
func (m *Icx) BuilderContainer(src *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(goImage).
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("icx-go-mod")).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("icx-go-build")).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		WithExec([]string{"apt-get", "update", "-qq"}).
		WithExec([]string{"apt-get", "install", "-y", "-qq", "iproute2", "curl", "git"}).
		WithDirectory("/src", src).
		WithWorkdir("/src")
}

// Unit runs the test suite WITHOUT extra privilege: the root module minus the
// root-requiring datapath packages (see privilegedPkgRe) plus the separate cli
// module, race detector on by default, test cache disabled. It is the fast,
// runner-agnostic correctness gate. For the privileged lane that actually
// exercises the veth/AF_XDP datapath, use Integration.
func (m *Icx) Unit(
	ctx context.Context,
	src *dagger.Directory,
	// Run with the race detector (-race). Default true.
	// +optional
	// +default=true
	race bool,
) (string, error) {
	c := m.BuilderContainer(src)
	pkgs, err := rootTestPkgs(ctx, c, privilegedPkgRe)
	if err != nil {
		return "", err
	}
	return runSuite(ctx, c, goTestArgs(race), pkgs, false)
}

// Integration runs the FULL suite on a real kernel with the root capability set
// (InsecureRootCapabilities) so the AF_XDP/XSK socket setup, veth creation and
// XDP redirect-program load actually run rather than failing on EPERM. It covers
// the root module and the cli module and is the superset of Unit (same tests,
// plus the privileged ones). CI runs it on both amd64 and arm64 so the
// weak-memory aarch64 datapath is exercised on every PR.
//
// It is safe on a kernel without CONFIG_XDP_SOCKETS — the AF_XDP tests gate
// themselves at runtime and skip cleanly; the lane just covers less.
func (m *Icx) Integration(
	ctx context.Context,
	src *dagger.Directory,
	// Run with the race detector (-race). Default true.
	// +optional
	// +default=true
	race bool,
) (string, error) {
	return runSuite(ctx, m.BuilderContainer(src), goTestArgs(race), []string{"./..."}, true)
}

// Bench runs the Go benchmarks with -benchmem and no race detector (the race
// instrumentation perturbs timing), emitting benchstat-ready output. It is
// unprivileged — none of the benchmarks need a real datapath.
//
// pkgs/pattern/count/benchtime/cpu mirror the `go test` knobs so the
// performance thread can target one finding (e.g. the routing-contention
// RWMutex benchmark) and dial repetition/parallelism for stable numbers.
func (m *Icx) Bench(
	ctx context.Context,
	src *dagger.Directory,
	// Package pattern to benchmark. Default the whole root module.
	// +optional
	// +default="./..."
	pkgs string,
	// Benchmark name regexp passed to -bench. Default all.
	// +optional
	// +default="."
	pattern string,
	// -count: benchmark repetitions (raise for benchstat stability). Default 6.
	// +optional
	// +default=6
	count int,
	// -benchtime, e.g. "1s" or "100x". Empty uses the go default (1s).
	// +optional
	// +default=""
	benchtime string,
	// -cpu list, e.g. "1,4,8", to sweep GOMAXPROCS for the contention
	// benchmarks. Empty uses the container's CPU count.
	// +optional
	// +default=""
	cpu string,
) (string, error) {
	return execStdout(ctx, m.BuilderContainer(src).
		WithExec(benchArgs(pkgs, pattern, count, benchtime, cpu)))
}

// Benchstat runs the SAME benchmarks on the working tree and on a baseline git
// ref, then reports the delta with benchstat — the A/B harness for the
// performance thread. Both legs run back-to-back in one container (same engine,
// same caches) so machine drift cancels; raise count for tighter confidence
// intervals.
//
// The mounted source must carry its .git history so the baseline can be checked
// out into a detached worktree at /base.
func (m *Icx) Benchstat(
	ctx context.Context,
	src *dagger.Directory,
	// Baseline git ref (branch, tag or SHA) to compare the working tree against.
	baseRef string,
	// Package pattern to benchmark. Default the whole root module.
	// +optional
	// +default="./..."
	pkgs string,
	// Benchmark name regexp passed to -bench. Default all.
	// +optional
	// +default="."
	pattern string,
	// -count: benchmark repetitions. Default 10 (benchstat wants several).
	// +optional
	// +default=10
	count int,
	// -benchtime, e.g. "1s" or "100x". Empty uses the go default (1s).
	// +optional
	// +default=""
	benchtime string,
	// -cpu list, e.g. "1,4,8". Empty uses the container's CPU count.
	// +optional
	// +default=""
	cpu string,
) (string, error) {
	// Stand up a detached worktree of the baseline ref alongside the working
	// tree. safe.directory is set for both because the worktree's container UID
	// does not own the mounted .git.
	c := m.BuilderContainer(src).
		WithExec([]string{"go", "install", benchstatPkg}).
		WithExec([]string{"git", "config", "--global", "--add", "safe.directory", "/src"}).
		WithExec([]string{"git", "-C", "/src", "worktree", "add", "--detach", "/base", baseRef}).
		WithExec([]string{"git", "config", "--global", "--add", "safe.directory", "/base"})

	args := benchArgs(pkgs, pattern, count, benchtime, cpu)
	oldOut, err := execStdout(ctx, c.WithWorkdir("/base").WithExec(args))
	if err != nil {
		return oldOut, fmt.Errorf("benchstat: baseline %s: %w", baseRef, err)
	}
	newOut, err := execStdout(ctx, c.WithWorkdir("/src").WithExec(args))
	if err != nil {
		return newOut, fmt.Errorf("benchstat: working tree: %w", err)
	}
	// Hand the two result sets to benchstat as files — written in Go, no shell
	// redirects.
	return c.
		WithNewFile("/tmp/old.txt", oldOut).
		WithNewFile("/tmp/new.txt", newOut).
		WithExec([]string{"benchstat", "/tmp/old.txt", "/tmp/new.txt"}).
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

// All is the full local verification gate: Lint, then Unit (the fast
// unprivileged lane), then Integration (the privileged real-kernel lane). Unit
// and Integration are not redundant — Unit proves the unprivileged gate is
// green while Integration actually exercises the datapath the former skips. The
// combined output of every stage is returned; the first failing stage aborts.
func (m *Icx) All(ctx context.Context, src *dagger.Directory) (string, error) {
	var out strings.Builder
	for _, stage := range []struct {
		name string
		run  func(context.Context, *dagger.Directory) (string, error)
	}{
		{"lint", m.Lint},
		{"unit", func(ctx context.Context, s *dagger.Directory) (string, error) { return m.Unit(ctx, s, true) }},
		{"integration", func(ctx context.Context, s *dagger.Directory) (string, error) { return m.Integration(ctx, s, true) }},
	} {
		fmt.Fprintf(&out, "===== %s =====\n", stage.name)
		res, err := stage.run(ctx, src)
		out.WriteString(res)
		if err != nil {
			fmt.Fprintf(&out, "\n===== %s FAILED: %v =====\n", stage.name, err)
			return out.String(), fmt.Errorf("All: %s failed: %w", stage.name, err)
		}
		out.WriteString("\n")
	}
	return out.String(), nil
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

// goTestArgs is the `go test` flag vector shared by Unit and Integration.
func goTestArgs(race bool) []string {
	args := []string{"-count=1", "-v"}
	if race {
		args = append(args, "-race")
	}
	return args
}

// benchArgs is the `go test -bench` argv reused by Bench and both Benchstat legs.
// -run '^$' skips tests so only benchmarks run; -benchmem reports allocs, which
// is exactly what the micro-allocation findings (P10/P11) track.
func benchArgs(pkgs, pattern string, count int, benchtime, cpu string) []string {
	args := []string{"go", "test", "-run", "^$", "-bench", pattern, "-benchmem", "-count=" + strconv.Itoa(count)}
	if benchtime != "" {
		args = append(args, "-benchtime="+benchtime)
	}
	if cpu != "" {
		args = append(args, "-cpu="+cpu)
	}
	return append(args, strings.Fields(pkgs)...)
}

// rootTestPkgs lists the root-module packages, dropping any whose import path
// matches exclude (nil = keep all). The filter runs in Go against `go list`
// output rather than a shell pipeline.
func rootTestPkgs(ctx context.Context, c *dagger.Container, exclude *regexp.Regexp) ([]string, error) {
	out, err := c.WithExec([]string{"go", "list", "./..."}).Stdout(ctx)
	if err != nil {
		return nil, fmt.Errorf("go list root packages: %w", err)
	}
	var pkgs []string
	for _, p := range strings.Fields(out) {
		if exclude != nil && exclude.MatchString(p) {
			continue
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		return nil, errors.New("go list returned no packages")
	}
	return pkgs, nil
}

// runSuite runs `go test <testArgs> <rootPkgs>` in the root module and then
// `go test <testArgs> ./...` in the cli module, concatenating both outputs.
// privileged toggles the full root capability set for the kernel/datapath tests.
func runSuite(ctx context.Context, c *dagger.Container, testArgs, rootPkgs []string, privileged bool) (string, error) {
	opts := dagger.ContainerWithExecOpts{InsecureRootCapabilities: privileged}
	var b strings.Builder

	b.WriteString("===== root module =====\n")
	rootCmd := append(append([]string{"go", "test"}, testArgs...), rootPkgs...)
	rootOut, err := execStdout(ctx, c.WithExec(rootCmd, opts))
	b.WriteString(rootOut)
	if err != nil {
		return b.String(), fmt.Errorf("root module tests: %w", err)
	}

	b.WriteString("\n===== cli module =====\n")
	cliCmd := append(append([]string{"go", "test"}, testArgs...), "./...")
	cliOut, err := execStdout(ctx, c.WithWorkdir("/src/cli").WithExec(cliCmd, opts))
	b.WriteString(cliOut)
	if err != nil {
		return b.String(), fmt.Errorf("cli module tests: %w", err)
	}
	return b.String(), nil
}

// execStdout returns the container's stdout, recovering the captured output from
// the ExecError when the command exits non-zero — Dagger otherwise discards it,
// so a failing lane would return an error with no test log.
func execStdout(ctx context.Context, c *dagger.Container) (string, error) {
	out, err := c.Stdout(ctx)
	if err != nil {
		var ee *dagger.ExecError
		if errors.As(err, &ee) {
			return ee.Stdout + ee.Stderr, err
		}
	}
	return out, err
}
