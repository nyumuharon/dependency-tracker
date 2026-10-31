# Accuracy and reliability validation

The corpus in `cmd/dep-tracker/testdata/corpus` contains 36 authored fixtures with
explicit expected package identities and versions. It covers npm lockfile v1/v3,
Yarn Classic/Berry, pnpm v5/v9, Python lockfiles and manifests, Cargo, Go modules
and checksums, Composer, Ruby, NuGet, Maven/Gradle, Conan/vcpkg, Pub, Hex and Swift.
Each case is checked both as a single manifest and through directory discovery.
Fixtures are deliberately small and do not execute project build scripts.

## Independent inventory comparisons

`TestNpmInventoryAgainstPackageManager` invokes npm offline against the shared
npm v3 fixture. It compares every dependency identity/version, including scoped
packages and two installed versions of the same transitive dependency. CI
requires npm to be available on both Linux and macOS.

`TestNpmInventoryAgainstSyft` compares the same four dependency identities against
Syft 1.55.0's SBOM inventory. It passed locally, and a dedicated CI job downloads
the pinned official Syft binary, verifies its published SHA-256 checksum, and
reruns the comparison. Root application records are excluded from both sides.
Syft is a test tool, not a runtime dependency of dep-tracker.

```bash
go test ./cmd/dep-tracker -run 'TestParserAccuracyCorpus|TestNpmInventoryAgainstPackageManager' -v
SYFT_BINARY=/path/to/syft go test ./cmd/dep-tracker -run TestNpmInventoryAgainstSyft -v
```

These are bounded inventory checks, not proof that every syntax variant or real
project is handled, and not vulnerability-detection accuracy measurements.
Unsupported complex ecosystem version orderings still receive no guessed fix.
Add a minimal fixture and explicit expected inventory when a new format or edge
case is reported. Broader real-project comparisons remain useful ongoing work.

## Failure handling and coverage

Regression tests cover absent/invalid/zero EPSS scores, malformed and unreadable
installed metadata, partial inventories, installed npm symlink cycles, registry
HTTP and parse failures, cache persistence, NVD severity fallback, and report
confidence markers. All external intelligence requests in these tests are mocked.

CI runs race-enabled tests on Linux and macOS and enforces at least 80% statement
coverage per platform. Native binaries are built and executed on both platforms.
Windows installer tests verify checksums, failure handling and PATH configuration.
The published-release smoke workflow installs and runs actual release binaries on
Linux, macOS and Windows. Coverage does not measure correctness; inventory
expectations and failure assertions are separate checks.

## Reproducible parser performance measurements

```bash
go test ./cmd/dep-tracker -run '^$' -bench BenchmarkParserCorpus -benchmem
```

These benchmarks measure local manifest parsing and allocations only. They do
not include network/API latency, and results depend on the host and filesystem
cache. Compare results on the same machine and Go toolchain when investigating
regressions; do not extrapolate them to full online scan throughput.
