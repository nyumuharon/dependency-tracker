# Dependency Risk Tracker

**Dependency Risk Tracker (`dep-tracker`)** is a high-performance, zero-dependency Software Composition Analysis (SCA) and supply-chain vulnerability intelligence CLI tool written in Go. It discovers, analyzes, and prioritizes security vulnerabilities and maintenance risks across modern software projects in any programming language—even when a project lacks a lockfile or manifest.

The tool combines a **Three-Layer Intelligent Dependency Discovery Engine** with a **Two-Phase Batch OSV & NVD Vulnerability Pipeline**, an in-memory **CVSS v3.1 Vector Calculator**, **FIRST.org EPSS** 30-day exploitation probabilities, **CISA Known Exploited Vulnerabilities (KEV)** catalog alerts, **Multi-Registry Staleness Auditing**, and automated generation of **CycloneDX v1.4 SBOM** (`sbom.json`) and **OASIS SARIF v2.1.0** (`results.sarif`) compliance reports.

---

## Key Capabilities

* **Three-Layer Intelligent Dependency Discovery**:
  * **Layer 1 — Manifests, Lockfiles & Build DSLs**: Recursively detects and parses 30+ manifest, lockfile, and build DSL formats across **12 ecosystems** (npm/Yarn/pnpm, PyPI/Poetry/Pipenv/uv/Conda, Maven/Gradle, NuGet/.NET, Cargo/Rust, Go Modules, Composer/PHP, RubyGems/Bundler, Conan/vcpkg/CMake, Dart/Flutter Pub, Elixir Mix, and Swift Package Manager). Automatically resolves unpinned manifests against exact versions installed in local environments.
  * **Layer 2 — Installed Virtual & Vendor Environment Introspection**: Automatically inspects **8 installed environment formats** when lockfiles are absent or manifests use loose version specifiers (`>=`, `^`, `*`): Python `venv`/`.venv` (`*.dist-info/METADATA`), Node `node_modules/*/package.json`, .NET `obj/project.assets.json`, PHP `vendor/composer/installed.json`, Go `vendor/modules.txt`, Ruby `vendor/bundle/**/*.gemspec`, C/C++ `vcpkg_installed/vcpkg/status`, and Dart `.dart_tool/package_config.json`.
  * **Layer 3 — Zero-Manifest Source-Code Import Fallback**: Extracts third-party imports directly from source files across **10 programming language families** (`.py`, `.js`/`.ts`/`.jsx`/`.tsx`, `.go`, `.rs`, `.c`/`.cpp`/`.h`/`.hpp`, `.java`/`.kt`, `.cs`, `.php`, `.rb`, and `.dart`), filters out standard-library modules, maps import names to canonical registry packages, and labels their versions as unresolved rather than assuming that the latest registry release is installed.
* **High-Speed Two-Phase Batch OSV Engine**: Uses a pooled HTTP/2 transport (`MaxIdleConnsPerHost: 32`) to query `/v1/querybatch` in batches of up to 1,000 resolved packages, then concurrently fetches full query results for packages with matching advisories.
* **Instant In-Memory CVSS v3.1 Vector Calculator & Cached NVD 2.0 Fallback**: Computes exact CVSS v3.1 base scores in memory without a network request from vector strings using official FIRST.org equations, with parallelized NIST NVD CVE 2.0 API fallback backed by a 24-hour local disk cache (`nvd_cache.json`).
* **CISA KEV & FIRST EPSS Exploitability Prioritization**: Cross-references every CVE against CISA's Known Exploited Vulnerabilities (KEV) catalog and queries FIRST.org EPSS in batches to compute a two-dimensional four-tier risk priority (`CRITICAL-EXPLOITABLE`, `HIGH`, `MEDIUM`, `LOW`).
* **Fast Multi-Registry Staleness Auditing**: Audits package maintenance health concurrently across npm, PyPI lightweight RSS release feeds (`~10 KB` instead of multi-MB JSON payloads), Maven Central, NuGet, Crates.io, Go Proxy, Packagist, RubyGems, ConanCenter, Pub.dev, and Hex.pm with a 12-hour local disk cache (`staleness_cache.json`), flagging packages untouched for > 2 years (730 days).
* **CycloneDX v1.4 SBOM & OASIS SARIF v2.1.0 Export**: Automatically generates `sbom.json` (with standardized PURLs and embedded CVSS/EPSS/KEV ratings) and `results.sarif` (for GitHub Code Scanning and CI/CD inline PR annotations).

---

## Supported Ecosystems & Three-Layer Discovery Matrix

### Layer 1: Manifests, Lockfiles & Build DSLs

| Ecosystem / Platform | Languages | Supported Lockfiles (Transitive) | Supported Manifests & Build DSLs (Direct) | Upstream Registry |
| :--- | :--- | :--- | :--- | :--- |
| **npm** | JavaScript, TypeScript | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `package.json` | `registry.npmjs.org` |
| **PyPI** | Python | `poetry.lock`, `Pipfile.lock`, `uv.lock` | `requirements.txt`, `pyproject.toml` (PEP 621, Poetry, PDM), `Pipfile`, `setup.py`, `setup.cfg`, `environment.yml` | `pypi.org` (JSON & RSS) |
| **Maven / Gradle** | Java, Kotlin, Scala | `gradle.lockfile` | `pom.xml` (with `<properties>` & `<dependencyManagement>`), `build.gradle`, `build.gradle.kts`, `libs.versions.toml` | `search.maven.org` |
| **NuGet** | C#, F#, .NET | `packages.lock.json`, `paket.lock` | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `Directory.Packages.props` | `api.nuget.org` |
| **crates.io** | Rust | `Cargo.lock` | `Cargo.toml` | `crates.io` |
| **Go** | Go | `go.sum` (checksum-history fallback) | `go.mod` (preferred) | `proxy.golang.org` |
| **Packagist** | PHP | `composer.lock` | `composer.json` | `repo.packagist.org` |
| **RubyGems** | Ruby | `Gemfile.lock` | `Gemfile`, `*.gemspec` | `rubygems.org` |
| **ConanCenter** | C, C++ | `conan.lock` | `conanfile.txt`, `conanfile.py`, `vcpkg.json`, `CMakeLists.txt` (`find_package` / `FetchContent`) | `conan.io` / GitHub |
| **Pub** | Dart, Flutter | `pubspec.lock` | `pubspec.yaml` | `pub.dev` |
| **Hex** | Elixir, Erlang | `mix.lock` | `mix.exs` | `hex.pm` |
| **SwiftURL** | Swift | `Package.resolved` | `Package.swift` | GitHub / SwiftPM |

### Layer 2: Installed Virtual & Vendor Environments

| Runtime / Ecosystem | Inspected Environment Path / Artifact | Resolution Behavior |
| :--- | :--- | :--- |
| **Python (`PyPI`)** | `venv/`, `.venv/`, `env/` (`site-packages/*.dist-info/METADATA`, `*.egg-info/PKG-INFO`) | Resolves exact installed versions & upgrades unpinned `requirements.txt` ranges |
| **Node.js (`npm`)** | `node_modules/*/package.json` & `node_modules/@scope/*/package.json` | Resolves installed direct & transitive packages when lockfiles are absent |
| **.NET (`NuGet`)** | `obj/project.assets.json` | Extracts exact resolved NuGet package graph from `libraries` / `targets` |
| **PHP (`Packagist`)** | `vendor/composer/installed.json` | Extracts exact installed Composer v1/v2 packages |
| **Go (`Go`)** | `vendor/modules.txt` | Extracts vendored Go module names and versions |
| **Ruby (`RubyGems`)** | `vendor/bundle/**/specifications/*.gemspec` | Extracts exact bundled Gem names and versions |
| **C/C++ (`ConanCenter`)** | `vcpkg_installed/vcpkg/status` | Parses Debian-control style `Package:` / `Version:` / `Status: install ok installed` blocks |
| **Dart / Flutter (`Pub`)** | `.dart_tool/package_config.json` | Extracts resolved Dart/Flutter packages and versions from `rootUri` cache paths |

### Layer 3: Zero-Manifest Source-Code Import Fallback

When a target directory contains raw source code with no manifest, lockfile, or installed environment, `dep-tracker` scans `.py`, `.js`/`.ts`/`.jsx`/`.tsx`, `.go`, `.rs`, `.c`/`.cpp`/`.cc`/`.cxx`/`.h`/`.hpp`, `.java`, `.kt`/`.kts`, `.cs`, `.php`, `.rb`, and `.dart` files, excludes standard-library imports, maps module names to canonical package identifiers (e.g., `cv2` $\rightarrow$ `opencv-python`, `sklearn` $\rightarrow$ `scikit-learn`, `bs4` $\rightarrow$ `beautifulsoup4`, `yaml` $\rightarrow$ `PyYAML`, `PIL` $\rightarrow$ `Pillow`), and checks registry maintenance metadata. Import discovery does not establish an installed version: these packages remain unresolved until an exact manifest pin, lockfile, or installed environment is available.

---

## Architectural Workflow

```mermaid
flowchart TD
    Target["Target Input (Directory or Manifest/Lockfile)"] --> L1["Layer 1: Manifests, Lockfiles & Build DSLs (12 Ecosystems)"]
    L1 --> L2["Layer 2: Installed Virtual & Vendor Environments (8 Runtimes)"]
    L2 --> L3{"Any Manifest or Env Found?"}
    L3 -->|No| Fallback["Layer 3: Source-Code Import Extraction (10 Languages)"]
    L3 -->|Yes| Dedupe["Dependency Deduplication & Installed-Version Pinning"]
    Fallback --> Dedupe

    Dedupe --> OSVBatch["Two-Phase OSV Batch Engine (/v1/querybatch -> /v1/vulns)"]
    Dedupe --> Stale["Concurrent Multi-Registry Staleness Checker + 12h Disk Cache"]

    OSVBatch --> LocalCVSS["In-Memory CVSS v3.1 Vector Calculator"]
    LocalCVSS --> NVDCheck{"CVSS Resolved?"}
    NVDCheck -->|No| NVDFallback["Parallel NIST NVD 2.0 API + 24h Disk Cache"]
    NVDCheck -->|Yes| KEVCheck["CISA KEV Catalog Check"]
    NVDFallback --> KEVCheck
    KEVCheck --> EPSS["Batched FIRST.org EPSS 30-Day Probability"]

    EPSS & Stale --> Scoring["Two-Dimensional Risk Matrix (CVSS + EPSS + CISA KEV)"]
    Scoring --> Report["Prioritized Terminal Report & Upgrade Guidance"]
    Scoring --> SBOM["CycloneDX v1.4 JSON SBOM (sbom.json)"]
    Scoring --> SARIF["OASIS SARIF v2.1.0 Report (results.sarif)"]

    Report --> Gate{"Critical-Exploitable Detected?"}
    Gate -->|Yes| ExitFail["Exit Code 1 (CI/CD Policy Failure)"]
    Gate -->|No| ExitPass["Exit Code 0 (Passed)"]
```

---

## Risk Scoring Matrix

| Priority Tier | Qualification Criteria | Description |
| :--- | :--- | :--- |
| **CRITICAL-EXPLOITABLE** | Listed in **CISA KEV** **OR** (`CVSS >= 7.0` and `EPSS >= 0.20` for the same advisory) | Confirmed active in-the-wild exploitation or severe vulnerability with high 30-day exploit probability. Triggers CI/CD exit code `1`. |
| **HIGH** | `CVSS >= 7.0` (`EPSS < 0.20` and not in CISA KEV) | High technical severity flaws without immediate indicators of active weaponization. |
| **MEDIUM** | `4.0 <= CVSS < 7.0` | Moderate security defects requiring scheduled patching. |
| **LOW** | `0.0 < CVSS < 4.0` | Low-impact advisories or defense-in-depth findings. |
| **NONE** | Completed checks found no advisories | No known advisories were returned for the scanned version. |
| **UNKNOWN** | Checks incomplete and no findings available | Resolve the reported errors before treating the scan as clean. |

---

## Installation & Distribution

`dep-tracker` is compiled as a single standalone executable with zero external runtime dependencies. It runs on Linux, macOS, and Windows without requiring Go, Python, or Node.js on the host machine.

### Method 1: Automated One-Line Install (Recommended)

Installs the latest standalone binary, configures your `PATH`, and makes `dep-tracker` globally available with no dependencies required:

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/nyumuharon/dependency-tracker/main/scripts/install.ps1 | iex
```

**Linux & macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/nyumuharon/dependency-tracker/main/scripts/install.sh | bash
```

Once installed, simply run `dep-tracker --help` from any directory!

---

### Method 2: Manual Standalone Downloads

If you prefer to download standalone binaries manually without an installer, grab the latest release from [GitHub Releases](https://github.com/nyumuharon/dependency-tracker/releases/latest):

| Operating System | Architecture | Binary Download Link | Archive (.zip / .tar.gz) |
| :--- | :--- | :--- | :--- |
| **Windows** | x86_64 / amd64 | [`dep-tracker-windows-amd64.exe`](https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-windows-amd64.exe) | [`.zip`](https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-windows-amd64.zip) |
| **Linux** | x86_64 / amd64 | [`dep-tracker-linux-amd64`](https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-linux-amd64) | [`.tar.gz`](https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-linux-amd64.tar.gz) |
| **Linux** | ARM64 / aarch64 | [`dep-tracker-linux-arm64`](https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-linux-arm64) | [`.tar.gz`](https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-linux-arm64.tar.gz) |
| **macOS** | Apple Silicon (M1-M4) | [`dep-tracker-darwin-arm64`](https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-darwin-arm64) | [`.tar.gz`](https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-darwin-arm64.tar.gz) |
| **macOS** | Intel (x86_64) | [`dep-tracker-darwin-amd64`](https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-darwin-amd64) | [`.tar.gz`](https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-darwin-amd64.tar.gz) |

---


### Method 3: Install via Go (`go install`)

If you have Go 1.26.3+ installed, install globally in one command:
```bash
go install github.com/nyumuharon/dependency-tracker/cmd/dep-tracker@latest
```
*(Make sure `$GOPATH/bin` or `%USERPROFILE%\go\bin` is in your `PATH`)*

---

### Method 4: Build from Source

```bash
git clone https://github.com/nyumuharon/dependency-tracker.git
cd dependency-tracker

# Linux / macOS
go build -ldflags="-s -w" -o dep-tracker ./cmd/dep-tracker

# Windows (PowerShell)
go build -ldflags="-s -w" -o dep-tracker.exe ./cmd/dep-tracker
```

---


## Usage

### 1. View Built-in Help and Commands
```bash
dep-tracker help
# or
dep-tracker --help
```

### 2. Recursive Project or Workspace Scan
Scan any project directory (manifests, virtual/vendor environments, or raw source code):
```bash
# Scan current directory
dep-tracker scan .

# Scan an external project directory
dep-tracker scan /path/to/project
```

### 3. Single Manifest, Lockfile, or Environment File Scan
```bash
dep-tracker scan package-lock.json
dep-tracker scan requirements.txt
dep-tracker scan pom.xml
dep-tracker scan Cargo.lock
dep-tracker scan obj/project.assets.json
```

### 4. Export CycloneDX SBOM & GitHub SARIF
```bash
# Export CycloneDX v1.4 JSON SBOM and OASIS SARIF v2.1.0 report
dep-tracker scan . --sbom reports/sbom.json --sarif reports/results.sarif
```

### 5. Machine-Readable JSON Output (for CI/CD Pipelines)
```bash
# Output raw JSON to stdout (status logs go to stderr)
dep-tracker scan . --json > scan-report.json
```

### 6. Filter Unmaintained / Stale Packages Only
```bash
# Audit dependencies with no release in over 2 years (730 days)
dep-tracker scan . --stale-only
```

### 7. Version Information
```bash
dep-tracker version
# or
dep-tracker -v
```

### 8. Self-Update in Place
```bash
dep-tracker update
```
Automatically checks GitHub Releases for new versions and upgrades the `dep-tracker` binary in-place. Both installers and the updater require the downloaded binary to match its entry in the release’s `SHA256SUMS.txt`. Missing checksums, download failures, and mismatches stop installation before replacing an existing binary.

---

## Scan completeness and version confidence

Each JSON package result includes `ScanStatus` (`complete` or `incomplete`), `CheckErrors`, and `Pkg.VersionSource` (`manifest`, `lockfile`, `installed`, `constraint`, or `import`). Lockfile and installed-environment decisions are scoped to each project directory, so sibling projects in a monorepo are resolved independently. Go directory scans prefer `go.mod` over `go.sum`, which can include historical dependency versions.

Ranges such as `^1.2.3`, `>=2.0,<3`, Cargo's implicit caret ranges, and unpinned imports are preserved. They are resolved against local installed environments when available. Otherwise vulnerability checks for those packages remain incomplete; the scanner never substitutes the latest registry version. An exact manifest pin identifies a declared version, not proof that the package is installed.

OSV failures, unavailable KEV/EPSS data, missing severity data, and failed maintenance checks are reported explicitly. Stale KEV data may still supply known findings, but a failed refresh makes the scan incomplete. A package with findings retains its known priority even if another check fails. `--stale-only` also includes incomplete results so errors remain visible. The SBOM and SARIF always cover the full result set; SARIF records incomplete checks as execution notifications.

Fixed releases are selected for the queried package and the affected interval containing its scanned version. Version comparisons use SemVer for npm, Go, Cargo, and Pub, and numeric release ordering for other ecosystems. Unsupported qualifiers produce no guessed recommendation. The remediation table lists individual fixed releases rather than presenting one version as a guaranteed fix for every advisory. Verify branch compatibility before upgrading.

| Exit code | Meaning |
| :--- | :--- |
| `0` | Checks and exports completed, with no critical-exploitable package. HIGH/MEDIUM/LOW findings may still exist. |
| `1` | A completed scan found a critical-exploitable package, or arguments/input could not be processed. |
| `2` | Checks were incomplete, versions unresolved, or a report could not be written. Takes precedence over code `1` for incomplete scans. |

Report parent directories are created automatically. SBOM and SARIF metadata use the running application version. Unresolved dependencies have their original version declaration recorded as a property, without a fabricated version or PURL.

---

## Testing

Run the parser, scoring, mocked API/CLI failure, report export, checksum, and installer regression tests:
```bash
go test -v -race -cover ./...
go vet ./...
bash scripts/test-install.sh
```

---

Pushes and pull requests run CI checks. The release workflow also runs the race-enabled Go tests and `go vet` before building and publishing binaries.

## License

This project is licensed under the MIT License.
