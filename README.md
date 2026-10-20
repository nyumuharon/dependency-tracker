# Dependency Risk Tracker (`dep-tracker`)

[![Go Version](https://img.shields.io/badge/go-1.24-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#installation)

**Dependency Risk Tracker (`dep-tracker`)** is a high-speed, zero-dependency Software Composition Analysis (SCA) and software supply chain security CLI tool written in pure Go. It discovers, analyzes, and prioritizes vulnerabilities and maintenance risks across modern software projects—even when a project lacks a lockfile or manifest.

The tool combines a **Three-Layer Intelligent Dependency Discovery Engine** with a **Two-Phase Batch OSV & NVD Vulnerability Pipeline**, an in-memory **CVSS v3.1 Vector Calculator**, **FIRST.org EPSS** 30-day exploit probabilities, **CISA Known Exploited Vulnerabilities (KEV)** catalog alerts, **Multi-Registry Staleness Auditing**, and automated generation of **CycloneDX v1.4 SBOM** (`sbom.json`) and **OASIS SARIF v2.1.0** (`results.sarif`) compliance reports.

---

## Key Capabilities

* **Three-Layer Intelligent Dependency Discovery**:
  * **Layer 1 — Manifests, Lockfiles & Build DSLs**: Recursively detects and parses 30+ manifest, lockfile, and build DSL formats across **12 ecosystems** (npm/Yarn/pnpm, PyPI/Poetry/Pipenv/uv/Conda, Maven/Gradle, NuGet/.NET, Cargo/Rust, Go Modules, Composer/PHP, RubyGems/Bundler, Conan/vcpkg/CMake, Dart/Flutter Pub, Elixir Mix, and Swift Package Manager). Automatically resolves unpinned manifests against exact versions installed in local environments.
  * **Layer 2 — Installed Virtual & Vendor Environment Introspection**: Automatically inspects **8 installed environment formats** when lockfiles are absent or manifests use loose version specifiers (`>=`, `^`, `*`): Python `venv`/`.venv` (`*.dist-info/METADATA`), Node `node_modules/*/package.json`, .NET `obj/project.assets.json`, PHP `vendor/composer/installed.json`, Go `vendor/modules.txt`, Ruby `vendor/bundle/**/*.gemspec`, C/C++ `vcpkg_installed/vcpkg/status`, and Dart `.dart_tool/package_config.json`.
  * **Layer 3 — Zero-Manifest Source-Code Import Fallback**: Extracts third-party imports directly from source files across **10 programming language families** (`.py`, `.js`/`.ts`/`.jsx`/`.tsx`, `.go`, `.rs`, `.c`/`.cpp`/`.h`/`.hpp`, `.java`/`.kt`, `.cs`, `.php`, `.rb`, and `.dart`), filters out standard-library modules, maps import names to canonical registry packages, and resolves their versions via upstream registries.
* **High-Speed Two-Phase Batch OSV Engine**: Uses a pooled HTTP/2 transport (`MaxIdleConnsPerHost: 32`) to query `/v1/querybatch` in a single round-trip for all discovered packages and concurrently hydrates `/v1/vulns/<id>` only for packages with matching advisories.
* **Instant In-Memory CVSS v3.1 Vector Calculator & Cached NVD 2.0 Fallback**: Computes exact CVSS v3.1 base scores in memory (0 ms) from vector strings using official FIRST.org equations, with parallelized NIST NVD CVE 2.0 API fallback backed by a 24-hour local disk cache (`nvd_cache.json`).
* **CISA KEV & FIRST EPSS Exploitability Prioritization**: Cross-references every CVE against CISA's Known Exploited Vulnerabilities (KEV) catalog and queries FIRST.org EPSS in batches to compute a two-dimensional four-tier risk priority (`CRITICAL-EXPLOITABLE`, `HIGH`, `MEDIUM`, `LOW`).
* **Fast Multi-Registry Staleness Auditing**: Audits package maintenance health concurrently across npm, PyPI lightweight RSS release feeds (`~10 KB` instead of multi-MB JSON payloads), Maven Central, NuGet, Crates.io, Go Proxy, Packagist, RubyGems, ConanCenter, Pub.dev, and Hex.pm with a 12-hour local disk cache (`staleness_cache.json`), flagging packages untouched for > 2 years (730 days).
* **CycloneDX v1.4 SBOM & OASIS SARIF v2.1.0 Export**: Automatically generates `sbom.json` (with standardized PURLs and embedded CVSS/EPSS/KEV ratings) and `results.sarif` (for GitHub Code Scanning and CI/CD inline PR annotations).

---

## Installation

Because `dep-tracker` is written in Go with zero external C library dependencies, it is distributed as a single standalone executable binary that runs on Linux, macOS, and Windows without requiring any runtime (no Node.js, Python, or Go needed).

### 1. Pre-compiled Binaries (GitHub Releases)

Download the binary matching your operating system and architecture from the [GitHub Releases](https://github.com/nyumuharon/dependency-tracker/releases) page:

#### Linux & macOS (curl / bash)
```bash
# Linux (x86_64)
curl -sSL -o dep-tracker https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-linux-amd64
chmod +x dep-tracker
sudo mv dep-tracker /usr/local/bin/

# Linux (ARM64 / Graviton)
curl -sSL -o dep-tracker https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-linux-arm64
chmod +x dep-tracker
sudo mv dep-tracker /usr/local/bin/

# macOS (Apple Silicon M1-M4)
curl -sSL -o dep-tracker https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-darwin-arm64
chmod +x dep-tracker
sudo mv dep-tracker /usr/local/bin/

# macOS (Intel)
curl -sSL -o dep-tracker https://github.com/nyumuharon/dependency-tracker/releases/latest/download/dep-tracker-darwin-amd64
chmod +x dep-tracker
sudo mv dep-tracker /usr/local/bin/
```

#### Windows
Download `dep-tracker-windows-amd64.exe` from GitHub Releases and add it to your system `PATH`.

---

### 2. Package Managers

* **macOS & Linux (Homebrew)**:
  ```bash
  brew install nyumuharon/tap/dep-tracker
  ```

* **Windows (WinGet)**:
  ```powershell
  winget install NyumuHaron.DependencyRiskTracker
  ```

* **Windows (Scoop)**:
  ```powershell
  scoop install dep-tracker
  ```

---

### 3. Install via Go (`go install`)

If you have Go 1.22+ installed:
```bash
go install github.com/nyumuharon/dependency-tracker/cmd/dep-tracker@latest
```

---

### 4. Build from Source

```bash
git clone https://github.com/nyumuharon/dependency-tracker.git
cd dependency-tracker
go build -ldflags="-s -w" -o dep-tracker ./cmd/dep-tracker
```

To compile release binaries for all platforms:
```bash
./scripts/build-release.sh
```
Compiled standalone binaries and SHA-256 checksums are generated in the `dist/` directory.

---

## Quick Start & Usage Reference

### Built-in Help
Display full usage instructions, available subcommands, options, and supported ecosystems:
```bash
dep-tracker help
# or
dep-tracker --help
```

### Scan a Project Directory
Recursively scan a project directory for manifests, virtual/vendor environments, or raw source imports:
```bash
# Scan the current directory
dep-tracker scan .

# Scan an external directory
dep-tracker scan /path/to/project
```

### Scan a Specific Manifest or Lockfile
```bash
dep-tracker scan package-lock.json
dep-tracker scan requirements.txt
dep-tracker scan pom.xml
dep-tracker scan Cargo.lock
dep-tracker scan obj/project.assets.json
```

### Export CycloneDX SBOM & GitHub SARIF
Generate compliance artifacts during scan:
```bash
dep-tracker scan . --sbom sbom.json --sarif results.sarif
```
* **`sbom.json`**: CycloneDX v1.4 JSON Software Bill of Materials with standardized Package URLs (PURLs) and vulnerability details.
* **`results.sarif`**: OASIS SARIF v2.1.0 report compatible with GitHub Code Scanning alerts and CI/CD pipelines.

### Machine-Readable JSON Mode (CI/CD Pipelines)
Output scan results as raw JSON to standard output (progress messages stream to stderr):
```bash
dep-tracker scan . --json > scan-results.json
```

### Audit Stale / Unmaintained Dependencies Only
Filter findings to packages whose latest registry release is older than 2 years (730 days):
```bash
dep-tracker scan . --stale-only
```

### Check Version
```bash
dep-tracker version
# or
dep-tracker -v
```

---

## Risk Scoring Matrix

Vulnerabilities are evaluated using a two-dimensional matrix combining technical severity (CVSS v3.1), real-world exploit probability (FIRST.org EPSS), and confirmed active attacks (CISA KEV catalog):

| Priority Tier | Qualification Criteria | Description | CI/CD Exit Code |
| :--- | :--- | :--- | :--- |
| **CRITICAL-EXPLOITABLE** | Listed in **CISA KEV** **OR** (`CVSS >= 7.0` and `EPSS >= 0.20`) | Active in-the-wild exploitation or severe flaw with high probability of weaponization. Requires immediate mitigation. | **`1`** (Build Failure) |
| **HIGH** | `CVSS >= 7.0` (`EPSS < 0.20` and not in CISA KEV) | High technical severity flaw without immediate evidence of mass exploitation. | `0` |
| **MEDIUM** | `4.0 <= CVSS < 7.0` | Moderate technical flaw to be addressed in standard patch cycle. | `0` |
| **LOW** | `0.0 < CVSS < 4.0` | Low-severity finding or defense-in-depth advisory. | `0` |
| **NONE** | No CVEs detected | Package has no known security advisories in official threat feeds. | `0` |

---

## Supported Ecosystems & Three-Layer Discovery Matrix

### Layer 1: Manifests, Lockfiles & Build DSLs

| Ecosystem | Languages | Lockfiles (Transitive) | Manifests & Build DSLs (Direct) | Upstream Registry |
| :--- | :--- | :--- | :--- | :--- |
| **npm** | JavaScript, TypeScript | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `package.json` | `registry.npmjs.org` |
| **PyPI** | Python | `poetry.lock`, `Pipfile.lock`, `uv.lock` | `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py`, `environment.yml` | `pypi.org` (JSON & RSS) |
| **Maven / Gradle** | Java, Kotlin, Scala | `gradle.lockfile` | `pom.xml`, `build.gradle`, `build.gradle.kts`, `libs.versions.toml` | `search.maven.org` |
| **NuGet** | C#, F#, .NET | `packages.lock.json`, `paket.lock` | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config` | `api.nuget.org` |
| **crates.io** | Rust | `Cargo.lock` | `Cargo.toml` | `crates.io` |
| **Go** | Go | `go.sum` | `go.mod` | `proxy.golang.org` |
| **Packagist** | PHP | `composer.lock` | `composer.json` | `repo.packagist.org` |
| **RubyGems** | Ruby | `Gemfile.lock` | `Gemfile`, `*.gemspec` | `rubygems.org` |
| **ConanCenter** | C, C++ | `conan.lock` | `conanfile.txt`, `vcpkg.json`, `CMakeLists.txt` | `conan.io` / GitHub |
| **Pub** | Dart, Flutter | `pubspec.lock` | `pubspec.yaml` | `pub.dev` |
| **Hex** | Elixir, Erlang | `mix.lock` | `mix.exs` | `hex.pm` |
| **SwiftURL** | Swift | `Package.resolved` | `Package.swift` | GitHub / SwiftPM |

### Layer 2: Installed Virtual & Vendor Environments

| Runtime / Ecosystem | Inspected Environment Path / Artifact | Resolution Behavior |
| :--- | :--- | :--- |
| **Python (`PyPI`)** | `venv/`, `.venv/`, `env/` (`site-packages/*.dist-info/METADATA`) | Resolves exact installed versions; upgrades unpinned `requirements.txt` ranges |
| **Node.js (`npm`)** | `node_modules/*/package.json` | Resolves installed direct & transitive packages when lockfiles are missing |
| **.NET (`NuGet`)** | `obj/project.assets.json` | Extracts exact resolved package dependency graph |
| **PHP (`Packagist`)** | `vendor/composer/installed.json` | Extracts exact installed Composer v1/v2 packages |
| **Go (`Go`)** | `vendor/modules.txt` | Extracts vendored Go module names and versions |
| **Ruby (`RubyGems`)** | `vendor/bundle/**/specifications/*.gemspec` | Extracts exact bundled Gem names and versions |
| **C/C++ (`ConanCenter`)** | `vcpkg_installed/vcpkg/status` | Parses Debian-control style package install status blocks |
| **Dart / Flutter (`Pub`)** | `.dart_tool/package_config.json` | Extracts resolved packages and versions from cache paths |

### Layer 3: Zero-Manifest Source-Code Import Fallback

When a target directory contains raw source code with no manifest, lockfile, or environment, `dep-tracker` analyzes `.py`, `.js`/`.ts`/`.jsx`/`.tsx`, `.go`, `.rs`, `.c`/`.cpp`/`.h`/`.hpp`, `.java`, `.kt`, `.cs`, `.php`, `.rb`, and `.dart` files:
1. Strips comments and string literals.
2. Identifies `import`, `require`, `#include`, `using`, and `use` directives.
3. Filters out language standard-library modules.
4. Maps import names to canonical registry packages (e.g., `cv2` $\rightarrow$ `opencv-python`, `sklearn` $\rightarrow$ `scikit-learn`, `bs4` $\rightarrow$ `beautifulsoup4`, `yaml` $\rightarrow$ `PyYAML`, `PIL` $\rightarrow$ `Pillow`).
5. Queries public registries to determine latest releases and audits for vulnerabilities and staleness.

---

## Project Structure

```
dependency_risk_tracker/
├── cmd/
│   └── dep-tracker/              # Main CLI application entrypoint & subcommands
│       ├── main.go               # Command-line interface, help handler & orchestration
│       ├── parsers.go            # Layer 1-3 multi-ecosystem dependency discovery
│       ├── osv_client.go         # Two-phase batch OSV client & CVSS v3.1 calculator
│       ├── nvd_client.go         # NIST NVD 2.0 fallback client & disk cache
│       ├── epss_client.go        # FIRST.org EPSS 30-day exploitation probability client
│       ├── kev_client.go         # CISA Known Exploited Vulnerabilities (KEV) catalog
│       ├── staleness_client.go   # Multi-registry staleness checker & PyPI RSS cache
│       ├── scorer.go             # Two-dimensional risk priority classification
│       ├── sbom_generator.go     # CycloneDX v1.4 JSON SBOM exporter
│       └── sarif_generator.go    # OASIS SARIF v2.1.0 GitHub Code Scanning exporter
├── dist/                         # Compiled standalone release binaries & checksums
│   ├── dep-tracker-linux-amd64
│   ├── dep-tracker-linux-arm64
│   ├── dep-tracker-windows-amd64.exe
│   ├── dep-tracker-windows-arm64.exe
│   ├── dep-tracker-darwin-amd64
│   ├── dep-tracker-darwin-arm64
│   └── SHA256SUMS.txt
├── scripts/
│   └── build-release.sh          # Automated multi-platform compilation script
├── docs/                         # System architecture & academic documentation
├── go.mod                        # Go module definition
├── README.md                     # Technical documentation & usage manual
├── sbom.json                     # Generated CycloneDX v1.4 SBOM
└── results.sarif                 # Generated OASIS SARIF v2.1.0 report
```

---

## Testing

Run unit tests, parser verification, and race condition tests:
```bash
go test -v -race ./...
```

---

## License

This project is licensed under the [MIT License](LICENSE).
