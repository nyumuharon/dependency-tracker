# Changelog

## Unreleased

- Date Maven staleness from the most recently published version instead of the highest version number, so a maintained release line is not reported stale because of an old pre-release on a newer major.
- Report the fixed release when an advisory's introduced version carries a qualifier (such as `2.0-beta9`) and the scanned version belongs to a later numeric release.
- Rank an advisory with no severity from any source as `UNKNOWN` instead of `LOW`, and show the score as unknown instead of `0.0`.
- Fall back to the advisory database's qualitative rating (low, moderate, high, critical) when neither OSV nor NVD supplies a CVSS score. The JSON report gains a `Severity` field per vulnerability.
- Report a missing severity once per advisory instead of twice, and count `UNKNOWN` packages in the tier breakdown.
- Track source-import coverage per ecosystem. A manifest no longer hides imports of other languages in its directory tree, which previously let mixed-language projects pass as clean.
- Report unreadable source files and directories during import discovery as discovery errors instead of silently skipping them, and read long source lines without losing the imports that follow.

Missed and misidentified dependencies:
- requirements.txt: check hash-pinned requirements (`--hash`, `\` continuations), `==` with spaces, and `-r` includes; report direct references (`name @ url`) under the package name.
- go.mod: apply `replace` directives. Conan 2 `conan.lock`: read `requires`, `build_requires` and `python_requires`.
- npm/Yarn: check aliased packages (`npm:real@version`) as the real package; include `optionalDependencies`.
- Cargo: include `[dependencies.name]` subtables, platform-specific and workspace dependencies and renamed crates; skip path, Git and workspace-local crates, including unpublished crates in `Cargo.lock`.
- pyproject.toml: include uv and PDM development dependencies and Poetry dependency subtables; stop reporting `include-group` entries as packages.
- Maven: resolve nested and embedded properties and versions managed by `dependencyManagement`; skip imported BOMs. .NET: resolve `$(Property)` versions and `VersionOverride`.
- Gemfile.lock: strip platform suffixes (`1.10.0-x86_64-linux`).
- Prefer lockfiles over manifests for Pipfile, Gemfile, pubspec, mix, NuGet, Swift and Gradle too.
- Scan folders named `build`, `dist`, `target`, `bin` and `env` unless they are build output beside a dependency file; recognise virtual environments by `pyvenv.cfg`; never skip the scan root because of its name.
- Keep partial results, marked incomplete, when a folder is unreadable or a manifest is malformed, instead of ending the scan with no report.
- Use the installed version instead of a mismatched manifest pin, including manifests in subfolders of the environment's project.
- Source imports: scope local module names to their project (a folder needs `__init__.py` to be a Python package), map `google.*`, Go vanity-host and versioned module paths, and Symfony and other PHP namespaces to real packages, handle `import a, b`, skip docstrings, and use the full Python 3.12 standard library list.

Scans wrongly marked incomplete:
- Pace and retry NVD requests (and accept `NVD_API_KEY`), read CVSS v4.0 scores from NVD, and only report a failed NVD lookup when no other source rated the advisory.
- Date ConanCenter releases from their first recipe revision, read large NuGet packages' paged release lists and prefer stable releases, and date crates by their newest stable release instead of the last metadata change.
- Skip RustSec "unmaintained" notices and withdrawn advisories; merge advisories that list each other as aliases.

Reports, release and installers:
- SARIF: describe each rule by its vulnerability rather than the first affected package, omit `security-severity` when unknown, add per-package fingerprints, and give locations relative to the repository root (or as absolute file URIs outside it).
- SBOM: normalise PyPI PURLs and add `bom-ref` and `serialNumber`.
- Terminal report: keep the remediation table aligned for long names, order fixed releases by version, and note what `--stale-only` summarises; report generation no longer reorders the SBOM and SARIF.
- Write caches atomically. On Windows, report where the previous binary is if an update cannot restore it.
- Installers: compare PATH entries exactly on Windows; on Linux and macOS create a missing `/usr/local/bin` and replace the binary by rename.
- Release: fail when the tag does not match `appVersion`, build with the CI-tested Go version, and limit write permission to the publishing job. CI also runs the Go tests on Windows.

## 1.0.8

- Represent missing EPSS scores as unknown/null, preserve confirmed zero, and reject missing, duplicate, non-finite, and out-of-range scores.
- Propagate installed-environment read and parse errors, retain recovered dependencies, and return incomplete-scan status instead of silent omissions.
- Expand parser accuracy tests to 36 cases across all 12 ecosystems; fix Yarn Berry, pnpm v5, Dart/Elixir lockfiles, setup.py metadata leakage, and Conda equality handling.
- Compare the shared npm fixture with npm and checksum-verified Syft 1.55.0 in CI.
- Run native Linux/macOS race tests, builds and executable checks; require exact 100% statement coverage with no excluded source files.
- Validate public Axios, Gin, bat and Poetry inventories against Syft, and exercise full online scans of public and existing local projects.
- Cover interrupted update downloads, disk/permission errors, process exit behavior, malformed manifests and every report tier; reject invalid CVSS numbers and missing catalog/date metadata.
- Add cross-platform cache isolation, API/cache/report regression tests, and the MIT license in source and release archives.

## 1.0.7

- Decode binary HTTP checksum responses in the Windows PowerShell installer before validating checksums.
- Cover text and byte checksum responses, duplicate checksums, CLI argument errors, scoring boundaries, CVSS vectors, and EPSS batching with regression tests.
- Go statement coverage is now 53.0%.

## 1.0.6

- Resolve dependency discovery independently for sibling projects and include nested installed npm dependencies.
- Preserve version constraints and mark unresolved versions and failed checks as incomplete. Incomplete scans and failed exports return exit code 2.
- Apply CVSS and EPSS thresholds to each advisory, and select fixed releases for the scanned package and affected interval.
- Include actual application versions and incomplete-check details in SBOM and SARIF reports; create report directories automatically.
- Verify release SHA-256 checksums before installing or updating binaries.
- Run regression tests in CI and before release, including native Windows installer and PATH tests.
- Add workflows for live Linux and Windows installation checks against published releases.

Go tests cover 51.7% of statements, up from 27.3% before the reliability fixes.
