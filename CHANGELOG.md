# Changelog

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
