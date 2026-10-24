# Changelog

## 1.0.6

- Resolve dependency discovery independently for sibling projects and include nested installed npm dependencies.
- Preserve version constraints and mark unresolved versions and failed checks as incomplete. Incomplete scans and failed exports return exit code 2.
- Apply CVSS and EPSS thresholds to each advisory, and select fixed releases for the scanned package and affected interval.
- Include actual application versions and incomplete-check details in SBOM and SARIF reports; create report directories automatically.
- Verify release SHA-256 checksums before installing or updating binaries.
- Run regression tests in CI and before release, including native Windows installer and PATH tests.
- Add workflows for live Linux and Windows installation checks against published releases.

Go tests cover 51.7% of statements, up from 27.3% before the reliability fixes.
