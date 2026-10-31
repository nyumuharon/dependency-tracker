# Real-world validation — 31 October 2026

The following public repositories were cloned read-only outside the source tree.
No project installation or build scripts were executed. Each primary manifest or
lockfile was parsed and compared against checksum-verified Syft 1.55.0 using the
same files. npm development dependencies were enabled in Syft; application/root
records and Go's standard library were excluded from dependency comparisons.

| Project | Pinned commit | Input | Tracker entries | Syft entries | Missing / extra |
| --- | --- | --- | ---: | ---: | --- |
| [Axios](https://github.com/axios/axios) | `9d11464a75ee5c644c0308d742f58755c0482594` | `package-lock.json` | 661 | 661 | 0 / 0 |
| [Gin](https://github.com/gin-gonic/gin) | `0f09c3a9b4626d9fe9979cf4d0521d6ae32ab646` | `go.mod` and `go.sum` | 32 | 32 | 0 / 0 |
| [bat](https://github.com/sharkdp/bat) | `8f5727ea3869a71c65c0f4f4a42ed18bdb26ae7b` | `Cargo.lock` and `Cargo.toml` | 317 | 317 | 0 / 0 |
| [Poetry](https://github.com/python-poetry/poetry) | `906ba21dff6f08c0df7d381a5e7879e12f6102e0` | `poetry.lock` | 75 | 75 | 0 / 0 |

All 1,085 inventory entries matched across these four pinned projects. This
checks package identities and versions, not reachability or exploitability.
Other revisions, formats, and dependency managers need their own validation.

## Full online scans

Actual release-source scanner executions queried OSV, NVD, EPSS, KEV and package
registries, writing JSON, CycloneDX and SARIF reports outside the repository.

| Project | Dependencies | Scanner-reported advisory occurrences | Packages with incomplete intelligence | Exit |
| --- | ---: | ---: | ---: | ---: |
| Axios | 661 | 4 | 1 | 2 |
| Gin | 32 | 8 | 2 | 2 |
| bat | 317 | 5 | 5 | 2 |
| Poetry | 75 | 18 | 2 | 2 |

These counts are observations from the run, not independently confirmed
exploitation findings. Incomplete results were caused by missing severity or
EPSS information in the upstream responses, including advisories without a CVSS
rating. Exit 2 correctly prevents treating these scans as clean or complete.
Advisory occurrences may repeat across package versions. Intelligence changes
over time; reruns may produce different findings.

Existing projects on the local machine were also scanned read-only. Their
reports and dependency details remain in local storage to preserve privacy.

## Reproduce the inventory comparison

Clone the four repositories into a directory with child names `axios`, `gin`,
`bat`, and `poetry`, and check out the pinned commits above. Then run:

```bash
REALWORLD_ROOT=/path/to/clones SYFT_BINARY=/path/to/syft \
  go test ./cmd/dep-tracker -run TestRealWorldInventories -v -count=1
```

The test writes `inventory-comparison.json` beside the clones with exact commits,
counts, timings and full differences. The integration test is opt-in so ordinary
unit tests require neither network access nor arbitrary external repositories.
