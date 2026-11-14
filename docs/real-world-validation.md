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

## Additional ecosystems — 15 November 2026

Eight more projects were compared with checksum-verified Syft 1.55.0 on the same
files. Rerunning the four comparisons above after the 1.1.0 parser changes still
gives 0 missing and 0 extra entries (bat's own root crate is now excluded, like
an npm application's root record).

| Project | Pinned commit | Input | Tracker | Syft | Result |
| --- | --- | --- | ---: | ---: | --- |
| [React](https://github.com/facebook/react) | `df6aa4ec76cff5b3adde531c6fe8c36099e0469b` | `yarn.lock` | 2,042 | 2,042 | Exact match |
| [Flask](https://github.com/pallets/flask) | `49943b5a94413a530761350f04e896f76e8d620e` | `uv.lock` | 79 | 79 | Exact match |
| [Pydantic](https://github.com/pydantic/pydantic) | `560f0f96a37d6913afdfddb2de22030ef08e68c3` | `uv.lock` | 165 | 167 | Match; Syft's two extra entries are the project's own editable packages, with no version |
| [Symfony Demo](https://github.com/symfony/demo) | `f42980c690b4bf335fa41bbafdb075bb67b719c2` | `composer.lock` | 155 | 101 | Match; the tracker strips the `v` version prefix and includes the 54 `packages-dev` entries |
| [Vite](https://github.com/vitejs/vite) | `f898888222297aa56d6fc281c585d4d4e4d51f58` | `pnpm-lock.yaml` | 1,208 | 1,330 | Match after a fix; the 122 Syft-only entries are local `file:` workspace folders |
| [Rails](https://github.com/rails/rails) | `50c54eed065b8bfb1b0bbb5fa770c859baa98f9b` | `Gemfile.lock` | 219 | 269 | Match after a fix; Syft also lists Rails' own `PATH` gems and each platform build of a gem separately |
| [Spring Petclinic](https://github.com/spring-projects/spring-petclinic) | `500158f732419217507c7656904b8e6aa1bcc0d6` | `pom.xml` | 28 | 29 | Fixed; Syft lists 25 dependencies with unknown versions (inherited from the Spring Boot parent) and the project itself; the tracker now resolves them through the parent POM chain |
| [eShop](https://github.com/dotnet/eShop) | `913acea66708a59595351174cee9b29f37179d29` | directory | 89 NuGet | — | Syft does not read `Directory.Packages.props`; every package referenced by a `.csproj` was found |

These comparisons found four defects, fixed in the release after 1.1.0:

- **Maven:** dependencies whose versions come from a parent POM were silently left out (3 of 28 found for Petclinic). Versions are now resolved through parent POMs and imported BOMs.
- **NuGet:** every plain `Version="…"` was treated as a range, so .NET projects were never checked.
- **pnpm:** local `file:` workspace folders were reported as unresolved, so every pnpm monorepo scan was incomplete.
- **Bundler:** the project's own `PATH` gems were looked up as published gems.

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
