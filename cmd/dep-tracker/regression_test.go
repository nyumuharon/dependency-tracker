package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeFixture(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMonorepoInstalledDependenciesStayInTheirProject(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "app-a/package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/shared":{"version":"1.0.0"}}}`)
	writeFixture(t, root, "app-b/package.json", `{"dependencies":{"shared":"^2.0.0"}}`)
	writeFixture(t, root, "app-b/node_modules/shared/package.json", `{"name":"shared","version":"2.3.0"}`)
	writeFixture(t, root, "app-b/node_modules/shared/node_modules/transitive/package.json", `{"name":"transitive","version":"3.0.0"}`)
	writeFixture(t, root, "app-c/package.json", `{"dependencies":{"shared":"^4.0.0"}}`)
	writeFixture(t, root, "app-d/main.py", "import requests\n")
	pkgs, _, err := DiscoverDependencies(root)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]Package{}
	for _, p := range pkgs {
		found[filepath.Base(p.ProjectPath)+":"+p.Name] = p
	}
	for key, version := range map[string]string{"app-a:shared": "1.0.0", "app-b:shared": "2.3.0", "app-b:transitive": "3.0.0", "app-c:shared": "^4.0.0", "app-d:requests": "latest"} {
		if p := found[key]; p.Version != version {
			t.Errorf("%s: got %+v, want version %s", key, p, version)
		}
	}
	if found["app-b:shared"].VersionSource != "installed" {
		t.Fatal("installed version provenance missing")
	}
	if validateQueryVersion(found["app-c:shared"]) == nil {
		t.Fatal("sibling's installation must not resolve app-c")
	}
	if validateQueryVersion(found["app-d:requests"]) == nil {
		t.Fatal("imports must not claim the latest version is installed")
	}
}

func TestDiscoveryRejectsMalformedManifest(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "package.json", `{"dependencies":`)
	if _, _, err := DiscoverDependencies(root); err == nil {
		t.Fatal("malformed manifest was silently skipped")
	}
}

func TestVersionConstraintsAndExactPins(t *testing.T) {
	root := t.TempDir()
	fixtures := []struct {
		name, content string
		exact         map[string]bool
	}{
		{"package.json", `{"dependencies":{"range":"^1.2.3","pin":"1.2.3","wildcard":"*"}}`, map[string]bool{"range": false, "pin": true, "wildcard": false}},
		{"requirements.txt", "requests>=2.0,<3\nflask==2.3.0\nhttpx\n", map[string]bool{"requests": false, "flask": true, "httpx": false}},
		{"Cargo.toml", "[dependencies]\nrange = \"1.2.3\"\npin = \"=1.2.3\"\n", map[string]bool{"range": false, "pin": true}},
		{"app.csproj", `<Project><ItemGroup><PackageReference Include="range" Version="1.2.3"/><PackageReference Include="pin" Version="[1.2.3]"/></ItemGroup></Project>`, map[string]bool{"range": false, "pin": true}},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			path := writeFixture(t, root, f.name, f.content)
			pkgs, err := ParseManifest(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(pkgs) != len(f.exact) {
				t.Fatalf("got %+v", pkgs)
			}
			for _, p := range pkgs {
				if (validateQueryVersion(p) == nil) != f.exact[p.Name] {
					t.Errorf("incorrect confidence: %+v", p)
				}
			}
		})
	}
}

func TestGoManifestPreferredOverHistoricalChecksums(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module example.com/app\n\ngo 1.26.3\nrequire example.com/dep v2.0.0\n")
	writeFixture(t, root, "go.sum", "example.com/dep v1.0.0 h1:old\nexample.com/dep v2.0.0 h1:new\n")
	pkgs, _, err := DiscoverDependencies(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Version != "v2.0.0" {
		t.Fatalf("historical versions included: %+v", pkgs)
	}
}

func TestPriorityThresholdsUseTheSameVulnerability(t *testing.T) {
	vulns := []Vulnerability{{CVSS: 9.8, EPSS: .01}, {CVSS: 3.0, EPSS: .9}}
	if got := ScoreVulnerabilities(vulns); got != "HIGH" {
		t.Fatalf("got %s", got)
	}
	vulns[0].EPSS = .2
	if got := ScoreVulnerabilities(vulns); got != "CRITICAL-EXPLOITABLE" {
		t.Fatalf("got %s", got)
	}
}

func TestFixedReleaseMatchesPackageAndAffectedInterval(t *testing.T) {
	var res osvResponse
	err := json.Unmarshal([]byte(`{"vulns":[{"id":"GHSA-test","affected":[
 {"package":{"name":"other","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"99.0.0"}]}]},
 {"package":{"name":"example","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.5.0"},{"introduced":"2.0.0"},{"fixed":"2.5.0"},{"introduced":"9.0.0"},{"fixed":"10.0.0"}]}]}
 ]}]}`), &res)
	if err != nil {
		t.Fatal(err)
	}
	for version, want := range map[string]string{"1.2.0": "1.5.0", "2.2.0": "2.5.0", "9.2.0": "10.0.0", "2.7.0": ""} {
		got := parseVulns(res, Package{Name: "example", Ecosystem: "npm", Version: version})[0].FixedVersion
		if got != want {
			t.Errorf("%s: got %s, want %s", version, got, want)
		}
	}
}

func TestVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b, eco string
		want      int
		ok        bool
	}{
		{"9.0.0", "10.0.0", "npm", -1, true},
		{"1.0.0-rc.2", "1.0.0-rc.10", "npm", -1, true},
		{"1.0.0", "1.0.0-rc.1", "npm", 1, true},
		{"1.0.0+build1", "1.0.0+build2", "npm", 0, true},
		{"1.10", "1.9", "PyPI", 1, true},
		{"1.0.Final", "1.0.CR1", "Maven", 0, false},
	} {
		got, ok := compareVersions(tc.a, tc.b, tc.eco)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("%+v: %d, %v", tc, got, ok)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func mockHTTP(t *testing.T, handler roundTripFunc) {
	t.Helper()
	old := httpClient
	httpClient = &http.Client{Transport: handler}
	t.Cleanup(func() { httpClient = old })
}
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestOSVBatchRejectsMissingResultsAndDetailFailures(t *testing.T) {
	for _, mode := range []string{"missing", "detail-failure", "clean"} {
		t.Run(mode, func(t *testing.T) {
			mockHTTP(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/v1/querybatch" {
					if mode == "missing" {
						return response(200, `{"results":[]}`), nil
					}
					if mode == "clean" {
						return response(200, `{"results":[{}]}`), nil
					}
					return response(200, `{"results":[{"vulns":[{"id":"GHSA-test"}]}]}`), nil
				}
				return response(503, `{}`), nil
			})
			pkg := Package{Name: "example", Version: "1.0.0", Ecosystem: "npm"}
			got, err := QueryOSVBatch([]Package{pkg})
			if mode == "clean" {
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := got[pkg.Key()]; !ok {
					t.Fatal("clean result must be explicit")
				}
			} else if err == nil {
				t.Fatal("expected an incomplete query error")
			}
		})
	}
}

func TestReleaseChecksumValidation(t *testing.T) {
	sum := sha256.Sum256([]byte("binary"))
	valid := hex.EncodeToString(sum[:])
	for _, tc := range []struct {
		manifest string
		ok       bool
	}{
		{valid + "  dep-tracker-linux-amd64\n", true},
		{valid + " *dep-tracker-linux-amd64\n", true},
		{valid + "  other-asset\n", false},
		{"garbage  dep-tracker-linux-amd64\n", false},
		{strings.Repeat(valid+"  dep-tracker-linux-amd64\n", 2), false},
	} {
		got, err := releaseChecksum(tc.manifest, "dep-tracker-linux-amd64")
		if (err == nil) != tc.ok || (tc.ok && got != valid) {
			t.Errorf("%q: %q, %v", tc.manifest, got, err)
		}
	}
}

func TestExportsIncludeActualVersionAndIncompleteStatus(t *testing.T) {
	root := t.TempDir()
	results := []ScanResult{{Pkg: Package{Name: "example", Version: "^1.0.0", Ecosystem: "npm", VersionSource: "constraint"}, PriorityTier: "UNKNOWN", ScanStatus: "incomplete", CheckErrors: []string{"unresolved version"}}}
	sbomPath := filepath.Join(root, "nested", "sbom.json")
	sarifPath := filepath.Join(root, "nested", "results.sarif")
	if err := GenerateSBOM(results, sbomPath); err != nil {
		t.Fatal(err)
	}
	if err := GenerateSARIF(results, sarifPath); err != nil {
		t.Fatal(err)
	}
	var sbom CycloneDXSBOM
	data, _ := os.ReadFile(sbomPath)
	if err := json.Unmarshal(data, &sbom); err != nil {
		t.Fatal(err)
	}
	if sbom.Metadata.Tools[0].Version != appVersion || sbom.Components[0].PURL != "" {
		t.Fatalf("misleading SBOM metadata: %+v", sbom)
	}
	if !strings.Contains(string(data), `"UNKNOWN"`) || !strings.Contains(string(data), `"incomplete"`) {
		t.Fatal("missing SBOM confidence")
	}
	var sarif SARIFReport
	data, _ = os.ReadFile(sarifPath)
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatal(err)
	}
	if sarif.Runs[0].Tool.Driver.Version != appVersion || sarif.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("misleading SARIF metadata")
	}
	if len(sarif.Runs[0].Invocations[0].ToolExecutionNotifications) != 1 {
		t.Fatal("missing SARIF error notification")
	}
	for _, tc := range []struct {
		pkg  Package
		want string
	}{
		{Package{Name: "org.example:lib", Version: "1.0.0", Ecosystem: "Maven"}, "pkg:maven/org.example/lib@1.0.0"},
		{Package{Name: "@scope/lib", Version: "1.0.0", Ecosystem: "npm"}, "pkg:npm/%40scope/lib@1.0.0"},
	} {
		if got := buildPURL(tc.pkg); got != tc.want {
			t.Errorf("PURL: %s", got)
		}
	}
}

func TestScanExitCodesAndJSON(t *testing.T) {
	for _, mode := range []string{"clean", "osv-down", "unresolved", "critical", "export-failure", "epss-down", "kev-down", "nvd-down", "staleness-down"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
			stalenessCacheOnce = sync.Once{}
			nvdCacheOnce = sync.Once{}
			version := "1.0.0"
			if mode == "unresolved" {
				version = "^1.0.0"
			}
			manifest := writeFixture(t, root, "package.json", fmt.Sprintf(`{"dependencies":{"example":"%s"}}`, version))
			mockHTTP(t, func(r *http.Request) (*http.Response, error) {
				switch r.URL.Host {
				case "registry.npmjs.org":
					if mode == "staleness-down" {
						return response(503, `{}`), nil
					}
					return response(200, `{"dist-tags":{"latest":"2.0.0"},"time":{"2.0.0":"2026-10-01T00:00:00Z"}}`), nil
				case "www.cisa.gov":
					if mode == "kev-down" {
						return response(503, `{}`), nil
					}
					return response(200, `{"vulnerabilities":[]}`), nil
				case "api.osv.dev":
					if mode == "osv-down" {
						return response(503, `{}`), nil
					}
					vulnerable := mode == "critical" || mode == "epss-down" || mode == "nvd-down"
					if r.URL.Path == "/v1/querybatch" {
						if vulnerable {
							return response(200, `{"results":[{"vulns":[{"id":"GHSA-example"}]}]}`), nil
						}
						return response(200, `{"results":[{}]}`), nil
					}
					severity := `[{"type":"CVSS_V3","score":"9.8"}]`
					if mode == "nvd-down" {
						severity = `[]`
					}
					return response(200, fmt.Sprintf(`{"vulns":[{"id":"GHSA-example","aliases":["CVE-2026-12345"],"severity":%s}]}`, severity)), nil
				case "api.first.org":
					if mode == "epss-down" {
						return response(503, `{}`), nil
					}
					return response(200, `{"data":[{"cve":"CVE-2026-12345","epss":"0.9"}]}`), nil
				case "services.nvd.nist.gov":
					return response(503, `{}`), nil
				}
				return nil, fmt.Errorf("unexpected request: %s", r.URL)
			})
			sarif := filepath.Join(root, "reports", "results.sarif")
			sbom := filepath.Join(root, "reports", "sbom.json")
			if mode == "export-failure" {
				sbom = writeFixture(t, root, "blocked", "file") + "/sbom.json"
			}
			stdout := os.Stdout
			file, err := os.CreateTemp(root, "stdout")
			if err != nil {
				t.Fatal(err)
			}
			os.Stdout = file
			code := run([]string{"scan", manifest, "--json", "--sbom", sbom, "--sarif", sarif})
			os.Stdout = stdout
			file.Close()
			want := 2
			if mode == "clean" {
				want = 0
			}
			if mode == "critical" {
				want = 1
			}
			if code != want {
				t.Errorf("exit %d, want %d", code, want)
			}
			data, err := os.ReadFile(file.Name())
			if err != nil {
				t.Fatal(err)
			}
			var results []ScanResult
			if err := json.Unmarshal(data, &results); err != nil {
				t.Fatalf("stdout must be JSON: %s: %v", data, err)
			}
			if len(results) != 1 {
				t.Fatalf("got %+v", results)
			}
			if mode == "osv-down" || mode == "unresolved" {
				if results[0].PriorityTier != "UNKNOWN" || results[0].ScanStatus != "incomplete" {
					t.Fatalf("failed check appeared clean: %+v", results[0])
				}
			}
		})
	}
}

func TestVerifiedUpdateRejectsTamperingBeforeReplacement(t *testing.T) {
	for _, mode := range []string{"valid", "tampered", "missing-checksum", "download-failed"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			installed := writeFixture(t, root, "dep-tracker", "existing executable")
			sum := sha256.Sum256([]byte("new executable"))
			hash := hex.EncodeToString(sum[:])
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "SHA256SUMS.txt") {
					if mode == "missing-checksum" {
						return response(404, "missing"), nil
					}
					return response(200, hash+"  dep-tracker-linux-amd64\n"), nil
				}
				if mode == "download-failed" {
					return response(404, "missing"), nil
				}
				if mode == "tampered" {
					return response(200, "tampered executable"), nil
				}
				return response(200, "new executable"), nil
			})}
			path, err := downloadVerifiedUpdate(client, "https://example.com/releases/v1.0.6", "dep-tracker-linux-amd64", root)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				data, _ := os.ReadFile(path)
				if string(data) != "new executable" {
					t.Fatal("wrong download")
				}
				os.Remove(path)
			} else if err == nil {
				t.Fatal("unverified download accepted")
			}
			data, _ := os.ReadFile(installed)
			if string(data) != "existing executable" {
				t.Fatal("installed binary changed before verification")
			}
			leftovers, _ := filepath.Glob(filepath.Join(root, ".dep-tracker-update-*"))
			if len(leftovers) > 0 {
				t.Fatalf("temporary downloads leaked: %v", leftovers)
			}
		})
	}
}

func TestInstalledEnvironmentDoesNotAddAssumedImportVersions(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".venv/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA", "Name: requests\nVersion: 2.31.0\n\n")
	writeFixture(t, root, "app.py", "import requests\n")
	pkgs, _, err := DiscoverDependencies(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Version != "2.31.0" || pkgs[0].VersionSource != "installed" {
		t.Fatalf("installed environment must resolve imports: %+v", pkgs)
	}
}

func TestStaleKEVCacheIsUsefulButIncomplete(t *testing.T) {
	root := t.TempDir()
	path := writeFixture(t, root, "kev.json", `{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`)
	catalog, err := loadStaleCacheOrError(path, fmt.Errorf("service unavailable"))
	if err == nil || len(catalog) != 1 {
		t.Fatalf("stale data must retain findings with an explicit refresh error: %v, %v", catalog, err)
	}
}
