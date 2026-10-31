package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegistryMaintenanceResponsesAndFailures(t *testing.T) {
	recent := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	stamp := recent.Format(time.RFC3339)
	cases := []struct{ eco, name, body string }{
		{"npm", "example", fmt.Sprintf(`{"dist-tags":{"latest":"1.0.0"},"time":{"1.0.0":%q}}`, stamp)},
		{"PyPI", "example", fmt.Sprintf(`<rss><channel><item><title>1.0.0</title><pubDate>%s</pubDate></item></channel></rss>`, recent.Format(time.RFC1123Z))},
		{"Maven", "org.example:example", fmt.Sprintf(`{"response":{"docs":[{"latestVersion":"1.0.0","timestamp":%d}]}}`, recent.UnixMilli())},
		{"NuGet", "Example", fmt.Sprintf(`{"items":[{"upper":"1.0.0","items":[{"catalogEntry":{"version":"1.0.0","published":%q}}]}]}`, stamp)},
		{"Go", "github.com/Example/Example", fmt.Sprintf(`{"Version":"1.0.0","Time":%q}`, stamp)},
		{"crates.io", "example", fmt.Sprintf(`{"crate":{"max_version":"1.0.0","updated_at":%q}}`, stamp)},
		{"Packagist", "example/example", fmt.Sprintf(`{"packages":{"example/example":[{"version":"1.0.0","time":%q}]}}`, stamp)},
		{"RubyGems", "example", fmt.Sprintf(`{"version":"1.0.0","version_created_at":%q}`, stamp)},
		{"Pub", "example", fmt.Sprintf(`{"latest":{"version":"1.0.0","published":%q}}`, stamp)},
		{"Hex", "example", fmt.Sprintf(`{"releases":[{"version":"1.0.0","inserted_at":%q}]}`, stamp)},
	}
	for _, tc := range cases {
		t.Run(tc.eco, func(t *testing.T) {
			for _, mode := range []string{"healthy", "http-error", "malformed", "missing-date"} {
				t.Run(mode, func(t *testing.T) {
					t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
					stalenessCacheOnce = sync.Once{}
					calls := 0
					mockHTTP(t, func(r *http.Request) (*http.Response, error) {
						calls++
						if mode == "http-error" {
							return response(503, `{}`), nil
						}
						if mode == "malformed" {
							return response(200, "not valid"), nil
						}
						if mode == "missing-date" {
							return response(200, `{}`), nil
						}
						return response(200, tc.body), nil
					})
					p := Package{Name: tc.name, Ecosystem: tc.eco}
					result, err := CheckStaleness(p)
					if mode != "healthy" {
						if err == nil {
							t.Fatalf("%s was accepted as complete: %+v", mode, result)
						}
						return
					}
					if err != nil || result.LatestVersion != "1.0.0" || result.IsStale || result.LastUpdated.IsZero() {
						t.Fatalf("wrong release data: %+v %v", result, err)
					}
					SaveStalenessCache()
					stalenessCacheOnce = sync.Once{}
					cached, err := CheckStaleness(p)
					if err != nil || cached.LatestVersion != "1.0.0" || calls != 1 {
						t.Fatalf("cache did not preserve the result: %+v %v calls=%d", cached, err, calls)
					}
				})
			}
		})
	}
}

func TestPyPIFallbackAndConanUnknownDate(t *testing.T) {
	t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
	stalenessCacheOnce = sync.Once{}
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/rss/") {
			return response(503, ""), nil
		}
		if strings.Contains(r.URL.Host, "githubusercontent") {
			return response(200, "versions:\n  \"1.0.0\":\n    folder: all\n"), nil
		}
		return response(200, fmt.Sprintf(`{"info":{"version":"1.0.0"},"urls":[{"upload_time_iso_8601":%q}]}`, time.Now().UTC().Format(time.RFC3339))), nil
	})
	if result, err := CheckStaleness(Package{Name: "example", Ecosystem: "PyPI"}); err != nil || result.LatestVersion != "1.0.0" {
		t.Fatalf("PyPI fallback: %+v %v", result, err)
	}
	if _, err := CheckStaleness(Package{Name: "example", Ecosystem: "ConanCenter"}); err == nil {
		t.Fatal("recipe version without a date must remain incomplete")
	}
}

func TestNVDMetricsFallbackAndCache(t *testing.T) {
	for _, metric := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		t.Run(metric, func(t *testing.T) {
			t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
			nvdCacheOnce = sync.Once{}
			calls := 0
			mockHTTP(t, func(r *http.Request) (*http.Response, error) {
				calls++
				return response(200, fmt.Sprintf(`{"vulnerabilities":[{"cve":{"metrics":{%q:[{"cvssData":{"baseScore":7.5}}]}}}]}`, metric)), nil
			})
			score, err := QueryNVD("CVE-2026-11111")
			if err != nil || score != 7.5 {
				t.Fatalf("score=%v err=%v", score, err)
			}
			SaveNVDCache()
			nvdCacheOnce = sync.Once{}
			score, err = QueryNVD("CVE-2026-11111")
			if err != nil || score != 7.5 || calls != 1 {
				t.Fatalf("cache score=%v calls=%d err=%v", score, calls, err)
			}
		})
	}
}

func TestReportsExposeUnknownEPSSAndKnownZero(t *testing.T) {
	root := t.TempDir()
	results := []ScanResult{
		{Pkg: Package{Name: "unknown", Version: "1.0.0", Ecosystem: "npm"}, ScanStatus: "incomplete", CheckErrors: []string{"EPSS unavailable"}, PriorityTier: "HIGH", Vulnerabilities: []Vulnerability{{CVEID: "CVE-2026-11111", CVSS: 9.8}}},
		{Pkg: Package{Name: "zero", Version: "1.0.0", Ecosystem: "npm"}, ScanStatus: "complete", PriorityTier: "HIGH", Vulnerabilities: []Vulnerability{{CVEID: "CVE-2026-22222", CVSS: 9.8, EPSSKnown: true, FixedVersion: "2.0.0", Summary: "fixture issue"}}, Staleness: StalenessResult{LatestVersion: "2.0.0", LastUpdated: time.Now()}},
		{Pkg: Package{Name: "stale", Version: "1.0.0", Ecosystem: "npm"}, ScanStatus: "complete", PriorityTier: "NONE", Staleness: StalenessResult{IsStale: true}},
	}
	file, err := os.Create(filepath.Join(root, "terminal.txt"))
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	func() { defer func() { os.Stdout = old }(); os.Stdout = file; PrintReport(results) }()
	file.Close()
	data, _ := os.ReadFile(file.Name())
	for _, want := range []string{"EPSS: unknown", "EPSS: 0.00000", "INCOMPLETE", "FIXED RELEASES", "STALE PACKAGES"} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("terminal missing %q", want)
		}
	}
	for _, generate := range []func([]ScanResult, string) error{GenerateSBOM, GenerateSARIF} {
		path := filepath.Join(root, "report.json")
		if err := generate(results, path); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(path)
		if !json.Valid(data) || !strings.Contains(string(data), "unknown") || !strings.Contains(string(data), "0.00000") {
			t.Fatalf("missing EPSS confidence: %s", data)
		}
	}
}

func TestNullCachesFallBackToFreshData(t *testing.T) {
	t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
	for _, path := range []string{getNVDCachePath(), getStalenessCachePath()} {
		if err := os.WriteFile(path, []byte("null"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	nvdCacheOnce = sync.Once{}
	stalenessCacheOnce = sync.Once{}
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "services.nvd.nist.gov" {
			return response(200, `{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5}}]}}}]}`), nil
		}
		return response(200, fmt.Sprintf(`{"dist-tags":{"latest":"1.0.0"},"time":{"1.0.0":%q}}`, time.Now().UTC().Format(time.RFC3339))), nil
	})
	if score, err := QueryNVD("CVE-2026-11111"); err != nil || score != 7.5 {
		t.Fatalf("%v %v", score, err)
	}
	if result, err := CheckStaleness(Package{Name: "example", Ecosystem: "npm"}); err != nil || result.LatestVersion != "1.0.0" {
		t.Fatalf("%+v %v", result, err)
	}
}
