package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func captureReport(t *testing.T, results []ScanResult) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "report")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	func() { defer func() { os.Stdout = old }(); os.Stdout = file; PrintReport(results) }()
	file.Close()
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func TestRiskReportEveryTierAndExploitationMarker(t *testing.T) {
	cases := []struct {
		name, tier string
		v          Vulnerability
	}{
		{"ransomware", "CRITICAL-EXPLOITABLE", Vulnerability{CVEID: "CVE-2026-11111", ID: "GHSA-ransom", CVSS: 5, IsKEV: true, KEVRansomware: true, Summary: "Issue", FixedVersion: "2.0.0"}},
		{"exploited", "CRITICAL-EXPLOITABLE", Vulnerability{CVEID: "CVE-2026-22222", CVSS: 8, IsKEV: true, FixedVersion: "2.0.0"}},
		{"high", "HIGH", Vulnerability{CVEID: "CVE-2026-33333", CVSS: 8}},
		{"medium", "MEDIUM", Vulnerability{CVEID: "CVE-2026-44444", CVSS: 5}},
		{"low", "LOW", Vulnerability{ID: "GHSA-low", CVSS: 3}},
	}
	var results []ScanResult
	for _, tc := range cases {
		results = append(results, ScanResult{Pkg: Package{Name: tc.name, Version: "1.0.0", Ecosystem: "npm"}, ScanStatus: "incomplete", PriorityTier: tc.tier, CheckErrors: []string{"EPSS unavailable"}, Vulnerabilities: []Vulnerability{tc.v}, Staleness: StalenessResult{LatestVersion: "3.0.0", LastUpdated: time.Now().Add(-3 * 365 * 24 * time.Hour), IsStale: true}})
	}
	for _, name := range []string{"safe-z", "safe-a"} {
		results = append(results, ScanResult{Pkg: Package{Name: name, Version: "1.0.0", Ecosystem: "npm"}, ScanStatus: "complete", PriorityTier: "NONE", Staleness: StalenessResult{IsStale: true}})
	}
	text := captureReport(t, results)
	for _, want := range []string{"KNOWN RANSOMWARE", "CISA-KEV EXPLOITED", "[MEDIUM]", "[LOW]", "CRITICAL-EXPLOITABLE", "safe-a", "safe-z"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	root := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	results[0].Pkg.ManifestPath = filepath.Join(cwd, "cmd", "dep-tracker", "testdata", "package.json")
	if err := GenerateSARIF(results, filepath.Join(root, "report.sarif")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "report.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Runs[0].Results) != 5 {
		t.Fatal("findings lost")
	}
	if report.Runs[0].Tool.Driver.Rules[0].Properties["security-severity"] != "10.0" {
		t.Fatal("active exploitation priority not reflected")
	}
	blocked := writeFixture(t, root, "blocked", "file")
	for _, generate := range []func([]ScanResult, string) error{GenerateSBOM, GenerateSARIF} {
		if err := generate(results, filepath.Join(blocked, "report.json")); err == nil {
			t.Fatal("failed export reported success")
		}
	}
	for _, tier := range []string{"CRITICAL-EXPLOITABLE", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"} {
		if rank := tierRank(tier); rank < 1 || rank > 6 {
			t.Fatal(rank)
		}
	}
	if text := captureReport(t, nil); !strings.Contains(text, "No vulnerabilities found") {
		t.Fatal(text)
	}
	unknown := []ScanResult{{Pkg: Package{Name: "unknown"}, ScanStatus: "incomplete", PriorityTier: "UNKNOWN", CheckErrors: []string{"missing data"}}}
	if text := captureReport(t, unknown); !strings.Contains(text, "Scan incomplete:") {
		t.Fatal(text)
	}
}

func TestPURLTypesAndCLIEqualsOptions(t *testing.T) {
	for _, tc := range []struct{ eco, name, version, want string }{
		{"PyPI", "requests", "1.0.0", "pkg:pypi/requests@1.0.0"},
		{"NuGet", "Library", "1.0.0", "pkg:nuget/Library@1.0.0"},
		{"Go", "example.com/library", "v1.0.0", "pkg:golang/example.com/library@v1.0.0"},
		{"crates.io", "serde", "1.0.0", "pkg:cargo/serde@1.0.0"},
		{"Packagist", "vendor/library", "1.0.0", "pkg:composer/vendor/library@1.0.0"},
		{"RubyGems", "rack", "1.0.0", "pkg:gem/rack@1.0.0"},
		{"ConanCenter", "zlib", "1.0.0", "pkg:conan/zlib@1.0.0"},
		{"Pub", "http", "1.0.0", "pkg:pub/http@1.0.0"},
		{"Hex", "jason", "1.0.0", "pkg:hex/jason@1.0.0"},
		{"SwiftURL", "library", "1.0.0", "pkg:swift/library@1.0.0"},
		{"Other", "library", "1.0.0", "pkg:generic/library@1.0.0"},
	} {
		got := buildPURL(Package{Name: tc.name, Version: tc.version, Ecosystem: tc.eco})
		if got != tc.want {
			t.Errorf("%s: %s", tc.eco, got)
		}
	}
	opts, path, err := parseArgs([]string{"scan", ".", "--sbom", "bom.json", "--sarif=results.sarif"})
	if err != nil || path != "." || opts.sbomPath != "bom.json" || opts.sarifPath != "results.sarif" {
		t.Fatalf("%+v %s %v", opts, path, err)
	}
	for _, tc := range []struct {
		a, b, eco string
		want      int
		ok        bool
	}{
		{"1.0.0-alpha", "1.0.0", "npm", -1, true},
		{"1.0.0-alpha", "1.0.0-beta", "npm", -1, true},
		{"1.0.0-alpha", "1.0.0", "PyPI", 0, false},
	} {
		got, ok := compareVersions(tc.a, tc.b, tc.eco)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("%+v: %v %v", tc, got, ok)
		}
	}
}
