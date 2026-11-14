package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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

func TestSARIFRulesLocationsAndFingerprints(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	inRepo := writeFixture(t, repo, "..svc/package.json", "{}")
	outside := writeFixture(t, t.TempDir(), "pom.xml", "<project/>")
	cwdOnly := t.TempDir()
	belowCwd := writeFixture(t, cwdOnly, "sub/go.mod", "module x\n")
	shared := Vulnerability{CVEID: "CVE-2026-1", Summary: "shared issue", CVSS: 7.5, EPSSKnown: true}
	results := []ScanResult{
		{Pkg: Package{Name: "a", Version: "1.0.0", Ecosystem: "npm", ManifestPath: inRepo}, ScanStatus: "complete", Vulnerabilities: []Vulnerability{shared}},
		{Pkg: Package{Name: "b", Version: "2.0.0", Ecosystem: "npm", ManifestPath: inRepo}, ScanStatus: "complete", Vulnerabilities: []Vulnerability{shared}},
		{Pkg: Package{Name: "c", Version: "1.0.0", Ecosystem: "Maven", ManifestPath: outside}, ScanStatus: "incomplete", Vulnerabilities: []Vulnerability{{CVEID: "CVE-2026-2"}}},
		{Pkg: Package{Name: "d", Version: "1.0.0", Ecosystem: "Go", ManifestPath: belowCwd}, ScanStatus: "complete", Vulnerabilities: []Vulnerability{{CVEID: "GHSA-x", Severity: "HIGH"}}},
		{Pkg: Package{Name: "e", Version: "1.0.0", Ecosystem: "npm"}, ScanStatus: "complete", Vulnerabilities: []Vulnerability{{CVEID: "CVE-2026-3", IsKEV: true}}},
	}
	path := filepath.Join(t.TempDir(), "out.sarif")
	if err := generateSARIFWithDirectory(results, path, func() (string, error) { return cwdOnly, nil }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	run := report.Runs[0]
	if len(run.Tool.Driver.Rules) != 4 || len(run.Results) != 5 {
		t.Fatalf("rules %d results %d", len(run.Tool.Driver.Rules), len(run.Results))
	}
	rule := run.Tool.Driver.Rules[0]
	if strings.Contains(rule.ShortDescription.Text+rule.Help.Text+rule.Help.Markdown, "a@1.0.0") || rule.ShortDescription.Text != "CVE-2026-1: shared issue" {
		t.Fatalf("shared rule names one package: %+v", rule)
	}
	if _, ok := run.Tool.Driver.Rules[1].Properties["security-severity"]; ok {
		t.Fatal("unknown severity reported as a number")
	}
	if run.Tool.Driver.Rules[2].Properties["security-severity"] != "7.0" || run.Tool.Driver.Rules[3].Properties["security-severity"] != "10.0" {
		t.Fatalf("rated or KEV severities wrong: %+v %+v", run.Tool.Driver.Rules[2].Properties, run.Tool.Driver.Rules[3].Properties)
	}
	fp := map[string]bool{}
	for _, r := range run.Results {
		fp[r.PartialFingerprints["dependencyFinding/v1"]] = true
	}
	if len(fp) != 5 {
		t.Fatalf("findings share fingerprints: %v", fp)
	}
	loc := func(i int) SARIFArtifactLocation {
		return run.Results[i].Locations[0].PhysicalLocation.ArtifactLocation
	}
	if got := loc(0); got.URI != "..svc/package.json" || got.URIBaseID != "%SRCROOT%" {
		t.Fatalf("repository-relative path: %+v", got)
	}
	if got := loc(2); !strings.HasPrefix(got.URI, "file:///") || got.URIBaseID != "" || strings.Contains(got.URI, `\`) {
		t.Fatalf("outside path must be an absolute file URI: %+v", got)
	}
	if got := loc(3); got.URI != "sub/go.mod" || got.URIBaseID != "%SRCROOT%" {
		t.Fatalf("working-directory-relative path: %+v", got)
	}
	if got := loc(4); got.URI != "manifest" {
		t.Fatalf("missing manifest path: %+v", got)
	}
}

func TestCacheWritesAreAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	writeCacheFile(path, []byte(`{"a":1}`))
	if data, err := os.ReadFile(path); err != nil || string(data) != `{"a":1}` {
		t.Fatalf("%s %v", data, err)
	}
	// A missing directory and a directory in the way both leave no temp files.
	writeCacheFile(filepath.Join(dir, "missing", "cache.json"), []byte("x"))
	blocked := filepath.Join(dir, "blocked")
	writeFixture(t, blocked, "keep", "x")
	writeCacheFile(blocked, []byte("x"))
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestSBOMReferencesAndPyPINames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbom.json")
	pkg := Package{Name: "Django_REST", Version: "3.0.0", Ecosystem: "PyPI", VersionSource: "manifest"}
	other := pkg
	other.ProjectPath = "other"
	if err := GenerateSBOM([]ScanResult{{Pkg: pkg}, {Pkg: other}, {Pkg: Package{Name: "loose", Version: "^1.0", Ecosystem: "npm", VersionSource: "constraint"}}}, path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var bom CycloneDXSBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	refs := []string{bom.Components[0].BOMRef, bom.Components[1].BOMRef, bom.Components[2].BOMRef}
	want := []string{"pkg:pypi/django-rest@3.0.0", "pkg:pypi/django-rest@3.0.0#2", "npm:loose@^1.0"}
	if strings.Join(refs, " ") != strings.Join(want, " ") || !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(bom.SerialNumber) {
		t.Fatalf("refs %v serial %s", refs, bom.SerialNumber)
	}
}

func TestRemediationTableOrdersFixedReleasesByVersion(t *testing.T) {
	out := captureReport(t, []ScanResult{{
		Pkg:          Package{Name: "org.apache.logging.log4j:log4j-core", Version: "2.24.0", Ecosystem: "Maven"},
		ScanStatus:   "complete",
		PriorityTier: "HIGH",
		Vulnerabilities: []Vulnerability{
			{CVEID: "CVE-1", CVSS: 7, FixedVersion: "2.25.10"},
			{CVEID: "CVE-2", CVSS: 7, FixedVersion: "2.25.4"},
			{CVEID: "CVE-3", CVSS: 7, FixedVersion: "3.0.0-beta1"},
			{CVEID: "CVE-4", CVSS: 7, FixedVersion: "2.3.0-rc1"},
		},
	}})
	if !strings.Contains(out, "2.25.4, 2.25.10, 2.3.0-rc1, 3.0.0-beta1") || !strings.Contains(out, "org.apache.logging.log4j:log4j-core HIGH") {
		t.Fatalf("fixed releases misordered or table misaligned:\n%s", out)
	}
}
