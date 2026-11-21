package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nyumuharon/dependency-tracker/internal/model"
)

func captureReport(t *testing.T, results []model.ScanResult) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "report")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	func() {
		defer func() { os.Stdout = old }()
		os.Stdout = file
		PrintReport(results)
	}()
	file.Close()
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

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

func TestRiskReportEveryTierAndExploitationMarker(t *testing.T) {
	appVersion := "1.1.1"
	cases := []struct {
		name, tier string
		v          model.Vulnerability
	}{
		{"ransomware", "CRITICAL-EXPLOITABLE", model.Vulnerability{CVEID: "CVE-2026-11111", ID: "GHSA-ransom", CVSS: 5, IsKEV: true, KEVRansomware: true, Summary: "Issue", FixedVersion: "2.0.0"}},
		{"exploited", "CRITICAL-EXPLOITABLE", model.Vulnerability{CVEID: "CVE-2026-22222", CVSS: 8, IsKEV: true, FixedVersion: "2.0.0"}},
		{"high", "HIGH", model.Vulnerability{CVEID: "CVE-2026-33333", CVSS: 8}},
		{"medium", "MEDIUM", model.Vulnerability{CVEID: "CVE-2026-44444", CVSS: 5}},
		{"low", "LOW", model.Vulnerability{ID: "GHSA-low", CVSS: 3}},
	}
	var results []model.ScanResult
	for _, tc := range cases {
		results = append(results, model.ScanResult{
			Pkg:             model.Package{Name: tc.name, Version: "1.0.0", Ecosystem: "npm"},
			ScanStatus:      "incomplete",
			PriorityTier:    tc.tier,
			CheckErrors:     []string{"EPSS unavailable"},
			Vulnerabilities: []model.Vulnerability{tc.v},
			Staleness:       model.StalenessResult{LatestVersion: "3.0.0", LastUpdated: time.Now().Add(-3 * 365 * 24 * time.Hour), IsStale: true},
		})
	}
	for _, name := range []string{"safe-z", "safe-a"} {
		results = append(results, model.ScanResult{
			Pkg:          model.Package{Name: name, Version: "1.0.0", Ecosystem: "npm"},
			ScanStatus:   "complete",
			PriorityTier: "NONE",
			Staleness:    model.StalenessResult{IsStale: true},
		})
	}
	text := captureReport(t, results)
	for _, want := range []string{"KNOWN RANSOMWARE", "CISA-KEV EXPLOITED", "[MEDIUM]", "[LOW]", "CRITICAL-EXPLOITABLE", "safe-a", "safe-z"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	root := t.TempDir()
	results[0].Pkg.ManifestPath = filepath.Join(root, "package.json")
	if err := GenerateSARIF(results, filepath.Join(root, "report.sarif"), appVersion); err != nil {
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
	for _, generate := range []func([]model.ScanResult, string, string) error{GenerateSBOM, GenerateSARIF} {
		if err := generate(results, filepath.Join(blocked, "report.json"), appVersion); err == nil {
			t.Fatal("failed export reported success")
		}
	}
	for _, tier := range []string{"CRITICAL-EXPLOITABLE", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"} {
		if rank := TierRank(tier); rank < 1 || rank > 6 {
			t.Fatal(rank)
		}
	}
	if text := captureReport(t, nil); !strings.Contains(text, "No vulnerabilities found") {
		t.Fatal(text)
	}
	unknown := []model.ScanResult{{Pkg: model.Package{Name: "unknown"}, ScanStatus: "incomplete", PriorityTier: "UNKNOWN", CheckErrors: []string{"missing data"}}}
	if text := captureReport(t, unknown); !strings.Contains(text, "Scan incomplete:") {
		t.Fatal(text)
	}
}

func TestPURLTypes(t *testing.T) {
	for _, tc := range []struct{ eco, name, version, want string }{
		{"PyPI", "requests", "1.0.0", "pkg:pypi/requests@1.0.0"},
		{"Maven", "org.apache:log4j", "2.0.0", "pkg:maven/org.apache/log4j@2.0.0"},
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
		got := BuildPURL(model.Package{Name: tc.name, Version: tc.version, Ecosystem: tc.eco})
		if got != tc.want {
			t.Errorf("%s: %s", tc.eco, got)
		}
	}
}

func TestSARIFRulesLocationsAndFingerprints(t *testing.T) {
	appVersion := "1.1.1"
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	inRepo := writeFixture(t, repo, "..svc/package.json", "{}")
	outside := writeFixture(t, t.TempDir(), "pom.xml", "<project/>")
	cwdOnly := t.TempDir()
	belowCwd := writeFixture(t, cwdOnly, "sub/go.mod", "module x\n")
	shared := model.Vulnerability{CVEID: "CVE-2026-1", Summary: "shared issue", CVSS: 7.5, EPSSKnown: true}
	results := []model.ScanResult{
		{Pkg: model.Package{Name: "a", Version: "1.0.0", Ecosystem: "npm", ManifestPath: inRepo}, ScanStatus: "complete", Vulnerabilities: []model.Vulnerability{shared}},
		{Pkg: model.Package{Name: "b", Version: "2.0.0", Ecosystem: "npm", ManifestPath: inRepo}, ScanStatus: "complete", Vulnerabilities: []model.Vulnerability{shared}},
		{Pkg: model.Package{Name: "c", Version: "1.0.0", Ecosystem: "Maven", ManifestPath: outside}, ScanStatus: "incomplete", Vulnerabilities: []model.Vulnerability{{CVEID: "CVE-2026-2"}}},
		{Pkg: model.Package{Name: "d", Version: "1.0.0", Ecosystem: "Go", ManifestPath: belowCwd}, ScanStatus: "complete", Vulnerabilities: []model.Vulnerability{{CVEID: "GHSA-x", Severity: "HIGH"}}},
		{Pkg: model.Package{Name: "e", Version: "1.0.0", Ecosystem: "npm"}, ScanStatus: "complete", Vulnerabilities: []model.Vulnerability{{CVEID: "CVE-2026-3", IsKEV: true}}},
	}
	path := filepath.Join(t.TempDir(), "out.sarif")
	if err := GenerateSARIFWithDirectory(results, path, appVersion, func() (string, error) { return cwdOnly, nil }); err != nil {
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

func TestSBOMReferencesAndPyPINames(t *testing.T) {
	appVersion := "1.1.1"
	path := filepath.Join(t.TempDir(), "sbom.json")
	pkg := model.Package{Name: "Django_REST", Version: "3.0.0", Ecosystem: "PyPI", VersionSource: "manifest"}
	other := pkg
	other.ProjectPath = "other"
	if err := GenerateSBOM([]model.ScanResult{{Pkg: pkg}, {Pkg: other}, {Pkg: model.Package{Name: "loose", Version: "^1.0", Ecosystem: "npm", VersionSource: "constraint"}}}, path, appVersion); err != nil {
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
	out := captureReport(t, []model.ScanResult{{
		Pkg:          model.Package{Name: "org.apache.logging.log4j:log4j-core", Version: "2.24.0", Ecosystem: "Maven"},
		ScanStatus:   "complete",
		PriorityTier: "HIGH",
		Vulnerabilities: []model.Vulnerability{
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

func TestScorerEdgeCases(t *testing.T) {
	if Score(0, 0, false, false) != "NONE" {
		t.Fatal("expected NONE without CVE")
	}
	if Score(8.0, 0.3, true, false) != "CRITICAL-EXPLOITABLE" {
		t.Fatal("expected CRITICAL-EXPLOITABLE")
	}
	if Score(7.5, 0.1, true, false) != "HIGH" {
		t.Fatal("expected HIGH")
	}
	if Score(5.0, 0.1, true, false) != "MEDIUM" {
		t.Fatal("expected MEDIUM")
	}
	if Score(2.0, 0.1, true, false) != "LOW" {
		t.Fatal("expected LOW")
	}
	if Score(0, 0, true, false) != "UNKNOWN" {
		t.Fatal("expected UNKNOWN for unscored CVE")
	}
	for _, l := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		if NormalizeSeverityLabel(l) != l {
			t.Fatalf("expected %s", l)
		}
	}
	if NormalizeSeverityLabel("moderate") != "MEDIUM" {
		t.Fatal("expected MEDIUM for moderate")
	}
	if NormalizeSeverityLabel("unknown") != "" {
		t.Fatal("expected empty for unknown label")
	}
	for l, want := range map[string]float64{
		"LOW": 0.1, "MEDIUM": 4.0, "HIGH": 7.0, "CRITICAL": 9.0, "": 0,
	} {
		if SeverityLabelScore(l) != want {
			t.Fatalf("score for %s: got %f, want %f", l, SeverityLabelScore(l), want)
		}
	}
	// ScoreVulnerabilities with ranking
	vulns := []model.Vulnerability{
		{CVEID: "CVE-1", CVSS: 2.0},
		{CVEID: "CVE-2", CVSS: 8.0, EPSS: 0.5, EPSSKnown: true},
	}
	if ScoreVulnerabilities(vulns) != "CRITICAL-EXPLOITABLE" {
		t.Fatal("expected CRITICAL-EXPLOITABLE from combined vulns")
	}
	if ScorePackage(vulns, false) != "CRITICAL-EXPLOITABLE" {
		t.Fatal("expected CRITICAL-EXPLOITABLE")
	}
	if ScorePackage(nil, true) != "UNKNOWN" {
		t.Fatal("expected UNKNOWN for incomplete scan with no vulns")
	}
}

func TestIncompleteReportCollapsingAndSBOMViewer(t *testing.T) {
	var results []model.ScanResult
	for i := 1; i <= 7; i++ {
		results = append(results, model.ScanResult{
			Pkg:          model.Package{Name: "pkg-" + string(rune('a'+i-1)), Version: "latest", Ecosystem: "PyPI", ManifestPath: "app.py", VersionSource: "import"},
			ScanStatus:   "incomplete",
			PriorityTier: "UNKNOWN",
			CheckErrors:  []string{"unresolved version"},
		})
	}
	collapsed := captureReport(t, results)
	if !strings.Contains(collapsed, "2 more incomplete check(s) collapsed") || strings.Contains(collapsed, "pkg-g@latest") {
		t.Fatalf("expected collapsed incomplete output:\n%s", collapsed)
	}

	file, err := os.CreateTemp(t.TempDir(), "expanded")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	func() {
		defer func() { os.Stdout = old }()
		os.Stdout = file
		PrintReportWithOptions(results, true)
	}()
	file.Close()
	expanded, _ := os.ReadFile(file.Name())
	if !strings.Contains(string(expanded), "pkg-g@latest") || strings.Contains(string(expanded), "collapsed") {
		t.Fatalf("expected expanded incomplete output:\n%s", expanded)
	}

	root := t.TempDir()
	sbomPath := filepath.Join(root, "sbom.json")
	if err := GenerateSBOM(results, sbomPath, "1.1.2"); err != nil {
		t.Fatal(err)
	}
	viewFile, err := os.CreateTemp(t.TempDir(), "view")
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() { os.Stdout = old }()
		os.Stdout = viewFile
		if err := PrintIncompleteFromSBOM(sbomPath); err != nil {
			t.Fatal(err)
		}
	}()
	viewFile.Close()
	viewed, _ := os.ReadFile(viewFile.Name())
	if !strings.Contains(string(viewed), "pkg-g@latest") || !strings.Contains(string(viewed), "Total incomplete checks: 7") {
		t.Fatalf("unexpected SBOM incomplete view:\n%s", viewed)
	}

	cleanSBOM := filepath.Join(root, "clean.json")
	if err := GenerateSBOM([]model.ScanResult{{Pkg: model.Package{Name: "safe", Version: "1.0.0", Ecosystem: "npm"}, ScanStatus: "complete", PriorityTier: "NONE"}}, cleanSBOM, "1.1.2"); err != nil {
		t.Fatal(err)
	}
	cleanViewFile, err := os.CreateTemp(t.TempDir(), "clean-view")
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() { os.Stdout = old }()
		os.Stdout = cleanViewFile
		if err := PrintIncompleteFromSBOM(cleanSBOM); err != nil {
			t.Fatal(err)
		}
	}()
	cleanViewFile.Close()
	cleanViewed, _ := os.ReadFile(cleanViewFile.Name())
	if !strings.Contains(string(cleanViewed), "No incomplete checks recorded") {
		t.Fatalf("expected clean SBOM message:\n%s", cleanViewed)
	}

	if err := PrintIncompleteFromSBOM(filepath.Join(root, "missing.json")); err == nil {
		t.Fatal("expected error for missing SBOM")
	}
	badSBOM := writeFixture(t, root, "bad.json", "{invalid")
	if err := PrintIncompleteFromSBOM(badSBOM); err == nil {
		t.Fatal("expected error for malformed SBOM")
	}
}
