package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPackageKeys(t *testing.T) {
	pkg := Package{
		Name:        "example",
		Version:     "1.0.0",
		Ecosystem:   "npm",
		ProjectPath: "app",
	}
	if got := pkg.Key(); got != "example@1.0.0@npm@app" {
		t.Fatalf("unexpected Key(): %q", got)
	}
	if got := pkg.StalenessKey(); got != "example@npm" {
		t.Fatalf("unexpected StalenessKey(): %q", got)
	}
}

func TestVulnerabilityMethods(t *testing.T) {
	// EPSS known
	known := Vulnerability{CVEID: "CVE-2026-1", EPSS: 0.12345, EPSSKnown: true}
	if known.EPSSDisplay() != "0.12345" || known.epssDisplay() != "0.12345" {
		t.Fatalf("unexpected EPSSDisplay: %s", known.EPSSDisplay())
	}
	// MarshalJSON with known EPSS
	data, err := json.Marshal(known)
	if err != nil || !strings.Contains(string(data), "0.12345") {
		t.Fatalf("marshal error: %v, json: %s", err, data)
	}

	// EPSS unknown CVE
	unknownCVE := Vulnerability{CVEID: "CVE-2026-2", EPSSKnown: false}
	if unknownCVE.EPSSDisplay() != "unknown" {
		t.Fatalf("unexpected EPSSDisplay for unknown CVE: %s", unknownCVE.EPSSDisplay())
	}
	// MarshalJSON with null EPSS
	data, err = json.Marshal(unknownCVE)
	if err != nil || !strings.Contains(string(data), "null") {
		t.Fatalf("marshal error: %v, json: %s", err, data)
	}

	// EPSS unknown non-CVE
	nonCVE := Vulnerability{CVEID: "GHSA-1234", EPSSKnown: false}
	if !strings.Contains(nonCVE.EPSSDisplay(), "not applicable") {
		t.Fatalf("unexpected EPSSDisplay for non-CVE: %s", nonCVE.EPSSDisplay())
	}

	// CVSS known
	withCVSS := Vulnerability{CVSS: 7.5}
	if withCVSS.SeverityScore() != 7.5 || withCVSS.severityScore() != 7.5 {
		t.Fatalf("unexpected SeverityScore: %f", withCVSS.SeverityScore())
	}
	if withCVSS.CVSSDisplay() != "7.5" || withCVSS.cvssDisplay() != "7.5" {
		t.Fatalf("unexpected CVSSDisplay: %s", withCVSS.CVSSDisplay())
	}

	// Qualitative ratings
	ratings := map[string]float64{
		"LOW":      0.1,
		"MEDIUM":   4.0,
		"HIGH":     7.0,
		"CRITICAL": 9.0,
		"OTHER":    0.0,
	}
	for r, want := range ratings {
		v := Vulnerability{Severity: r}
		if v.SeverityScore() != want {
			t.Fatalf("rating %s: got %f, want %f", r, v.SeverityScore(), want)
		}
		if r != "OTHER" && v.CVSSDisplay() != "unscored, rated "+r {
			t.Fatalf("rating %s display: got %s", r, v.CVSSDisplay())
		}
	}
	unscored := Vulnerability{}
	if unscored.CVSSDisplay() != "unknown" {
		t.Fatalf("unscored display: got %s", unscored.CVSSDisplay())
	}

	// ScanResult / StalenessResult sanity
	res := ScanResult{
		ScanStatus: "complete",
		Pkg:        Package{Name: "pkg", Version: "1.0.0"},
		Staleness: StalenessResult{
			LatestVersion: "1.0.0",
			LastUpdated:   time.Now(),
		},
	}
	if res.Pkg.Name != "pkg" || res.Staleness.LatestVersion != "1.0.0" {
		t.Fatal("unexpected ScanResult structure")
	}
}
