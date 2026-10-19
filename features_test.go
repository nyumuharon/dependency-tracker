package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScoreKEVEscalation(t *testing.T) {
	// Active CISA KEV must escalate to CRITICAL-EXPLOITABLE regardless of low CVSS/EPSS
	if tier := Score(3.5, 0.001, true, true); tier != "CRITICAL-EXPLOITABLE" {
		t.Fatalf("expected CRITICAL-EXPLOITABLE for KEV vulnerability, got %s", tier)
	}

	// Without KEV, high CVSS and high EPSS triggers CRITICAL-EXPLOITABLE
	if tier := Score(8.5, 0.35, true, false); tier != "CRITICAL-EXPLOITABLE" {
		t.Fatalf("expected CRITICAL-EXPLOITABLE for high CVSS and EPSS, got %s", tier)
	}

	// High CVSS alone triggers HIGH
	if tier := Score(7.5, 0.05, true, false); tier != "HIGH" {
		t.Fatalf("expected HIGH, got %s", tier)
	}

	// Medium CVSS triggers MEDIUM
	if tier := Score(5.0, 0.01, true, false); tier != "MEDIUM" {
		t.Fatalf("expected MEDIUM, got %s", tier)
	}

	// Low CVSS triggers LOW
	if tier := Score(2.5, 0.001, true, false); tier != "LOW" {
		t.Fatalf("expected LOW, got %s", tier)
	}

	// No CVE triggers NONE
	if tier := Score(9.8, 0.99, false, false); tier != "NONE" {
		t.Fatalf("expected NONE when hasCVE is false, got %s", tier)
	}
}

func TestParseKEVData(t *testing.T) {
	sampleJSON := []byte(`{
		"title": "CISA Catalog",
		"catalogVersion": "2026.10.16",
		"vulnerabilities": [
			{
				"cveID": "CVE-2021-44228",
				"vendorProject": "Apache",
				"product": "Log4j",
				"vulnerabilityName": "Log4Shell",
				"knownRansomwareCampaignUse": "Known"
			},
			{
				"cveID": "CVE-2024-12345",
				"vendorProject": "Example",
				"product": "Widget",
				"knownRansomwareCampaignUse": "Unknown"
			}
		]
	}`)

	catalog, err := parseKEVData(sampleJSON)
	if err != nil {
		t.Fatalf("parseKEVData failed: %v", err)
	}

	if len(catalog) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(catalog))
	}

	log4j, exists := catalog["CVE-2021-44228"]
	if !exists {
		t.Fatalf("expected CVE-2021-44228 in catalog")
	}
	if log4j.KnownRansomwareCampaignUse != "Known" {
		t.Fatalf("expected Known ransomware campaign, got %s", log4j.KnownRansomwareCampaignUse)
	}
}

func TestParseVulnsRemediation(t *testing.T) {
	res := osvResponse{
		Vulns: []struct {
			ID       string   `json:"id"`
			Aliases  []string `json:"aliases"`
			Summary  string   `json:"summary"`
			Details  string   `json:"details"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			Affected []struct {
				Ranges []struct {
					Type   string `json:"type"`
					Events []struct {
						Fixed string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		}{
			{
				ID:      "GHSA-1234",
				Aliases: []string{"CVE-2024-9999"},
				Summary: "Sample issue",
				Affected: []struct {
					Ranges []struct {
						Type   string `json:"type"`
						Events []struct {
							Fixed string `json:"fixed"`
						} `json:"events"`
					} `json:"ranges"`
				}{
					{
						Ranges: []struct {
							Type   string `json:"type"`
							Events []struct {
								Fixed string `json:"fixed"`
							} `json:"events"`
						}{
							{
								Type: "SEMVER",
								Events: []struct {
									Fixed string `json:"fixed"`
								}{
									{Fixed: "2.5.0"},
								},
							},
						},
					},
				},
			},
		},
	}

	vulns := parseVulns(res)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].FixedVersion != "2.5.0" {
		t.Fatalf("expected fixed version 2.5.0, got %s", vulns[0].FixedVersion)
	}
}

func TestSARIFGeneration(t *testing.T) {
	tempDir := t.TempDir()
	sarifPath := filepath.Join(tempDir, "results.sarif")

	results := []ScanResult{
		{
			Pkg: Package{
				Name:         "express",
				Version:      "4.18.2",
				Ecosystem:    "npm",
				ManifestPath: "package.json",
			},
			PriorityTier: "HIGH",
			Vulnerabilities: []Vulnerability{
				{
					CVEID:        "CVE-2024-43796",
					ID:           "GHSA-qw6h-vgh9-j6wx",
					Summary:      "express vulnerable to XSS",
					CVSS:         7.5,
					EPSS:         0.005,
					FixedVersion: "4.19.2",
				},
			},
		},
	}

	if err := GenerateSARIF(results, sarifPath); err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("could not read generated SARIF: %v", err)
	}

	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if report.Version != "2.1.0" {
		t.Fatalf("expected SARIF version 2.1.0, got %s", report.Version)
	}
	if len(report.Runs) == 0 || len(report.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 run and 1 result in SARIF")
	}

	res := report.Runs[0].Results[0]
	if res.RuleID != "CVE-2024-43796" {
		t.Fatalf("expected ruleId CVE-2024-43796, got %s", res.RuleID)
	}
	if res.Level != "error" {
		t.Fatalf("expected error level for CVSS 7.5, got %s", res.Level)
	}
}

func TestParseConanFile(t *testing.T) {
	content := `
# Configuration for conan project
[requires]
openssl/3.1.4
zlib/1.3.1@user/channel
fmt/10.1.1#1234abcd5678
boost/1.83.0 # needed for networking

[generators]
CMakeDeps
CMakeToolchain
`
	tmp := filepath.Join(t.TempDir(), "conanfile.txt")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}

	pkgs, err := parseConanFile(tmp)
	if err != nil {
		t.Fatalf("parseConanFile failed: %v", err)
	}

	if len(pkgs) != 4 {
		t.Fatalf("expected 4 packages, got %d", len(pkgs))
	}

	expected := map[string]string{
		"openssl": "3.1.4",
		"zlib":    "1.3.1",
		"fmt":     "10.1.1",
		"boost":   "1.83.0",
	}

	for _, p := range pkgs {
		if p.Ecosystem != "ConanCenter" {
			t.Errorf("expected ConanCenter ecosystem, got %s", p.Ecosystem)
		}
		ver, ok := expected[p.Name]
		if !ok {
			t.Errorf("unexpected package: %s", p.Name)
		} else if ver != p.Version {
			t.Errorf("package %s expected version %s, got %s", p.Name, ver, p.Version)
		}
	}
}

func TestParseConanLock(t *testing.T) {
	// Test Conan 2.0 graph_lock format
	content := `{
		"version": "0.5",
		"graph_lock": {
			"nodes": {
				"0": {
					"ref": "myapp/1.0.0"
				},
				"1": {
					"ref": "openssl/3.1.4#f33783a3ec02ba44c4b92b5bbd097241"
				},
				"2": {
					"ref": "zlib/1.3.1#e1d4b1a1"
				}
			}
		}
	}`
	tmp := filepath.Join(t.TempDir(), "conan.lock")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}

	pkgs, err := parseConanLock(tmp)
	if err != nil {
		t.Fatalf("parseConanLock failed: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 dependency packages (excluding node 0 root), got %d", len(pkgs))
	}

	for _, p := range pkgs {
		if p.Ecosystem != "ConanCenter" {
			t.Errorf("expected ConanCenter ecosystem, got %s", p.Ecosystem)
		}
	}
}

func TestParseVcpkg(t *testing.T) {
	content := `{
		"name": "my-application",
		"version-string": "1.0.0",
		"dependencies": [
			"fmt",
			{
				"name": "openssl",
				"version>=": "3.1.0"
			},
			{
				"name": "zlib",
				"version": "1.2.11"
			}
		],
		"overrides": [
			{
				"name": "zlib",
				"version": "1.3.1"
			}
		]
	}`
	tmp := filepath.Join(t.TempDir(), "vcpkg.json")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}

	pkgs, err := parseVcpkg(tmp)
	if err != nil {
		t.Fatalf("parseVcpkg failed: %v", err)
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	pkgMap := make(map[string]string)
	for _, p := range pkgs {
		pkgMap[p.Name] = p.Version
		if p.Ecosystem != "ConanCenter" {
			t.Errorf("expected ConanCenter ecosystem, got %s", p.Ecosystem)
		}
	}

	// zlib should be overridden to 1.3.1
	if pkgMap["zlib"] != "1.3.1" {
		t.Errorf("expected zlib version 1.3.1 (overridden), got %s", pkgMap["zlib"])
	}
	if pkgMap["openssl"] != "3.1.0" {
		t.Errorf("expected openssl version 3.1.0, got %s", pkgMap["openssl"])
	}
	if pkgMap["fmt"] != "latest" {
		t.Errorf("expected fmt version latest, got %s", pkgMap["fmt"])
	}
}
