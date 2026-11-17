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
	var res osvResponse
	if err := json.Unmarshal([]byte(`{"vulns":[{"id":"GHSA-1234","aliases":["CVE-2024-9999"],"summary":"Sample issue","affected":[{"package":{"name":"example","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.5.0"}]}]}]}]}`), &res); err != nil {
		t.Fatal(err)
	}

	vulns := parseVulns(res, Package{Name: "example", Ecosystem: "npm", Version: "2.4.0"})
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
					EPSSKnown:    true,
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
