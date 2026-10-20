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

func TestPackageKeys(t *testing.T) {
	p1 := Package{Name: "qs", Version: "6.5.1", Ecosystem: "npm"}
	p2 := Package{Name: "qs", Version: "6.10.3", Ecosystem: "npm"}
	p3 := Package{Name: "qs", Version: "6.5.1", Ecosystem: "PyPI"}

	if p1.Key() == p2.Key() {
		t.Fatalf("expected distinct keys for different versions of same package, got %s", p1.Key())
	}
	if p1.Key() == p3.Key() {
		t.Fatalf("expected distinct keys for different ecosystems, got %s", p1.Key())
	}
	if p1.StalenessKey() != p2.StalenessKey() {
		t.Fatalf("expected identical staleness key for same package and ecosystem across versions")
	}
	if p1.StalenessKey() == p3.StalenessKey() {
		t.Fatalf("expected distinct staleness keys for different ecosystems")
	}
}

func TestParsePyProjectToml(t *testing.T) {
	content := `
[build-system]
requires = ["hatchling>=1.24"]
build-backend = "hatchling.build"

[project]
name = "alpha-miner"
version = "0.1.0"
dependencies = [
  "pydantic>=2.8,<3",
  "lark>=1.1,<2",
  "networkx[default]>=3.2,<4",
  "google-genai>=1.0",
]

[project.optional-dependencies]
dev = [
  "mypy>=1.10",
  "pytest>=8.2",
  "ruff>=0.5",
]
`
	tmp := filepath.Join(t.TempDir(), "pyproject.toml")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}

	pkgs, err := parsePyProjectToml(tmp)
	if err != nil {
		t.Fatalf("parsePyProjectToml failed: %v", err)
	}

	if len(pkgs) != 7 {
		t.Fatalf("expected 7 packages, got %d", len(pkgs))
	}

	expected := map[string]string{
		"pydantic":     "2.8",
		"lark":         "1.1",
		"networkx":     "3.2",
		"google-genai": "1.0",
		"mypy":         "1.10",
		"pytest":       "8.2",
		"ruff":         "0.5",
	}

	for _, p := range pkgs {
		if p.Ecosystem != "PyPI" {
			t.Errorf("expected PyPI ecosystem, got %s", p.Ecosystem)
		}
		if ver, ok := expected[p.Name]; !ok {
			t.Errorf("unexpected package %s", p.Name)
		} else if p.Version != ver {
			t.Errorf("package %s expected version %s, got %s", p.Name, ver, p.Version)
		}
	}
}

func TestIntelligentContentAndSourceDiscovery(t *testing.T) {
	// 1. Maven POM with ${property} interpolation
	pomDir := t.TempDir()
	pomPath := filepath.Join(pomDir, "pom.xml")
	pomXML := `<project>
		<version>1.0.0</version>
		<properties>
			<log4j.version>2.14.1</log4j.version>
		</properties>
		<dependencies>
			<dependency>
				<groupId>org.apache.logging.log4j</groupId>
				<artifactId>log4j-core</artifactId>
				<version>${log4j.version}</version>
			</dependency>
		</dependencies>
	</project>`
	if err := os.WriteFile(pomPath, []byte(pomXML), 0644); err != nil {
		t.Fatalf("write pom: %v", err)
	}
	pomPkgs, err := ParseManifest(pomPath)
	if err != nil || len(pomPkgs) != 1 || pomPkgs[0].Version != "2.14.1" {
		t.Fatalf("expected interpolated Maven version 2.14.1, got %+v (err=%v)", pomPkgs, err)
	}

	// 2. Gradle build.gradle.kts + libs.versions.toml
	gradleDir := t.TempDir()
	gradleKts := filepath.Join(gradleDir, "build.gradle.kts")
	_ = os.WriteFile(gradleKts, []byte(`dependencies { implementation("com.google.guava:guava:32.1.2-jre") }`), 0644)
	gPkgs, err := ParseManifest(gradleKts)
	if err != nil || len(gPkgs) != 1 || gPkgs[0].Name != "com.google.guava:guava" {
		t.Fatalf("expected guava from build.gradle.kts, got %+v (err=%v)", gPkgs, err)
	}

	// 3. Zero-manifest project fallback (source code import scanning across languages)
	srcDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(srcDir, "app.py"), []byte("import os\nimport requests\nfrom bs4 import BeautifulSoup\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "index.js"), []byte("const fs = require('fs');\nimport express from 'express';\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\nimport (\n\t\"fmt\"\n\t\"github.com/gin-gonic/gin/binding\"\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "lib.rs"), []byte("use std::collections::HashMap;\nuse serde::Serialize;\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "main.cpp"), []byte("#include <iostream>\n#include <openssl/ssl.h>\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "App.java"), []byte("import java.util.List;\nimport org.apache.logging.log4j.LogManager;\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "Program.cs"), []byte("using System;\nusing Newtonsoft.Json;\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "index.php"), []byte("<?php\nuse Monolog\\Logger;\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "app.rb"), []byte("require 'json'\nrequire 'sinatra/base'\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "main.dart"), []byte("import 'package:flutter/material.dart';\nimport 'package:http/http.dart';\n"), 0644)

	discoveredPkgs, sources, err := DiscoverDependencies(srcDir)
	if err != nil {
		t.Fatalf("DiscoverDependencies failed: %v", err)
	}
	if len(sources) != 10 {
		t.Fatalf("expected 10 source files discovered, got %d", len(sources))
	}
	found := make(map[string]string)
	for _, p := range discoveredPkgs {
		found[p.Name] = p.Ecosystem
	}
	expectedImports := map[string]string{
		"requests":                             "PyPI",
		"beautifulsoup4":                       "PyPI",
		"express":                              "npm",
		"github.com/gin-gonic/gin":             "Go",
		"serde":                                "crates.io",
		"openssl":                              "ConanCenter",
		"org.apache.logging.log4j:log4j-core":  "Maven",
		"Newtonsoft.Json":                      "NuGet",
		"monolog/logger":                       "Packagist",
		"sinatra":                              "RubyGems",
		"http":                                 "Pub",
	}
	for name, eco := range expectedImports {
		if found[name] != eco {
			t.Errorf("expected %s (%s) from source imports, got %q", name, eco, found[name])
		}
	}

	// 4. Installed environment artifacts (project.assets.json, vendor/modules.txt, vendor/composer/installed.json, vcpkg/status, .dart_tool/package_config.json)
	envDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(envDir, "obj"), 0755)
	_ = os.WriteFile(filepath.Join(envDir, "obj", "project.assets.json"), []byte(`{
		"libraries": {
			"Newtonsoft.Json/13.0.3": { "type": "package" },
			"MyProject/1.0.0": { "type": "project" }
		}
	}`), 0644)
	_ = os.MkdirAll(filepath.Join(envDir, "vendor", "composer"), 0755)
	_ = os.WriteFile(filepath.Join(envDir, "vendor", "modules.txt"), []byte("# github.com/pkg/errors v0.9.1\n"), 0644)
	_ = os.WriteFile(filepath.Join(envDir, "vendor", "composer", "installed.json"), []byte(`{
		"packages": [{ "name": "monolog/monolog", "version": "v2.9.1" }]
	}`), 0644)
	_ = os.MkdirAll(filepath.Join(envDir, "vcpkg_installed", "vcpkg"), 0755)
	_ = os.WriteFile(filepath.Join(envDir, "vcpkg_installed", "vcpkg", "status"), []byte("Package: zlib\nVersion: 1.3.1\nStatus: install ok installed\n\n"), 0644)
	_ = os.MkdirAll(filepath.Join(envDir, ".dart_tool"), 0755)
	_ = os.WriteFile(filepath.Join(envDir, ".dart_tool", "package_config.json"), []byte(`{
		"configVersion": 2,
		"packages": [{ "name": "dio", "rootUri": "file:///home/user/.pub-cache/hosted/pub.dev/dio-5.4.0" }]
	}`), 0644)

	envPkgs, _, err := DiscoverDependencies(envDir)
	if err != nil {
		t.Fatalf("env DiscoverDependencies failed: %v", err)
	}
	envMap := make(map[string]string)
	for _, p := range envPkgs {
		envMap[p.Name] = p.Version + "@" + p.Ecosystem
	}
	if envMap["Newtonsoft.Json"] != "13.0.3@NuGet" ||
		envMap["github.com/pkg/errors"] != "v0.9.1@Go" ||
		envMap["monolog/monolog"] != "2.9.1@Packagist" ||
		envMap["zlib"] != "1.3.1@ConanCenter" ||
		envMap["dio"] != "5.4.0@Pub" {
		t.Fatalf("unexpected environment introspection results: %+v", envMap)
	}
}
