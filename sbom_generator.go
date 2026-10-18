package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type CycloneDXSBOM struct {
	BOMFormat   string          `json:"bomFormat"`
	SpecVersion string          `json:"specVersion"`
	Version     int             `json:"version"`
	Metadata    SBOMMetadata    `json:"metadata"`
	Components  []SBOMComponent `json:"components"`
}

type SBOMMetadata struct {
	Timestamp string `json:"timestamp"`
	Tools     []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tools"`
}

type SBOMComponent struct {
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	Properties []SBOMProperty `json:"properties,omitempty"`
}

type SBOMProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func GenerateSBOM(results []ScanResult, outputPath string) error {
	sbom := CycloneDXSBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
		Metadata: SBOMMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
	sbom.Metadata.Tools = append(sbom.Metadata.Tools, struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}{Name: "dependency-risk-tracker", Version: "1.0.0"})

	for _, r := range results {
		comp := SBOMComponent{
			Type:    "library",
			Name:    r.Pkg.Name,
			Version: r.Pkg.Version,
			PURL:    buildPURL(r.Pkg),
		}

		comp.Properties = append(comp.Properties, SBOMProperty{
			Name:  "risk:priorityTier",
			Value: r.PriorityTier,
		})

		staleStatus := "ACTIVE"
		if r.Staleness.IsStale {
			staleStatus = "STALE"
		}
		comp.Properties = append(comp.Properties, SBOMProperty{
			Name:  "risk:staleness",
			Value: staleStatus,
		})

		if r.Staleness.LatestVersion != "" {
			comp.Properties = append(comp.Properties, SBOMProperty{
				Name:  "risk:latestVersion",
				Value: r.Staleness.LatestVersion,
			})
		}

		for _, v := range r.Vulnerabilities {
			comp.Properties = append(comp.Properties, SBOMProperty{
				Name:  "vuln:cveID",
				Value: fmt.Sprintf("%s (CVSS:%.1f EPSS:%.5f)", v.CVEID, v.CVSS, v.EPSS),
			})
		}

		sbom.Components = append(sbom.Components, comp)
	}

	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return fmt.Errorf("sbom marshal: %w", err)
	}

	return os.WriteFile(outputPath, data, 0644)
}

func buildPURL(pkg Package) string {
	switch pkg.Ecosystem {
	case "npm":
		return fmt.Sprintf("pkg:npm/%s@%s", pkg.Name, pkg.Version)
	case "PyPI":
		return fmt.Sprintf("pkg:pypi/%s@%s", pkg.Name, pkg.Version)
	case "Maven":
		return fmt.Sprintf("pkg:maven/%s@%s", pkg.Name, pkg.Version)
	case "NuGet":
		return fmt.Sprintf("pkg:nuget/%s@%s", pkg.Name, pkg.Version)
	case "Go":
		return fmt.Sprintf("pkg:golang/%s@%s", pkg.Name, pkg.Version)
	case "crates.io":
		return fmt.Sprintf("pkg:cargo/%s@%s", pkg.Name, pkg.Version)
	case "Packagist":
		return fmt.Sprintf("pkg:composer/%s@%s", pkg.Name, pkg.Version)
	case "RubyGems":
		return fmt.Sprintf("pkg:gem/%s@%s", pkg.Name, pkg.Version)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", pkg.Name, pkg.Version)
	}
}
