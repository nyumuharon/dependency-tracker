package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	Version    string         `json:"version,omitempty"`
	PURL       string         `json:"purl,omitempty"`
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
		Components:  []SBOMComponent{},
		Metadata: SBOMMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
	sbom.Metadata.Tools = append(sbom.Metadata.Tools, struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}{Name: "dependency-risk-tracker", Version: appVersion})

	for _, r := range results {
		comp := SBOMComponent{
			Type:    "library",
			Name:    r.Pkg.Name,
			Version: r.Pkg.Version,
			PURL:    buildPURL(r.Pkg),
		}

		if validateQueryVersion(r.Pkg) != nil {
			comp.Version = ""
			comp.Properties = append(comp.Properties, SBOMProperty{Name: "version:declared", Value: r.Pkg.Version})
		}

		comp.Properties = append(comp.Properties, SBOMProperty{
			Name:  "risk:priorityTier",
			Value: r.PriorityTier,
		})

		staleStatus := "UNKNOWN"
		if !r.Staleness.LastUpdated.IsZero() && r.Staleness.CheckError == "" {
			staleStatus = "ACTIVE"
		}
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

		comp.Properties = append(comp.Properties, SBOMProperty{Name: "scan:status", Value: r.ScanStatus}, SBOMProperty{Name: "version:source", Value: r.Pkg.VersionSource})
		for _, msg := range r.CheckErrors {
			comp.Properties = append(comp.Properties, SBOMProperty{Name: "scan:error", Value: msg})
		}

		for _, v := range r.Vulnerabilities {
			comp.Properties = append(comp.Properties, SBOMProperty{
				Name:  "vuln:cveID",
				Value: fmt.Sprintf("%s (CVSS:%.1f EPSS:%.5f)", v.CVEID, v.CVSS, v.EPSS),
			})
			if v.FixedVersion != "" {
				comp.Properties = append(comp.Properties, SBOMProperty{
					Name:  "vuln:fixedVersion",
					Value: fmt.Sprintf("%s: fixed release %s (verify branch compatibility)", v.CVEID, v.FixedVersion),
				})
			}
			if v.IsKEV {
				comp.Properties = append(comp.Properties, SBOMProperty{
					Name:  "vuln:cisaKEV",
					Value: "true",
				})
			}
		}

		sbom.Components = append(sbom.Components, comp)
	}

	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return fmt.Errorf("sbom marshal: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

func buildPURL(pkg Package) string {
	if validateQueryVersion(pkg) != nil {
		return ""
	}
	name, version := pkg.Name, url.PathEscape(pkg.Version)
	// Escape each namespace/name segment while retaining its separators.
	segments := strings.Split(name, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
		segments[i] = strings.ReplaceAll(segments[i], "@", "%40")
	}
	name = strings.Join(segments, "/")
	if pkg.Ecosystem == "Maven" {
		name = strings.Replace(name, ":", "/", 1)
	}
	switch pkg.Ecosystem {
	case "npm":
		return fmt.Sprintf("pkg:npm/%s@%s", name, version)
	case "PyPI":
		return fmt.Sprintf("pkg:pypi/%s@%s", name, version)
	case "Maven":
		return fmt.Sprintf("pkg:maven/%s@%s", name, version)
	case "NuGet":
		return fmt.Sprintf("pkg:nuget/%s@%s", name, version)
	case "Go":
		return fmt.Sprintf("pkg:golang/%s@%s", name, version)
	case "crates.io":
		return fmt.Sprintf("pkg:cargo/%s@%s", name, version)
	case "Packagist":
		return fmt.Sprintf("pkg:composer/%s@%s", name, version)
	case "RubyGems":
		return fmt.Sprintf("pkg:gem/%s@%s", name, version)
	case "ConanCenter":
		return fmt.Sprintf("pkg:conan/%s@%s", name, version)
	case "Pub":
		return fmt.Sprintf("pkg:pub/%s@%s", name, version)
	case "Hex":
		return fmt.Sprintf("pkg:hex/%s@%s", name, version)
	case "SwiftURL":
		return fmt.Sprintf("pkg:swift/%s@%s", name, version)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", name, version)
	}
}
