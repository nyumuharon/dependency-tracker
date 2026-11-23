package report

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nyumuharon/dependency-tracker/internal/model"
	"github.com/nyumuharon/dependency-tracker/internal/version"
)

type CycloneDXSBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     SBOMMetadata    `json:"metadata"`
	Components   []SBOMComponent `json:"components"`
}

type SBOMMetadata struct {
	Timestamp string `json:"timestamp"`
	Tools     []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tools"`
}

type SBOMComponent struct {
	BOMRef     string         `json:"bom-ref"`
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

func GenerateSBOM(results []model.ScanResult, outputPath string, appVersion string) error {
	sbom := CycloneDXSBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.4",
		SerialNumber: newSerialNumber(),
		Version:      1,
		Components:   []SBOMComponent{},
		Metadata: SBOMMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
	usedRefs := make(map[string]int)
	sbom.Metadata.Tools = append(sbom.Metadata.Tools, struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}{Name: "dependency-risk-tracker", Version: appVersion})

	for _, r := range results {
		comp := SBOMComponent{
			Type:    "library",
			Name:    r.Pkg.Name,
			Version: r.Pkg.Version,
			PURL:    BuildPURL(r.Pkg),
		}
		// bom-ref must be unique; the same package can appear in several
		// projects of one scan.
		ref := comp.PURL
		if ref == "" {
			ref = r.Pkg.Ecosystem + ":" + r.Pkg.Name + "@" + r.Pkg.Version
		}
		usedRefs[ref]++
		if n := usedRefs[ref]; n > 1 {
			ref = fmt.Sprintf("%s#%d", ref, n)
		}
		comp.BOMRef = ref

		if version.ValidateQueryVersion(r.Pkg) != nil {
			comp.Version = ""
		}

		comp.Properties = append(comp.Properties, SBOMProperty{
			Name:  "risk:priorityTier",
			Value: r.PriorityTier,
		})
		comp.Properties = append(comp.Properties, SBOMProperty{
			Name:  "risk:scanStatus",
			Value: r.ScanStatus,
		})
		if r.Pkg.VersionSource != "" {
			comp.Properties = append(comp.Properties, SBOMProperty{
				Name:  "risk:versionSource",
				Value: r.Pkg.VersionSource,
			})
		}
		if r.Pkg.ProjectPath != "" {
			comp.Properties = append(comp.Properties, SBOMProperty{
				Name:  "risk:projectPath",
				Value: r.Pkg.ProjectPath,
			})
		}
		if r.Pkg.ManifestPath != "" {
			comp.Properties = append(comp.Properties, SBOMProperty{
				Name:  "risk:manifestPath",
				Value: r.Pkg.ManifestPath,
			})
		}
		for _, errStr := range r.CheckErrors {
			comp.Properties = append(comp.Properties, SBOMProperty{
				Name:  "risk:checkError",
				Value: errStr,
			})
		}

		for _, v := range r.Vulnerabilities {
			comp.Properties = append(comp.Properties, SBOMProperty{
				Name:  "vuln:cveID",
				Value: fmt.Sprintf("%s (CVSS:%s EPSS:%s)", v.CVEID, v.CVSSDisplay(), v.EPSSDisplay()),
			})
			if v.Summary != "" {
				comp.Properties = append(comp.Properties, SBOMProperty{
					Name:  "vuln:summary",
					Value: v.Summary,
				})
			}
			if v.FixedVersion != "" {
				comp.Properties = append(comp.Properties, SBOMProperty{
					Name:  "vuln:fixedVersion",
					Value: v.FixedVersion,
				})
			}
			if v.IsKEV {
				comp.Properties = append(comp.Properties, SBOMProperty{
					Name:  "vuln:cisaKEV",
					Value: "true",
				})
			}
		}

		if r.Staleness.IsStale {
			comp.Properties = append(comp.Properties, SBOMProperty{
				Name:  "lifecycle:isStale",
				Value: "true",
			})
			if !r.Staleness.LastUpdated.IsZero() {
				comp.Properties = append(comp.Properties, SBOMProperty{
					Name:  "lifecycle:lastUpdated",
					Value: r.Staleness.LastUpdated.Format(time.RFC3339),
				})
			}
		}

		sbom.Components = append(sbom.Components, comp)
	}

	data, _ := json.MarshalIndent(sbom, "", "  ")

	if dir := filepath.Dir(outputPath); dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(outputPath, data, 0644)
}

// newSerialNumber returns a random (version 4) UUID URN, as CycloneDX expects.
func newSerialNumber() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func BuildPURL(pkg model.Package) string {
	if version.ValidateQueryVersion(pkg) != nil {
		return ""
	}
	name, ver := pkg.Name, url.PathEscape(pkg.Version)
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
		return fmt.Sprintf("pkg:npm/%s@%s", name, ver)
	case "PyPI":
		// The PURL spec requires lowercase PyPI names with "_" as "-".
		return fmt.Sprintf("pkg:pypi/%s@%s", strings.ReplaceAll(strings.ToLower(name), "_", "-"), ver)
	case "Maven":
		return fmt.Sprintf("pkg:maven/%s@%s", name, ver)
	case "NuGet":
		return fmt.Sprintf("pkg:nuget/%s@%s", name, ver)
	case "Go":
		return fmt.Sprintf("pkg:golang/%s@%s", name, ver)
	case "crates.io":
		return fmt.Sprintf("pkg:cargo/%s@%s", name, ver)
	case "Packagist":
		return fmt.Sprintf("pkg:composer/%s@%s", name, ver)
	case "RubyGems":
		return fmt.Sprintf("pkg:gem/%s@%s", name, ver)
	case "ConanCenter":
		return fmt.Sprintf("pkg:conan/%s@%s", name, ver)
	case "Pub":
		return fmt.Sprintf("pkg:pub/%s@%s", name, ver)
	case "Hex":
		return fmt.Sprintf("pkg:hex/%s@%s", name, ver)
	case "SwiftURL":
		return fmt.Sprintf("pkg:swift/%s@%s", name, ver)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", name, ver)
	}
}
