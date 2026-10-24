package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations"`
}

type SARIFInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []SARIFNotification `json:"toolExecutionNotifications,omitempty"`
}
type SARIFNotification struct {
	Level   string       `json:"level"`
	Message SARIFMessage `json:"message"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     SARIFMessage           `json:"shortDescription"`
	FullDescription      SARIFMessage           `json:"fullDescription,omitempty"`
	Help                 SARIFHelp              `json:"help,omitempty"`
	DefaultConfiguration SARIFConfiguration     `json:"defaultConfiguration"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
}

type SARIFHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type SARIFConfiguration struct {
	Level string `json:"level"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

// GenerateSARIF creates a standard SARIF v2.1.0 document from scan results.
func GenerateSARIF(results []ScanResult, outputPath string) error {
	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "dependency-risk-tracker",
						Version:        appVersion,
						InformationURI: "https://github.com/nyumuharon/dependency-tracker",
						Rules:          []SARIFRule{},
					},
				},
				Results: []SARIFResult{},
			},
		},
	}

	invocation := SARIFInvocation{ExecutionSuccessful: true}
	ruleIndexMap := make(map[string]int)

	for _, r := range results {
		if r.ScanStatus == "incomplete" {
			invocation.ExecutionSuccessful = false
			for _, msg := range r.CheckErrors {
				invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, SARIFNotification{Level: "error", Message: SARIFMessage{Text: r.Pkg.Name + ": " + msg}})
			}
		}
		// Determine manifest file URI
		manifestURI := r.Pkg.ManifestPath
		if manifestURI == "" {
			manifestURI = "manifest"
		}
		// Convert to relative path if possible for GitHub Actions compatibility
		if cwd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(cwd, manifestURI); err == nil && !strings.HasPrefix(rel, "..") {
				manifestURI = rel
			}
		}

		for _, v := range r.Vulnerabilities {
			ruleID := v.CVEID
			if ruleID == "" {
				ruleID = v.ID
			}

			// Add rule definition if not already registered
			rIdx, exists := ruleIndexMap[ruleID]
			if !exists {
				rIdx = len(report.Runs[0].Tool.Driver.Rules)
				ruleIndexMap[ruleID] = rIdx

				// Map severity level
				level := "warning"
				secSeverity := fmt.Sprintf("%.1f", v.CVSS)
				if v.IsKEV || v.CVSS >= 7.0 {
					level = "error"
					if v.IsKEV && v.CVSS < 9.0 {
						secSeverity = "10.0"
					}
				} else if v.CVSS < 4.0 && v.CVSS > 0 {
					level = "note"
				}

				tags := []string{"security", "dependency", r.Pkg.Ecosystem}
				if v.IsKEV {
					tags = append(tags, "cisa-kev")
				}

				helpText := fmt.Sprintf("Package: %s (%s)\nInstalled Version: %s\nCVSS: %.1f | EPSS: %.5f\n",
					r.Pkg.Name, r.Pkg.Ecosystem, r.Pkg.Version, v.CVSS, v.EPSS)
				if v.FixedVersion != "" {
					helpText += fmt.Sprintf("Fixed release: %s (verify branch compatibility)\n", v.FixedVersion)
				}
				if v.IsKEV {
					helpText += "Warning: Listed in CISA Known Exploited Vulnerabilities (KEV) catalog!\n"
				}

				helpMarkdown := fmt.Sprintf("### Vulnerability Details\n\n"+
					"- **Package**: `%s` (%s)\n"+
					"- **Installed Version**: `%s`\n"+
					"- **Vulnerability ID**: `%s`\n"+
					"- **CVSS Base Score**: `%.1f`\n"+
					"- **EPSS Exploit Probability**: `%.5f`\n",
					r.Pkg.Name, r.Pkg.Ecosystem, r.Pkg.Version, ruleID, v.CVSS, v.EPSS)

				if v.FixedVersion != "" {
					helpMarkdown += fmt.Sprintf("- **Remediation**: Fixed release `%s` (verify branch compatibility)\n", v.FixedVersion)
				}
				if v.IsKEV {
					helpMarkdown += "\n**CISA KEV ALERT**: This vulnerability is actively exploited in the wild.\n"
				}
				if v.Summary != "" {
					helpMarkdown += fmt.Sprintf("\n**Summary**: %s\n", v.Summary)
				}

				rule := SARIFRule{
					ID:   ruleID,
					Name: "DependencyVulnerability",
					ShortDescription: SARIFMessage{
						Text: fmt.Sprintf("%s in %s@%s", ruleID, r.Pkg.Name, r.Pkg.Version),
					},
					FullDescription: SARIFMessage{
						Text: v.Summary,
					},
					Help: SARIFHelp{
						Text:     helpText,
						Markdown: helpMarkdown,
					},
					DefaultConfiguration: SARIFConfiguration{
						Level: level,
					},
					Properties: map[string]interface{}{
						"tags":              tags,
						"security-severity": secSeverity,
						"precision":         "very-high",
					},
				}

				report.Runs[0].Tool.Driver.Rules = append(report.Runs[0].Tool.Driver.Rules, rule)
			}

			// Determine result level
			resLevel := "warning"
			if v.IsKEV || v.CVSS >= 7.0 {
				resLevel = "error"
			} else if v.CVSS < 4.0 && v.CVSS > 0 {
				resLevel = "note"
			}

			messageText := fmt.Sprintf("Dependency %s@%s contains %s (CVSS %.1f, EPSS %.5f).",
				r.Pkg.Name, r.Pkg.Version, ruleID, v.CVSS, v.EPSS)
			if v.FixedVersion != "" {
				messageText += fmt.Sprintf(" Fixed release: %s (verify branch compatibility).", v.FixedVersion)
			}
			if v.IsKEV {
				messageText += " WARNING: Actively exploited in the wild according to CISA KEV!"
			}

			result := SARIFResult{
				RuleID:    ruleID,
				RuleIndex: rIdx,
				Level:     resLevel,
				Message: SARIFMessage{
					Text: messageText,
				},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI:       filepath.ToSlash(manifestURI),
								URIBaseID: "%SRCROOT%",
							},
							Region: SARIFRegion{
								StartLine: 1,
							},
						},
					},
				},
			}

			report.Runs[0].Results = append(report.Runs[0].Results, result)
		}
	}

	report.Runs[0].Invocations = []SARIFInvocation{invocation}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("sarif marshal: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}
