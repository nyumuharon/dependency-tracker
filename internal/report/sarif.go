package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/nyumuharon/dependency-tracker/internal/model"
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

type SARIFConfiguration struct {
	Level string `json:"level"`
}

type SARIFHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type SARIFResult struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           int                    `json:"ruleIndex"`
	Level               string                 `json:"level"`
	Message             SARIFMessage           `json:"message"`
	Locations           []SARIFLocation        `json:"locations"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
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
func GenerateSARIF(results []model.ScanResult, outputPath string, appVersion string) error {
	return GenerateSARIFWithDirectory(results, outputPath, appVersion, os.Getwd)
}

func GenerateSARIFWithDirectory(results []model.ScanResult, outputPath string, appVersion string, workingDirectory func() (string, error)) error {
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
		artifact := sarifArtifact(r.Pkg.ManifestPath, workingDirectory)

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

				// A rule describes the vulnerability. The affected package and
				// version belong to each result, since several packages can
				// share one rule.
				level := "warning"
				severity := v.SeverityScore()
				properties := map[string]interface{}{
					"tags":      []string{"security", "dependency"},
					"precision": "very-high",
				}
				// security-severity is omitted, rather than reported as 0.0,
				// when no severity is known.
				if severity > 0 || v.IsKEV {
					secSeverity := fmt.Sprintf("%.1f", severity)
					if v.IsKEV && severity < 9.0 {
						secSeverity = "10.0"
					}
					properties["security-severity"] = secSeverity
				}
				if v.IsKEV || severity >= 7.0 {
					level = "error"
				} else if severity < 4.0 && severity > 0 {
					level = "note"
				}
				if v.IsKEV {
					properties["tags"] = []string{"security", "dependency", "cisa-kev"}
				}

				helpText := fmt.Sprintf("Vulnerability: %s\nCVSS: %s | EPSS: %s\n", ruleID, v.CVSSDisplay(), v.EPSSDisplay())
				helpMarkdown := fmt.Sprintf("### Vulnerability Details\n\n"+
					"- **Vulnerability ID**: `%s`\n"+
					"- **CVSS Base Score**: `%s`\n"+
					"- **EPSS Exploit Probability**: `%s`\n",
					ruleID, v.CVSSDisplay(), v.EPSSDisplay())
				if v.IsKEV {
					helpText += "Warning: Listed in CISA Known Exploited Vulnerabilities (KEV) catalog!\n"
					helpMarkdown += "\n**CISA KEV ALERT**: This vulnerability is actively exploited in the wild.\n"
				}
				if v.Summary != "" {
					helpMarkdown += fmt.Sprintf("\n**Summary**: %s\n", v.Summary)
				}
				helpText += "Affected packages, versions and fixed releases are listed on each result.\n"
				helpMarkdown += "\nAffected packages, versions and fixed releases are listed on each result.\n"

				shortText := ruleID
				if v.Summary != "" {
					shortText = ruleID + ": " + v.Summary
				}
				rule := SARIFRule{
					ID:               ruleID,
					Name:             "DependencyVulnerability",
					ShortDescription: SARIFMessage{Text: shortText},
					FullDescription:  SARIFMessage{Text: v.Summary},
					Help: SARIFHelp{
						Text:     helpText,
						Markdown: helpMarkdown,
					},
					DefaultConfiguration: SARIFConfiguration{
						Level: level,
					},
					Properties: properties,
				}

				report.Runs[0].Tool.Driver.Rules = append(report.Runs[0].Tool.Driver.Rules, rule)
			}

			// Determine result level
			resLevel := "warning"
			if severity := v.SeverityScore(); v.IsKEV || severity >= 7.0 {
				resLevel = "error"
			} else if severity < 4.0 && severity > 0 {
				resLevel = "note"
			}

			messageText := fmt.Sprintf("Dependency %s@%s contains %s (CVSS %s, EPSS %s).",
				r.Pkg.Name, r.Pkg.Version, ruleID, v.CVSSDisplay(), v.EPSSDisplay())
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
							ArtifactLocation: artifact,
							Region: SARIFRegion{
								StartLine: 1,
							},
						},
					},
				},
				// Every finding points at line 1 of its manifest, so the package
				// identity keeps separate findings apart.
				PartialFingerprints: map[string]string{
					"dependencyFinding/v1": strings.Join([]string{r.Pkg.Ecosystem, r.Pkg.Name, r.Pkg.Version, ruleID}, "|"),
				},
			}

			report.Runs[0].Results = append(report.Runs[0].Results, result)
		}
	}

	report.Runs[0].Invocations = []SARIFInvocation{invocation}
	// All report fields are fixed JSON-supported types; I/O failures are returned below.
	data, _ := json.MarshalIndent(report, "", "  ")

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// sarifArtifact locates a manifest for code scanning. Paths inside a Git
// repository are made relative to its root (%SRCROOT%), so they match the
// repository files whichever directory was scanned. Other paths are relative
// to the working directory when they lie below it, and absolute file URIs
// otherwise.
func sarifArtifact(manifestPath string, workingDirectory func() (string, error)) SARIFArtifactLocation {
	if manifestPath == "" {
		return SARIFArtifactLocation{URI: "manifest", URIBaseID: "%SRCROOT%"}
	}
	below := func(base, path string) (string, bool) {
		rel, err := filepath.Rel(base, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return "", false
		}
		return filepath.ToSlash(rel), true
	}
	abs := manifestPath
	if resolved, err := filepath.Abs(manifestPath); err == nil {
		abs = resolved
	}
	if repo := gitRepositoryRoot(filepath.Dir(abs)); repo != "" {
		if rel, ok := below(repo, abs); ok {
			return SARIFArtifactLocation{URI: rel, URIBaseID: "%SRCROOT%"}
		}
	}
	if cwd, err := workingDirectory(); err == nil {
		if cwdAbs, err := filepath.Abs(cwd); err == nil {
			if rel, ok := below(cwdAbs, abs); ok {
				return SARIFArtifactLocation{URI: rel, URIBaseID: "%SRCROOT%"}
			}
		}
	}
	return SARIFArtifactLocation{URI: (&url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(abs), "/")}).String()}
}

// gitRepositoryRoot returns the nearest directory at or above dir that
// contains .git, or "" when there is none.
func gitRepositoryRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
