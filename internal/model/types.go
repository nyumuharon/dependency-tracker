package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Package struct {
	Name          string
	Version       string
	Ecosystem     string
	ManifestPath  string
	ProjectPath   string
	VersionSource string
}

// Key returns a unique identifier for a specific package name, version, and ecosystem.
func (p Package) Key() string {
	return p.Name + "@" + p.Version + "@" + p.Ecosystem + "@" + p.ProjectPath
}

// StalenessKey returns a unique identifier for a package name and ecosystem on an upstream registry.
func (p Package) StalenessKey() string {
	return p.Name + "@" + p.Ecosystem
}

type StalenessResult struct {
	CheckError    string    `json:"check_error,omitempty"`
	LatestVersion string    `json:"latest_version"`
	LastUpdated   time.Time `json:"last_updated"`
	IsStale       bool      `json:"is_stale"`
	CachedAt      time.Time `json:"cached_at"`
}

type Vulnerability struct {
	CVEID         string
	Summary       string
	CVSS          float64
	Severity      string // advisory database rating (LOW to CRITICAL); ranks an advisory only when CVSS is unknown
	ID            string
	EPSS          float64
	EPSSKnown     bool
	FixedVersion  string
	IsKEV         bool
	KEVRansomware bool
}

// MarshalJSON uses null for unknown EPSS scores. EPSSKnown distinguishes a
// confirmed zero probability from missing data in Go and in exported reports.
func (v Vulnerability) MarshalJSON() ([]byte, error) {
	type plain Vulnerability
	var score *float64
	if v.EPSSKnown {
		score = &v.EPSS
	}
	return json.Marshal(struct {
		plain
		EPSS *float64
	}{plain: plain(v), EPSS: score})
}

func (v Vulnerability) EPSSDisplay() string {
	if v.EPSSKnown {
		return fmt.Sprintf("%.5f", v.EPSS)
	}
	if strings.HasPrefix(v.CVEID, "CVE-") {
		return "unknown"
	}
	return "not applicable (non-CVE advisory)"
}

func (v Vulnerability) SeverityScore() float64 {
	if v.CVSS > 0 {
		return v.CVSS
	}
	return SeverityLabelScore(v.Severity)
}

func (v Vulnerability) CVSSDisplay() string {
	if v.CVSS > 0 {
		return fmt.Sprintf("%.1f", v.CVSS)
	}
	if v.Severity != "" {
		return "unscored, rated " + v.Severity
	}
	return "unknown"
}

func SeverityLabelScore(label string) float64 {
	switch label {
	case "LOW":
		return 0.1
	case "MEDIUM":
		return 4.0
	case "HIGH":
		return 7.0
	case "CRITICAL":
		return 9.0
	}
	return 0
}

type ScanResult struct {
	ScanStatus      string
	CheckErrors     []string `json:",omitempty"`
	Pkg             Package
	Vulnerabilities []Vulnerability
	PriorityTier    string
	Staleness       StalenessResult
}
