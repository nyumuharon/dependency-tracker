package main

import (
	"fmt"
	"strings"
)

func Score(cvss float64, epss float64, hasCVE bool, isKEV bool) string {
	if !hasCVE {
		return "NONE"
	}
	if isKEV || (cvss >= 7.0 && epss >= 0.2) {
		return "CRITICAL-EXPLOITABLE"
	}
	if cvss >= 7.0 {
		return "HIGH"
	}
	if cvss >= 4.0 {
		return "MEDIUM"
	}
	if cvss > 0 {
		return "LOW"
	}
	// No score from any source: the advisory is real but its severity is not
	// known, which must not be presented as low risk.
	return "UNKNOWN"
}

// normalizeSeverityLabel maps the qualitative rating of an advisory database
// to LOW, MEDIUM, HIGH or CRITICAL. Unrecognised ratings yield "".
func normalizeSeverityLabel(label string) string {
	switch l := strings.ToUpper(strings.TrimSpace(label)); l {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return l
	case "MODERATE":
		return "MEDIUM"
	}
	return ""
}

// severityLabelScore returns the lowest CVSS score in the band of a
// qualitative rating, or 0 when there is no usable rating.
func severityLabelScore(label string) float64 {
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

// severityScore is the score used for prioritisation: the CVSS base score when
// one is known, otherwise the floor of the qualitative rating.
func (v Vulnerability) severityScore() float64 {
	if v.CVSS > 0 {
		return v.CVSS
	}
	return severityLabelScore(v.Severity)
}

// cvssDisplay never prints a missing score as 0.0.
func (v Vulnerability) cvssDisplay() string {
	if v.CVSS > 0 {
		return fmt.Sprintf("%.1f", v.CVSS)
	}
	if v.Severity != "" {
		return "unscored, rated " + v.Severity
	}
	return "unknown"
}

// ScoreVulnerabilities applies both exploitability thresholds to the same advisory.
func ScoreVulnerabilities(vulns []Vulnerability) string {
	tier := "NONE"
	for _, v := range vulns {
		epss := 0.0
		if v.EPSSKnown {
			epss = v.EPSS
		}
		candidate := Score(v.severityScore(), epss, true, v.IsKEV)
		if tierRank(candidate) < tierRank(tier) {
			tier = candidate
		}
	}
	return tier
}
