package report

import (
	"github.com/nyumuharon/dependency-tracker/internal/model"
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

// NormalizeSeverityLabel maps the qualitative rating of an advisory database
// to LOW, MEDIUM, HIGH or CRITICAL. Unrecognised ratings yield "".
func NormalizeSeverityLabel(label string) string {
	return model.NormalizeSeverityLabel(label)
}

// SeverityLabelScore returns the lowest CVSS score in the band of a
// qualitative rating, or 0 when there is no usable rating.
func SeverityLabelScore(label string) float64 {
	return model.SeverityLabelScore(label)
}

// ScoreVulnerabilities applies both exploitability thresholds to the same advisory.
func ScoreVulnerabilities(vulns []model.Vulnerability) string {
	tier := "NONE"
	for _, v := range vulns {
		epss := 0.0
		if v.EPSSKnown {
			epss = v.EPSS
		}
		candidate := Score(v.SeverityScore(), epss, true, v.IsKEV)
		if TierRank(candidate) < TierRank(tier) {
			tier = candidate
		}
	}
	return tier
}

// ScorePackage prioritises by discovered vulnerabilities first, even when a
// check was incomplete. Missing data only creates UNKNOWN when no higher-tier
// finding has already been confirmed.
func ScorePackage(vulns []model.Vulnerability, scanIncomplete bool) string {
	tier := ScoreVulnerabilities(vulns)
	if tier == "NONE" && scanIncomplete {
		return "UNKNOWN"
	}
	return tier
}
