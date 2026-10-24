package main

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
	return "LOW"
}

// ScoreVulnerabilities applies both exploitability thresholds to the same advisory.
func ScoreVulnerabilities(vulns []Vulnerability) string {
	tier := "NONE"
	for _, v := range vulns {
		candidate := Score(v.CVSS, v.EPSS, true, v.IsKEV)
		if tierRank(candidate) < tierRank(tier) {
			tier = candidate
		}
	}
	return tier
}
