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
		epss := 0.0
		if v.EPSSKnown {
			epss = v.EPSS
		}
		candidate := Score(v.CVSS, epss, true, v.IsKEV)
		if tierRank(candidate) < tierRank(tier) {
			tier = candidate
		}
	}
	return tier
}
