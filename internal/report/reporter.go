package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nyumuharon/dependency-tracker/internal/model"
	"github.com/nyumuharon/dependency-tracker/internal/version"
)

const (
	maxInlineVulnerabilities = 7
	maxInlineIncomplete      = 5
)

func TierRank(tier string) int {
	switch tier {
	case "CRITICAL-EXPLOITABLE":
		return 1
	case "HIGH":
		return 2
	case "MEDIUM":
		return 3
	case "LOW":
		return 4
	case "UNKNOWN":
		return 5
	default:
		return 6
	}
}

func PrintReport(results []model.ScanResult) {
	PrintReportWithOptions(results, false, false)
}

func PrintReportWithOptions(results []model.ScanResult, showAllVulns, showAllIncomplete bool) {
	sep := strings.Repeat("=", 72)
	thinSep := strings.Repeat("-", 72)

	// Sort a copy, so the caller's order (used for the SBOM and SARIF) is kept:
	// highest priority first (CRITICAL -> HIGH -> MEDIUM -> LOW -> NONE), then alphabetically
	results = append([]model.ScanResult(nil), results...)
	sort.SliceStable(results, func(i, j int) bool {
		ri, rj := TierRank(results[i].PriorityTier), TierRank(results[j].PriorityTier)
		if ri != rj {
			return ri < rj
		}
		return strings.ToLower(results[i].Pkg.Name) < strings.ToLower(results[j].Pkg.Name)
	})

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	noneCount := 0
	unknownCount := 0
	staleCount := 0
	totalVulns := 0
	kevCount := 0
	fixCount := 0

	var vulnResults []model.ScanResult
	var staleOnlyClean []model.ScanResult
	var cleanCount int
	var incompleteCount int

	type RemediationRow struct {
		PkgName string
		Tier    string
		Current string
		Fix     string
	}
	var remediations []RemediationRow

	for _, r := range results {
		if r.ScanStatus == "incomplete" {
			incompleteCount++
		}
		if r.Staleness.IsStale {
			staleCount++
		}

		switch r.PriorityTier {
		case "CRITICAL-EXPLOITABLE":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		case "NONE":
			noneCount++
		case "UNKNOWN":
			unknownCount++
		}

		if len(r.Vulnerabilities) > 0 {
			vulnResults = append(vulnResults, r)
			totalVulns += len(r.Vulnerabilities)

			var fixes []string
			seenFix := make(map[string]bool)
			for _, v := range r.Vulnerabilities {
				if v.IsKEV {
					kevCount++
				}
				if v.FixedVersion != "" {
					fixCount++
					if !seenFix[v.FixedVersion] {
						fixes = append(fixes, v.FixedVersion)
						seenFix[v.FixedVersion] = true
					}
				}
			}
			if len(fixes) > 0 {
				eco := r.Pkg.Ecosystem
				sort.SliceStable(fixes, func(i, j int) bool {
					if c, ok := version.CompareVersions(fixes[i], fixes[j], eco); ok {
						return c < 0
					}
					return fixes[i] < fixes[j]
				})
				remediations = append(remediations, RemediationRow{
					PkgName: r.Pkg.Name,
					Tier:    r.PriorityTier,
					Current: r.Pkg.Version,
					Fix:     strings.Join(fixes, ", "),
				})
			}
		} else if r.ScanStatus != "incomplete" {
			cleanCount++
			if r.Staleness.IsStale {
				staleOnlyClean = append(staleOnlyClean, r)
			}
		}
	}

	fmt.Println(sep)
	fmt.Printf("%48s\n", "DEPENDENCY RISK TRACKER — SCAN REPORT")
	fmt.Println(sep)

	// ── SECTION 1: VULNERABILITIES (HIGH-SIGNAL) ──────────────────────────────
	if len(vulnResults) > 0 {
		fmt.Printf("\n🚨 IDENTIFIED VULNERABILITIES (%d package(s) affected):\n", len(vulnResults))
		shownVulns := 0
		for _, r := range vulnResults {
			if !showAllVulns && shownVulns >= maxInlineVulnerabilities {
				continue
			}
			shownVulns++
			badge := "[!]"
			if r.PriorityTier == "CRITICAL-EXPLOITABLE" {
				badge = "[CRITICAL-EXPLOITABLE]"
			} else {
				badge = fmt.Sprintf("[%s]", r.PriorityTier)
			}

			fmt.Printf("\n%s %s (%s)\n", badge, r.Pkg.Name, r.Pkg.Ecosystem)
			fmt.Printf("    Scanned Version : %s (%s)\n", r.Pkg.Version, r.Pkg.VersionSource)
			if r.Staleness.LatestVersion != "" {
				statusStr := "UNKNOWN"
				if !r.Staleness.LastUpdated.IsZero() && r.Staleness.CheckError == "" {
					statusStr = "ACTIVE"
				}
				if r.Staleness.IsStale {
					statusStr = "STALE (No updates in > 2 years)"
				}
				fmt.Printf("    Latest Version  : %s (%s)\n", r.Staleness.LatestVersion, statusStr)
			}

			fmt.Printf("    Vulnerabilities (%d):\n", len(r.Vulnerabilities))
			for _, v := range r.Vulnerabilities {
				idDisplay := v.CVEID
				if v.ID != "" && v.ID != v.CVEID {
					idDisplay = fmt.Sprintf("%s (%s)", v.CVEID, v.ID)
				}
				kevTag := ""
				if v.IsKEV {
					if v.KEVRansomware {
						kevTag = " | ⚠️ CISA-KEV: KNOWN RANSOMWARE"
					} else {
						kevTag = " | ⚠️ CISA-KEV EXPLOITED"
					}
				}
				fmt.Printf("      • %s [CVSS: %s | EPSS: %s%s]\n", idDisplay, v.CVSSDisplay(), v.EPSSDisplay(), kevTag)
				if v.Summary != "" {
					fmt.Printf("        Summary : %s\n", v.Summary)
				}
				if v.FixedVersion != "" {
					fmt.Printf("        Fix     : Fixed release: %s; verify branch compatibility\n", v.FixedVersion)
				}
			}
		}
		if !showAllVulns && len(vulnResults) > maxInlineVulnerabilities {
			fmt.Printf("\n... and %d more vulnerable package(s) collapsed for readability.\n", len(vulnResults)-maxInlineVulnerabilities)
			fmt.Println("    Run 'dep-tracker vulnerabilities' to view all vulnerable packages from sbom.json, or scan with '--show-vulnerabilities'.")
		}
	} else {
		if incompleteCount > 0 {
			fmt.Println("\nScan incomplete: absence of findings does not establish a clean scan.")
		} else {
			fmt.Println("\n✅ No vulnerabilities found across scanned packages!")
		}
	}

	// ── SECTION 2: ACTIONABLE REMEDIATION TABLE ───────────────────────────────
	if len(remediations) > 0 {
		fmt.Printf("\n\n%s\n", sep)
		fmt.Printf("%45s\n", "RECOMMENDED ACTIONS & FIXES")
		fmt.Println(sep)
		// Columns widen to the longest entry so long names keep the table aligned.
		nameWidth, currentWidth := 25, 12
		for _, rem := range remediations {
			nameWidth = max(nameWidth, len(rem.PkgName))
			currentWidth = max(currentWidth, len(rem.Current))
		}
		fmt.Printf("  %-*s %-20s %-*s %s\n", nameWidth, "PACKAGE", "SEVERITY", currentWidth, "CURRENT", "FIXED RELEASES")
		fmt.Println(thinSep)
		for _, rem := range remediations {
			fmt.Printf("  %-*s %-20s %-*s %s\n", nameWidth, rem.PkgName, rem.Tier, currentWidth, rem.Current, rem.Fix)
		}
	}

	if len(remediations) > 0 {
		fmt.Println("  Fixed releases apply to individual advisories; review the details above before upgrading.")
	}
	shownIncomplete := 0
	for _, r := range results {
		if r.ScanStatus == "incomplete" {
			if !showAllIncomplete && shownIncomplete >= maxInlineIncomplete {
				continue
			}
			shownIncomplete++
			fmt.Printf("\n[INCOMPLETE] %s@%s (%s; source: %s)\n", r.Pkg.Name, r.Pkg.Version, r.Pkg.ManifestPath, r.Pkg.VersionSource)
			for _, msg := range r.CheckErrors {
				fmt.Printf("  - %s\n", msg)
			}
		}
	}
	if !showAllIncomplete && incompleteCount > maxInlineIncomplete {
		fmt.Printf("\n... and %d more incomplete check(s) collapsed for readability.\n", incompleteCount-maxInlineIncomplete)
		fmt.Println("    Run 'dep-tracker incomplete' to view all incomplete checks from sbom.json, or scan with '--show-incomplete'.")
	}

	// ── SECTION 3: STALE / ABANDONED PACKAGES ─────────────────────────────────
	if len(staleOnlyClean) > 0 {
		fmt.Printf("\n\n%s\n", sep)
		fmt.Printf("⚠️  STALE PACKAGES WITH NO UPSTREAM RELEASE IN > 2 YEARS (%d):\n", len(staleOnlyClean))
		fmt.Println(sep)
		colWidth := 34
		for i := 0; i < len(staleOnlyClean); i += 2 {
			p1 := fmt.Sprintf("• %s@%s", staleOnlyClean[i].Pkg.Name, staleOnlyClean[i].Pkg.Version)
			p2 := ""
			if i+1 < len(staleOnlyClean) {
				p2 = fmt.Sprintf("• %s@%s", staleOnlyClean[i+1].Pkg.Name, staleOnlyClean[i+1].Pkg.Version)
			}
			fmt.Printf("  %-*s %s\n", colWidth, p1, p2)
		}
	}

	// ── SECTION 4: SAFE PACKAGES SUMMARY ─────────────────────────────────────
	if cleanCount > 0 {
		fmt.Printf("\n✓ %d package(s) scanned with zero known security advisories.\n", cleanCount)
	}

	// ── SECTION 5: EXECUTIVE SUMMARY ──────────────────────────────────────────
	ecosystems := make(map[string]bool)
	for _, r := range results {
		if r.Pkg.Ecosystem != "" {
			ecosystems[r.Pkg.Ecosystem] = true
		}
	}
	var ecoList []string
	for e := range ecosystems {
		ecoList = append(ecoList, e)
	}
	sort.Strings(ecoList)

	fmt.Printf("\n%s\n", sep)
	fmt.Printf("%38s\n", "EXECUTIVE SUMMARY")
	fmt.Println(sep)
	fmt.Printf("Total Packages Scanned : %d\n", len(results))
	fmt.Printf("Incomplete Checks      : %d package(s)\n", incompleteCount)
	if len(ecoList) > 0 {
		fmt.Printf("Ecosystems Scanned     : %s (%d)\n", strings.Join(ecoList, ", "), len(ecoList))
	}
	fmt.Printf("Total Vulnerabilities  : %d\n", totalVulns)
	if kevCount > 0 {
		fmt.Printf("CISA KEV Exploited     : %d (ACTIVELY EXPLOITED THREATS)\n", kevCount)
	}
	fmt.Printf("Remediations Available : %d\n", fixCount)
	fmt.Printf("Stale Packages         : %d\n", staleCount)
	fmt.Printf("\nPriority Tier Breakdown:\n")
	fmt.Printf("  CRITICAL-EXPLOITABLE : %d\n", criticalCount)
	fmt.Printf("  HIGH                 : %d\n", highCount)
	fmt.Printf("  MEDIUM               : %d\n", mediumCount)
	fmt.Printf("  LOW                  : %d\n", lowCount)
	fmt.Printf("  NONE                 : %d\n", noneCount)
	fmt.Printf("  UNKNOWN              : %d\n", unknownCount)
	fmt.Println(sep)
}

func PrintIncompleteFromSBOM(sbomPath string) error {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", sbomPath, err)
	}
	var sbom CycloneDXSBOM
	if err := json.Unmarshal(data, &sbom); err != nil {
		return fmt.Errorf("invalid SBOM %s: %w", sbomPath, err)
	}

	sep := strings.Repeat("=", 72)
	fmt.Println(sep)
	fmt.Printf("%48s\n", "DEPENDENCY RISK TRACKER — INCOMPLETE CHECKS")
	fmt.Println(sep)

	count := 0
	for _, comp := range sbom.Components {
		var status, manifest, source string
		var errs []string
		for _, prop := range comp.Properties {
			switch prop.Name {
			case "risk:scanStatus":
				status = prop.Value
			case "risk:manifestPath":
				manifest = prop.Value
			case "risk:versionSource":
				source = prop.Value
			case "risk:checkError":
				errs = append(errs, prop.Value)
			}
		}
		if status != "incomplete" {
			continue
		}
		count++
		ver := comp.Version
		if ver == "" {
			if _, after, ok := strings.Cut(strings.SplitN(comp.BOMRef, "#", 2)[0], "@"); ok {
				ver = after
			}
		}
		fmt.Printf("\n[INCOMPLETE] %s@%s (%s; source: %s)\n", comp.Name, ver, manifest, source)
		for _, msg := range errs {
			fmt.Printf("  - %s\n", msg)
		}
	}

	if count == 0 {
		fmt.Printf("\n✅ No incomplete checks recorded in %s.\n", sbomPath)
	} else {
		fmt.Printf("\nTotal incomplete checks: %d (from %s)\n", count, sbomPath)
	}
	fmt.Println(sep)
	return nil
}

func PrintVulnerabilitiesFromSBOM(sbomPath string) error {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", sbomPath, err)
	}
	var sbom CycloneDXSBOM
	if err := json.Unmarshal(data, &sbom); err != nil {
		return fmt.Errorf("invalid SBOM %s: %w", sbomPath, err)
	}

	sep := strings.Repeat("=", 72)
	fmt.Println(sep)
	fmt.Printf("%48s\n", "DEPENDENCY RISK TRACKER — VULNERABILITIES")
	fmt.Println(sep)

	count := 0
	for _, comp := range sbom.Components {
		var tier, manifest, source string
		var details []string
		hasVuln := false
		for _, prop := range comp.Properties {
			switch prop.Name {
			case "risk:priorityTier":
				tier = prop.Value
			case "risk:manifestPath":
				manifest = prop.Value
			case "risk:versionSource":
				source = prop.Value
			case "vuln:cveID":
				hasVuln = true
				details = append(details, "  • "+prop.Value)
			case "vuln:summary":
				details = append(details, "    Summary : "+prop.Value)
			case "vuln:fixedVersion":
				details = append(details, "    Fix     : Fixed release: "+prop.Value)
			case "vuln:cisaKEV":
				details = append(details, "    CISA-KEV: ⚠️ Actively exploited")
			}
		}
		if !hasVuln {
			continue
		}
		count++
		fmt.Printf("\n[%s] %s@%s (%s; source: %s)\n", tier, comp.Name, comp.Version, manifest, source)
		for _, line := range details {
			fmt.Println(line)
		}
	}

	if count == 0 {
		fmt.Printf("\n✅ No vulnerabilities recorded in %s.\n", sbomPath)
	} else {
		fmt.Printf("\nTotal vulnerable packages: %d (from %s)\n", count, sbomPath)
	}
	fmt.Println(sep)
	return nil
}
