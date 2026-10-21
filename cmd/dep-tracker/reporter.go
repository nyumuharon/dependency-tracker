package main

import (
	"fmt"
	"sort"
	"strings"
)

type ScanResult struct {
	Pkg             Package
	Vulnerabilities []Vulnerability
	PriorityTier    string
	Staleness       StalenessResult
}

func tierRank(tier string) int {
	switch tier {
	case "CRITICAL-EXPLOITABLE":
		return 1
	case "HIGH":
		return 2
	case "MEDIUM":
		return 3
	case "LOW":
		return 4
	default:
		return 5
	}
}

func PrintReport(results []ScanResult) {
	sep := strings.Repeat("=", 72)
	thinSep := strings.Repeat("-", 72)

	// Sort results: highest priority first (CRITICAL -> HIGH -> MEDIUM -> LOW -> NONE), then alphabetically
	sort.SliceStable(results, func(i, j int) bool {
		ri, rj := tierRank(results[i].PriorityTier), tierRank(results[j].PriorityTier)
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
	staleCount := 0
	totalVulns := 0
	kevCount := 0
	fixCount := 0

	var vulnResults []ScanResult
	var staleOnlyClean []ScanResult
	var cleanCount int

	type RemediationRow struct {
		PkgName string
		Tier    string
		Current string
		Fix     string
	}
	var remediations []RemediationRow

	for _, r := range results {
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
		default:
			noneCount++
		}

		if len(r.Vulnerabilities) > 0 {
			vulnResults = append(vulnResults, r)
			totalVulns += len(r.Vulnerabilities)

			bestFix := ""
			for _, v := range r.Vulnerabilities {
				if v.IsKEV {
					kevCount++
				}
				if v.FixedVersion != "" {
					fixCount++
					if bestFix == "" || v.FixedVersion > bestFix {
						bestFix = v.FixedVersion
					}
				}
			}
			if bestFix != "" {
				remediations = append(remediations, RemediationRow{
					PkgName: r.Pkg.Name,
					Tier:    r.PriorityTier,
					Current: r.Pkg.Version,
					Fix:     ">= " + bestFix,
				})
			}
		} else {
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
		for _, r := range vulnResults {
			badge := "[!]"
			if r.PriorityTier == "CRITICAL-EXPLOITABLE" {
				badge = "[CRITICAL-EXPLOITABLE]"
			} else {
				badge = fmt.Sprintf("[%s]", r.PriorityTier)
			}

			fmt.Printf("\n%s %s (%s)\n", badge, r.Pkg.Name, r.Pkg.Ecosystem)
			fmt.Printf("    Current Version : %s\n", r.Pkg.Version)
			if r.Staleness.LatestVersion != "" {
				statusStr := "ACTIVE"
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
				fmt.Printf("      • %s [CVSS: %.1f | EPSS: %.5f%s]\n", idDisplay, v.CVSS, v.EPSS, kevTag)
				if v.Summary != "" {
					fmt.Printf("        Summary : %s\n", v.Summary)
				}
				if v.FixedVersion != "" {
					fmt.Printf("        Fix     : Upgrade to >= %s\n", v.FixedVersion)
				}
			}
		}
	} else {
		fmt.Println("\n✅ No vulnerabilities found across scanned packages!")
	}

	// ── SECTION 2: ACTIONABLE REMEDIATION TABLE ───────────────────────────────
	if len(remediations) > 0 {
		fmt.Printf("\n\n%s\n", sep)
		fmt.Printf("%45s\n", "RECOMMENDED ACTIONS & FIXES")
		fmt.Println(sep)
		fmt.Printf("  %-25s %-15s %-12s %-15s\n", "PACKAGE", "SEVERITY", "CURRENT", "UPGRADE TO")
		fmt.Println(thinSep)
		for _, rem := range remediations {
			fmt.Printf("  %-25s %-15s %-12s %-15s\n", rem.PkgName, rem.Tier, rem.Current, rem.Fix)
		}
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
	fmt.Println(sep)
}
