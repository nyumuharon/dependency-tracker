package main

import (
	"fmt"
	"strings"
)

type ScanResult struct {
	Pkg             Package
	Vulnerabilities []Vulnerability
	PriorityTier    string
	Staleness       StalenessResult
}

func PrintReport(results []ScanResult) {
	sep := strings.Repeat("=", 72)
	fmt.Println(sep)
	fmt.Printf("%30s\n", "DEPENDENCY RISK TRACKER — SCAN REPORT")
	fmt.Println(sep)

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	noneCount := 0
	staleCount := 0
	totalVulns := 0

	for _, r := range results {
		fmt.Printf("\n[+] %s (%s)\n", r.Pkg.Name, r.Pkg.Ecosystem)
		fmt.Printf("    Current Version : %s\n", r.Pkg.Version)

		if r.Staleness.LatestVersion != "" {
			fmt.Printf("    Latest Version  : %s\n", r.Staleness.LatestVersion)
		}

		status := "ACTIVE"
		if r.Staleness.IsStale {
			status = "STALE"
			staleCount++
		}
		if r.Staleness.LatestVersion == "" {
			status = "UNKNOWN"
		}
		fmt.Printf("    Status          : %s\n", status)
		fmt.Printf("    Priority Tier   : %s\n", r.PriorityTier)

		if len(r.Vulnerabilities) == 0 {
			fmt.Printf("    Vulnerabilities : None\n")
		} else {
			fmt.Printf("    Vulnerabilities (%d):\n", len(r.Vulnerabilities))
			for _, v := range r.Vulnerabilities {
				idDisplay := v.CVEID
				if v.ID != "" && v.ID != v.CVEID {
					idDisplay = fmt.Sprintf("%s (%s)", v.CVEID, v.ID)
				}
				fmt.Printf("      - %s [CVSS: %.1f | EPSS: %.5f]\n", idDisplay, v.CVSS, v.EPSS)
				if v.Summary != "" {
					fmt.Printf("        Summary : %s\n", v.Summary)
				}
			}
			totalVulns += len(r.Vulnerabilities)
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
	}

	// Track unique ecosystems
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

	fmt.Printf("\n%s\n", sep)
	fmt.Printf("%30s\n", "SUMMARY")
	fmt.Printf("%s\n", sep)
	fmt.Printf("Total Packages Scanned : %d\n", len(results))
	if len(ecoList) > 0 {
		fmt.Printf("Ecosystems Scanned     : %s (%d)\n", strings.Join(ecoList, ", "), len(ecoList))
	}
	fmt.Printf("Total Vulnerabilities  : %d\n", totalVulns)
	fmt.Printf("Stale Packages         : %d\n", staleCount)
	fmt.Printf("\nPriority Tier Breakdown:\n")
	fmt.Printf("  CRITICAL-EXPLOITABLE : %d\n", criticalCount)
	fmt.Printf("  HIGH                 : %d\n", highCount)
	fmt.Printf("  MEDIUM               : %d\n", mediumCount)
	fmt.Printf("  LOW                  : %d\n", lowCount)
	fmt.Printf("  NONE                 : %d\n", noneCount)
	fmt.Printf("%s\n", sep)
}
