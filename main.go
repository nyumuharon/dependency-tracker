package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

type Package struct {
	Name         string
	Version      string
	Ecosystem    string
	ManifestPath string
}

func main() {
	if len(os.Args) < 3 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "Usage: dep-tracker scan <path>")
		fmt.Fprintln(os.Stderr, "  Examples:")
		fmt.Fprintln(os.Stderr, "    dep-tracker scan .                  # Scan entire project/repo recursively")
		fmt.Fprintln(os.Stderr, "    dep-tracker scan package.json       # Scan specific manifest")
		fmt.Fprintln(os.Stderr, "    dep-tracker scan package-lock.json  # Scan specific lockfile")
		os.Exit(1)
	}

	targetPath := os.Args[2]

	// 1. Parse manifest or project directory
	packages, err := ParsePath(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Total unique dependencies to analyze: %d\n\n", len(packages))

	// 2. Concurrently check staleness for all packages in parallel
	stalenessMap := make(map[string]StalenessResult)
	var stalenessMu sync.Mutex
	var stalenessWg sync.WaitGroup

	for _, pkg := range packages {
		stalenessWg.Add(1)
		go func(p Package) {
			defer stalenessWg.Done()
			st, err := CheckStaleness(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: staleness check failed for %s: %v\n", p.Name, err)
			}
			stalenessMu.Lock()
			stalenessMap[p.Name] = st
			stalenessMu.Unlock()
		}(pkg)
	}

	// 3. Concurrently query OSV for all packages (fetches full vulnerability data, summaries & CVE aliases)
	pkgVulns := make(map[string][]Vulnerability)
	var osvMu sync.Mutex
	var osvWg sync.WaitGroup

	for _, pkg := range packages {
		osvWg.Add(1)
		go func(p Package) {
			defer osvWg.Done()
			vulns, err := QueryOSV(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: OSV failed for %s: %v\n", p.Name, err)
				return
			}
			osvMu.Lock()
			pkgVulns[p.Name] = vulns
			osvMu.Unlock()
		}(pkg)
	}
	osvWg.Wait()

	// 4. Collect unique CVE IDs
	var allCVEIDs []string
	cveSeen := make(map[string]bool)

	for _, vulns := range pkgVulns {
		for _, v := range vulns {
			if v.CVEID != "" && !cveSeen[v.CVEID] {
				cveSeen[v.CVEID] = true
				allCVEIDs = append(allCVEIDs, v.CVEID)
			}
		}
	}

	// 4. Query CISA KEV catalog for known actively exploited vulnerabilities
	var kevCatalog map[string]KEVEntry
	if len(allCVEIDs) > 0 {
		var err error
		kevCatalog, err = FetchKEVCatalog()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: CISA KEV catalog fetch failed: %v\n", err)
		}
	}

	// Match CISA KEV status to discovered vulnerabilities
	for pkgName, vulns := range pkgVulns {
		for i, v := range vulns {
			if entry, ok := kevCatalog[v.CVEID]; ok {
				pkgVulns[pkgName][i].IsKEV = true
				if strings.EqualFold(entry.KnownRansomwareCampaignUse, "Known") {
					pkgVulns[pkgName][i].KEVRansomware = true
				}
			}
		}
	}

	// 5. Query NVD only as a fallback for CVEs that lacked a CVSS vector in OSV
	nvdScores := make(map[string]float64)
	for _, vulns := range pkgVulns {
		for _, v := range vulns {
			if v.CVSS == 0 && strings.HasPrefix(v.CVEID, "CVE-") && nvdScores[v.CVEID] == 0 {
				if score, err := QueryNVD(v.CVEID); err == nil && score > 0 {
					nvdScores[v.CVEID] = score
				}
			}
		}
	}

	// Assign fallback NVD CVSS scores to vulnerabilities that needed it
	for pkgName, vulns := range pkgVulns {
		for i, v := range vulns {
			if v.CVSS == 0 {
				if score, ok := nvdScores[v.CVEID]; ok {
					pkgVulns[pkgName][i].CVSS = score
				}
			}
		}
	}

	// 6. Batch EPSS query
	epssScores, err := QueryEPSS(allCVEIDs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: EPSS query failed: %v\n", err)
	}

	// Attach EPSS scores to vulnerabilities
	for pkgName, vulns := range pkgVulns {
		for i, v := range vulns {
			if score, ok := epssScores[v.CVEID]; ok {
				pkgVulns[pkgName][i].EPSS = score
			}
		}
	}

	// Wait for concurrent staleness checks to complete
	stalenessWg.Wait()

	// 7. Build scan results
	var results []ScanResult
	for _, pkg := range packages {
		vulns := pkgVulns[pkg.Name]

		// Find highest CVSS and EPSS across all vulns for this package, and check for active KEV
		var maxCVSS, maxEPSS float64
		hasKEV := false
		for _, v := range vulns {
			if v.CVSS > maxCVSS {
				maxCVSS = v.CVSS
			}
			if v.EPSS > maxEPSS {
				maxEPSS = v.EPSS
			}
			if v.IsKEV {
				hasKEV = true
			}
		}

		tier := Score(maxCVSS, maxEPSS, len(vulns) > 0, hasKEV)

		results = append(results, ScanResult{
			Pkg:             pkg,
			Vulnerabilities: vulns,
			PriorityTier:    tier,
			Staleness:       stalenessMap[pkg.Name],
		})
	}

	// 8. Print report
	PrintReport(results)

	// 9. Generate SBOM and SARIF reports
	if err := GenerateSBOM(results, "sbom.json"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: SBOM generation failed: %v\n", err)
	} else {
		fmt.Println("\nSBOM saved to sbom.json")
	}

	if err := GenerateSARIF(results, "results.sarif"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: SARIF generation failed: %v\n", err)
	} else {
		fmt.Println("SARIF report saved to results.sarif")
	}

	// 10. Exit with code 1 if any CRITICAL-EXPLOITABLE found
	for _, r := range results {
		if r.PriorityTier == "CRITICAL-EXPLOITABLE" {
			os.Exit(1)
		}
	}
}
