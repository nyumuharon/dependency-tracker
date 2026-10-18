package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

type Package struct {
	Name      string
	Version   string
	Ecosystem string
}

func main() {
	if len(os.Args) < 3 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "Usage: dep-tracker scan <manifest-file>")
		fmt.Fprintln(os.Stderr, "  Example: dep-tracker scan package.json")
		os.Exit(1)
	}

	manifestPath := os.Args[2]

	// 1. Parse manifest
	fmt.Printf("Scanning %s...\n", manifestPath)
	packages, err := ParseManifest(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing manifest: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d dependencies\n\n", len(packages))

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

	// 4. Query NVD only as a fallback for CVEs that lacked a CVSS vector in OSV
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

	// 5. Batch EPSS query
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

	// 6. Build scan results
	var results []ScanResult
	for _, pkg := range packages {
		vulns := pkgVulns[pkg.Name]

		// Find highest CVSS and EPSS across all vulns for this package
		var maxCVSS, maxEPSS float64
		for _, v := range vulns {
			if v.CVSS > maxCVSS {
				maxCVSS = v.CVSS
			}
			if v.EPSS > maxEPSS {
				maxEPSS = v.EPSS
			}
		}

		tier := Score(maxCVSS, maxEPSS, len(vulns) > 0)

		results = append(results, ScanResult{
			Pkg:             pkg,
			Vulnerabilities: vulns,
			PriorityTier:    tier,
			Staleness:       stalenessMap[pkg.Name],
		})
	}

	// 7. Print report
	PrintReport(results)

	// 8. Generate SBOM
	if err := GenerateSBOM(results, "sbom.json"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: SBOM generation failed: %v\n", err)
	} else {
		fmt.Println("\nSBOM saved to sbom.json")
	}

	// 9. Exit with code 1 if any CRITICAL-EXPLOITABLE found
	for _, r := range results {
		if r.PriorityTier == "CRITICAL-EXPLOITABLE" {
			os.Exit(1)
		}
	}
}
