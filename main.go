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

// Key returns a unique identifier for a specific package name, version, and ecosystem.
func (p Package) Key() string {
	return p.Name + "@" + p.Version + "@" + p.Ecosystem
}

// StalenessKey returns a unique identifier for a package name and ecosystem on an upstream registry.
func (p Package) StalenessKey() string {
	return p.Name + "@" + p.Ecosystem
}

const (
	maxOSVConcurrency       = 24
	maxStalenessConcurrency = 24
)

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

	// 2. Concurrently check staleness, fetch CISA KEV catalog, and batch-query OSV
	stalenessSem := make(chan struct{}, maxStalenessConcurrency)
	stalenessMap := make(map[string]StalenessResult)
	stalenessQueued := make(map[string]bool)
	var stalenessMu sync.Mutex
	var stalenessWg sync.WaitGroup

	for _, pkg := range packages {
		sKey := pkg.StalenessKey()
		if stalenessQueued[sKey] {
			continue
		}
		stalenessQueued[sKey] = true

		stalenessWg.Add(1)
		go func(p Package, key string) {
			defer stalenessWg.Done()
			stalenessSem <- struct{}{}
			st, err := CheckStaleness(p)
			<-stalenessSem
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: staleness check failed for %s: %v\n", p.Name, err)
			}
			stalenessMu.Lock()
			stalenessMap[key] = st
			stalenessMu.Unlock()
		}(pkg, sKey)
	}

	// Pre-fetch CISA KEV catalog in background while OSV queries run
	var kevCatalog map[string]KEVEntry
	var kevWg sync.WaitGroup
	kevWg.Add(1)
	go func() {
		defer kevWg.Done()
		var err error
		kevCatalog, err = FetchKEVCatalog()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: CISA KEV catalog fetch failed: %v\n", err)
		}
	}()

	// 3. Fast two-phase OSV query: batch check all packages first, then fetch details only for vulnerable packages
	pkgVulns, err := QueryOSVBatch(packages)
	if err != nil {
		// Fallback to individual concurrent queries if batch endpoint fails
		osvSem := make(chan struct{}, maxOSVConcurrency)
		pkgVulns = make(map[string][]Vulnerability)
		var osvMu sync.Mutex
		var osvWg sync.WaitGroup

		for _, pkg := range packages {
			osvWg.Add(1)
			go func(p Package) {
				defer osvWg.Done()
				osvSem <- struct{}{}
				vulns, err := QueryOSV(p)
				<-osvSem
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: OSV failed for %s: %v\n", p.Name, err)
					return
				}
				osvMu.Lock()
				pkgVulns[p.Key()] = vulns
				osvMu.Unlock()
			}(pkg)
		}
		osvWg.Wait()
	}

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

	// Wait for background KEV catalog load
	kevWg.Wait()

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

	// 5. Concurrently query NVD fallback (for CVEs lacking CVSS) and FIRST EPSS batch scores
	var epssScores map[string]float64
	var epssWg sync.WaitGroup
	epssWg.Add(1)
	go func() {
		defer epssWg.Done()
		var epssErr error
		epssScores, epssErr = QueryEPSS(allCVEIDs)
		if epssErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: EPSS query failed: %v\n", epssErr)
		}
	}()

	nvdScores := make(map[string]float64)
	nvdQueued := make(map[string]bool)
	var nvdMu sync.Mutex
	var nvdWg sync.WaitGroup
	nvdSem := make(chan struct{}, 5)

	for _, vulns := range pkgVulns {
		for _, v := range vulns {
			if v.CVSS == 0 && strings.HasPrefix(v.CVEID, "CVE-") && !nvdQueued[v.CVEID] {
				nvdQueued[v.CVEID] = true
				nvdWg.Add(1)
				go func(id string) {
					defer nvdWg.Done()
					nvdSem <- struct{}{}
					score, err := QueryNVD(id)
					<-nvdSem
					if err == nil && score > 0 {
						nvdMu.Lock()
						nvdScores[id] = score
						nvdMu.Unlock()
					}
				}(v.CVEID)
			}
		}
	}
	nvdWg.Wait()
	SaveNVDCache()
	epssWg.Wait()

	// Assign fallback NVD CVSS and EPSS scores to vulnerabilities
	for pkgName, vulns := range pkgVulns {
		for i, v := range vulns {
			if v.CVSS == 0 {
				if score, ok := nvdScores[v.CVEID]; ok {
					pkgVulns[pkgName][i].CVSS = score
				}
			}
			if score, ok := epssScores[v.CVEID]; ok {
				pkgVulns[pkgName][i].EPSS = score
			}
		}
	}

	// Wait for concurrent staleness checks to complete and persist cache
	stalenessWg.Wait()
	SaveStalenessCache()

	// 7. Build scan results
	var results []ScanResult
	for _, pkg := range packages {
		vulns := pkgVulns[pkg.Key()]

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
			Staleness:       stalenessMap[pkg.StalenessKey()],
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
