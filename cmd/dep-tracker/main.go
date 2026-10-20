package main

import (
	"encoding/json"
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

const appVersion = "1.0.0"

// cliOptions holds the command-line flags accepted by dep-tracker.
type cliOptions struct {
	sbomPath  string
	sarifPath string
	jsonOut   bool
	staleOnly bool
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Dependency Risk Tracker v"+appVersion)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage: dep-tracker scan <path> [options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "  --sbom <file>    Write the CycloneDX v1.4 SBOM to <file> (default: sbom.json)")
	fmt.Fprintln(os.Stderr, "  --sarif <file>   Write the OASIS SARIF v2.1.0 report to <file> (default: results.sarif)")
	fmt.Fprintln(os.Stderr, "  --json           Print the full risk report as JSON instead of the text report")
	fmt.Fprintln(os.Stderr, "  --stale-only     Only show packages with no release in over two years")
	fmt.Fprintln(os.Stderr, "  --version        Print the version and exit")
	fmt.Fprintln(os.Stderr, "  -h, --help       Show this help and exit")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  dep-tracker scan .                        # Scan entire project/repo recursively")
	fmt.Fprintln(os.Stderr, "  dep-tracker scan package-lock.json        # Scan a specific manifest or lockfile")
	fmt.Fprintln(os.Stderr, "  dep-tracker scan . --sbom out/sbom.json   # Choose where the SBOM is written")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Discovery layers: manifests/lockfiles -> installed environments -> source-code imports")
}

// parseArgs parses "scan <path> [options]" (the "scan" keyword is optional).
func parseArgs(args []string) (cliOptions, string, error) {
	opts := cliOptions{sbomPath: "sbom.json", sarifPath: "results.sarif"}
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help" || a == "help":
			printUsage()
			os.Exit(0)
		case a == "--version" || a == "-v":
			fmt.Println("dep-tracker " + appVersion)
			os.Exit(0)
		case a == "--json":
			opts.jsonOut = true
		case a == "--stale-only":
			opts.staleOnly = true
		case a == "--sbom" || a == "--sarif":
			if i+1 >= len(args) {
				return opts, "", fmt.Errorf("%s requires a file path", a)
			}
			i++
			if a == "--sbom" {
				opts.sbomPath = args[i]
			} else {
				opts.sarifPath = args[i]
			}
		case strings.HasPrefix(a, "--sbom="):
			opts.sbomPath = strings.TrimPrefix(a, "--sbom=")
		case strings.HasPrefix(a, "--sarif="):
			opts.sarifPath = strings.TrimPrefix(a, "--sarif=")
		case strings.HasPrefix(a, "-"):
			return opts, "", fmt.Errorf("unknown option %q", a)
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) > 0 && positional[0] == "scan" {
		positional = positional[1:]
	}
	if len(positional) != 1 {
		return opts, "", fmt.Errorf("expected exactly one path to scan")
	}
	return opts, positional[0], nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	opts, targetPath, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		printUsage()
		os.Exit(1)
	}

	// In --json mode, progress messages go to stderr so stdout stays valid JSON.
	info := os.Stdout
	if opts.jsonOut {
		info = os.Stderr
	}

	// 1. Parse manifest or project directory
	packages, err := ParsePath(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(info, "Total unique dependencies to analyze: %d\n\n", len(packages))

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

	// 8. Print report (optionally filtered to stale packages, optionally as JSON)
	shown := results
	if opts.staleOnly {
		shown = nil
		for _, r := range results {
			if r.Staleness.IsStale {
				shown = append(shown, r)
			}
		}
	}
	if opts.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(shown); err != nil {
			fmt.Fprintf(os.Stderr, "Error: JSON encoding failed: %v\n", err)
		}
	} else {
		PrintReport(shown)
	}

	// 9. Generate SBOM and SARIF reports (always cover the full result set)
	if err := GenerateSBOM(results, opts.sbomPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: SBOM generation failed: %v\n", err)
	} else {
		fmt.Fprintf(info, "\nSBOM saved to %s\n", opts.sbomPath)
	}

	if err := GenerateSARIF(results, opts.sarifPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: SARIF generation failed: %v\n", err)
	} else {
		fmt.Fprintf(info, "SARIF report saved to %s\n", opts.sarifPath)
	}

	// 10. Exit with code 1 if any CRITICAL-EXPLOITABLE found
	for _, r := range results {
		if r.PriorityTier == "CRITICAL-EXPLOITABLE" {
			os.Exit(1)
		}
	}
}
