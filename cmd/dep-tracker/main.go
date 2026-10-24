package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type Package struct {
	Name          string
	Version       string
	Ecosystem     string
	ManifestPath  string
	ProjectPath   string
	VersionSource string
}

// Key returns a unique identifier for a specific package name, version, and ecosystem.
func (p Package) Key() string {
	return p.Name + "@" + p.Version + "@" + p.Ecosystem + "@" + p.ProjectPath
}

// StalenessKey returns a unique identifier for a package name and ecosystem on an upstream registry.
func (p Package) StalenessKey() string {
	return p.Name + "@" + p.Ecosystem
}

const (
	maxOSVConcurrency       = 24
	maxStalenessConcurrency = 24
)

const appVersion = "1.0.5"

// cliOptions holds the command-line flags accepted by dep-tracker.
type cliOptions struct {
	sbomPath  string
	sarifPath string
	jsonOut   bool
	staleOnly bool
}

const helpText = `Dependency Risk Tracker v%[1]s
Software composition analysis: finds your project's dependencies, checks them
for known vulnerabilities, real-world exploitation and abandonment, and tells
you what to fix first.

USAGE
  dep-tracker <command> [arguments] [options]

COMMANDS
  scan <path>      Scan a project directory (recursively) or a single manifest,
                   lockfile or environment file, print a prioritised risk
                   report, and write an SBOM and a SARIF report.
  update           Check GitHub Releases and upgrade dep-tracker in-place.
  help             Show this help.
  version          Print the version number.

SCAN OPTIONS
  --sbom <file>    Where to write the CycloneDX v1.4 SBOM.
                   Default: sbom.json in the current directory.
  --sarif <file>   Where to write the OASIS SARIF v2.1.0 report
                   (for GitHub Code Scanning / CI). Default: results.sarif
  --json           Print the full risk report as JSON on stdout instead of
                   the text report (progress messages go to stderr).
  --stale-only     Only show packages with no upstream release in over two
                   years (730 days), plus incomplete results that need attention.
                   The SBOM/SARIF still cover everything.
  -h, --help       Show this help.
  -v, --version    Print the version number.

HOW DEPENDENCIES ARE FOUND
  Layer 1  Manifests & lockfiles: npm/yarn/pnpm, PyPI (requirements, poetry,
           Pipfile, uv, pyproject), Maven/Gradle, NuGet, Cargo, Go modules,
           Composer, RubyGems, Conan/vcpkg/CMake, Pub, Hex, SwiftPM.
  Layer 2  Installed environments: venv/.venv, node_modules,
           obj/project.assets.json, vendor/composer/installed.json,
           vendor/modules.txt, vendor/bundle, vcpkg_installed, .dart_tool.
  Layer 3  Source-code imports (used when no manifest exists): Python,
           JS/TS, Go, Rust, C/C++, Java/Kotlin, C#, PHP, Ruby, Dart.

PRIORITY TIERS
  CRITICAL-EXPLOITABLE  In the CISA KEV catalog, or CVSS >= 7.0 and EPSS >= 0.20
  HIGH                  CVSS >= 7.0
  MEDIUM                CVSS 4.0 - 6.9
  LOW                   CVSS below 4.0
  NONE                  No known vulnerabilities

EXIT CODES
  0  Scan finished; no CRITICAL-EXPLOITABLE packages found.
  1  CRITICAL-EXPLOITABLE package found, or invalid arguments/path.
  2  Scan incomplete: unresolved versions, failed checks, or failed report export.

EXAMPLES
  dep-tracker scan .                            Scan the current project
  dep-tracker scan ~/code/my-app                Scan another directory
  dep-tracker scan package-lock.json            Scan one lockfile
  dep-tracker scan . --sbom reports/sbom.json --sarif reports/app.sarif
  dep-tracker scan . --json > report.json       Machine-readable output
  dep-tracker scan . --stale-only               List abandoned packages
`

// printUsage writes the full help text to w.
func printUsage(w io.Writer) {
	fmt.Fprintf(w, helpText, appVersion)
}

// parseArgs parses "<command> [arguments] [options]".
// The "scan" keyword is optional: "dep-tracker ." also scans.
func parseArgs(args []string) (cliOptions, string, error) {
	opts := cliOptions{sbomPath: "sbom.json", sarifPath: "results.sarif"}
	if len(args) > 0 {
		switch args[0] {
		case "help":
			printUsage(os.Stdout)
			os.Exit(0)
		case "version":
			fmt.Println("dep-tracker " + appVersion)
			os.Exit(0)
		case "scan":
			args = args[1:]
		}
	}
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			printUsage(os.Stdout)
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
			return opts, "", fmt.Errorf("unknown option %q (run 'dep-tracker help')", a)
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) != 1 {
		return opts, "", fmt.Errorf("expected exactly one path to scan (run 'dep-tracker help')")
	}
	return opts, positional[0], nil
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return 1
	}

	if args[0] == "update" {
		if err := runUpdate(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		return 0
	}

	opts, targetPath, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
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
		return 1
	}
	scanIncomplete := false
	var intelligenceErrors []string
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
				st.CheckError = err.Error()
				fmt.Fprintf(os.Stderr, "Warning: staleness check failed for %s: %v\n", p.Name, err)
			}
			stalenessMu.Lock()
			stalenessMap[key] = st
			stalenessMu.Unlock()
		}(pkg, sKey)
	}

	// Pre-fetch CISA KEV catalog in background while OSV queries run
	var kevCatalog map[string]KEVEntry
	var kevErr error
	var kevWg sync.WaitGroup
	kevWg.Add(1)
	go func() {
		defer kevWg.Done()
		kevCatalog, kevErr = FetchKEVCatalog()
		if kevErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: CISA KEV catalog fetch failed: %v\n", kevErr)
		}
	}()

	packageErrors := make(map[string]string)
	queryPackages := make([]Package, 0, len(packages))
	for _, pkg := range packages {
		if err := validateQueryVersion(pkg); err != nil {
			packageErrors[pkg.Key()] = err.Error()
		} else {
			queryPackages = append(queryPackages, pkg)
		}
	}

	// 3. Fast two-phase OSV query: batch check all packages first, then fetch details only for vulnerable packages
	pkgVulns, err := QueryOSVBatch(queryPackages)
	if err != nil {
		// Fallback to individual concurrent queries if batch endpoint fails
		osvSem := make(chan struct{}, maxOSVConcurrency)
		pkgVulns = make(map[string][]Vulnerability)
		var osvMu sync.Mutex
		var osvWg sync.WaitGroup

		for _, pkg := range queryPackages {
			osvWg.Add(1)
			go func(p Package) {
				defer osvWg.Done()
				osvSem <- struct{}{}
				vulns, err := QueryOSV(p)
				<-osvSem
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: OSV failed for %s: %v\n", p.Name, err)
					osvMu.Lock()
					packageErrors[p.Key()] = err.Error()
					osvMu.Unlock()
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
			if strings.HasPrefix(v.CVEID, "CVE-") && !cveSeen[v.CVEID] {
				cveSeen[v.CVEID] = true
				allCVEIDs = append(allCVEIDs, v.CVEID)
			}
		}
	}

	// Wait for background KEV catalog load
	kevWg.Wait()
	if kevErr != nil {
		intelligenceErrors = append(intelligenceErrors, kevErr.Error())
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

	// 5. Concurrently query NVD fallback (for CVEs lacking CVSS) and FIRST EPSS batch scores
	var epssScores map[string]float64
	var epssErr error
	var epssWg sync.WaitGroup
	epssWg.Add(1)
	go func() {
		defer epssWg.Done()
		epssScores, epssErr = QueryEPSS(allCVEIDs)
		if epssErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: EPSS query failed: %v\n", epssErr)
		}
	}()

	nvdScores := make(map[string]float64)
	nvdErrors := make(map[string]string)
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
					nvdMu.Lock()
					if err != nil {
						nvdErrors[id] = err.Error()
					} else if score > 0 {
						nvdScores[id] = score
					} else {
						nvdErrors[id] = "No severity available for " + id
					}
					nvdMu.Unlock()
				}(v.CVEID)
			}
		}
	}
	nvdWg.Wait()
	SaveNVDCache()
	epssWg.Wait()
	if epssErr != nil {
		intelligenceErrors = append(intelligenceErrors, epssErr.Error())
	}

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
	results := []ScanResult{}
	for _, pkg := range packages {
		vulns := pkgVulns[pkg.Key()]

		tier := ScoreVulnerabilities(vulns)
		checkErrors := append([]string(nil), intelligenceErrors...)
		if msg := packageErrors[pkg.Key()]; msg != "" {
			checkErrors = append(checkErrors, msg)
		}
		for _, v := range vulns {
			if msg := nvdErrors[v.CVEID]; msg != "" {
				checkErrors = append(checkErrors, msg)
			}
			if v.CVSS == 0 {
				checkErrors = append(checkErrors, "Severity unavailable for "+v.CVEID)
			}
		}
		if st := stalenessMap[pkg.StalenessKey()]; st.CheckError != "" {
			checkErrors = append(checkErrors, "Staleness: "+st.CheckError)
		}
		status := "complete"
		if len(checkErrors) > 0 {
			status = "incomplete"
			scanIncomplete = true
			if len(vulns) == 0 {
				tier = "UNKNOWN"
			}
		}

		results = append(results, ScanResult{
			Pkg:             pkg,
			ScanStatus:      status,
			CheckErrors:     checkErrors,
			Vulnerabilities: vulns,
			PriorityTier:    tier,
			Staleness:       stalenessMap[pkg.StalenessKey()],
		})
	}

	// 8. Print report (optionally filtered to stale packages, optionally as JSON)
	shown := results
	if opts.staleOnly {
		shown = []ScanResult{}
		for _, r := range results {
			if r.Staleness.IsStale || r.ScanStatus == "incomplete" {
				shown = append(shown, r)
			}
		}
	}
	if opts.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(shown); err != nil {
			scanIncomplete = true
			fmt.Fprintf(os.Stderr, "Error: JSON encoding failed: %v\n", err)
		}
	} else {
		PrintReport(shown)
	}

	// 9. Generate SBOM and SARIF reports (always cover the full result set)
	if err := GenerateSBOM(results, opts.sbomPath); err != nil {
		scanIncomplete = true
		fmt.Fprintf(os.Stderr, "Warning: SBOM generation failed: %v\n", err)
	} else {
		fmt.Fprintf(info, "\nSBOM saved to %s\n", opts.sbomPath)
	}

	if err := GenerateSARIF(results, opts.sarifPath); err != nil {
		scanIncomplete = true
		fmt.Fprintf(os.Stderr, "Warning: SARIF generation failed: %v\n", err)
	} else {
		fmt.Fprintf(info, "SARIF report saved to %s\n", opts.sarifPath)
	}

	if scanIncomplete {
		fmt.Fprintln(os.Stderr, "Scan incomplete; review check errors and export warnings.")
		return 2
	}

	// 10. Exit with code 1 if any CRITICAL-EXPLOITABLE found
	for _, r := range results {
		if r.PriorityTier == "CRITICAL-EXPLOITABLE" {
			return 1
		}
	}

	return 0
}
