package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	osvURL      = "https://api.osv.dev/v1/query"
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	},
}

type Vulnerability struct {
	CVEID         string
	Summary       string
	CVSS          float64
	ID            string
	EPSS          float64
	FixedVersion  string
	IsKEV         bool
	KEVRansomware bool
}

// osvQuery is what we POST to the OSV API
type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// osvResponse is what OSV sends back
type osvResponse struct {
	Vulns []osvVulnerability `json:"vulns"`
}
type osvVulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
				Limit        string `json:"limit"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// fixedRelease selects the closing fixed event of the interval containing the
// scanned version, only for the package actually being queried. Other branches,
// packages, commit hashes and unsupported version orderings are never guessed.
func fixedRelease(v osvVulnerability, pkg Package) string {
	var best string
	for _, aff := range v.Affected {
		if aff.Package.Name != pkg.Name || aff.Package.Ecosystem != pkg.Ecosystem {
			continue
		}
		for _, r := range aff.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			inRange := false
			for _, ev := range r.Events {
				if ev.Introduced != "" {
					cmp, ok := compareVersions(pkg.Version, ev.Introduced, pkg.Ecosystem)
					inRange = ev.Introduced == "0" || (ok && cmp >= 0)
				}
				if ev.Fixed != "" {
					cmp, ok := compareVersions(pkg.Version, ev.Fixed, pkg.Ecosystem)
					if inRange && ok && cmp < 0 {
						if best == "" {
							best = ev.Fixed
						} else if c, comparable := compareVersions(ev.Fixed, best, pkg.Ecosystem); comparable && c < 0 {
							best = ev.Fixed
						}
					}
					inRange = false
				}
				if ev.LastAffected != "" || ev.Limit != "" {
					inRange = false
				}
			}
		}
	}
	return best
}

type osvBatchQuery struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []osvResponse `json:"results"`
}

func parseVulns(res osvResponse, pkg Package) []Vulnerability {
	if len(res.Vulns) == 0 {
		return nil
	}

	var vulns []Vulnerability
	for _, v := range res.Vulns {
		summary := v.Summary
		if summary == "" && v.Details != "" {
			firstLine := strings.Split(v.Details, "\n")[0]
			summary = strings.TrimSpace(firstLine)
		}

		fixedVersion := fixedRelease(v, pkg)

		vuln := Vulnerability{
			ID:           v.ID,
			Summary:      summary,
			FixedVersion: fixedVersion,
		}

		// Prefer a CVE alias over the OSV/GHSA ID
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				vuln.CVEID = alias
				break
			}
		}
		// Fall back to the OSV ID if no CVE alias exists
		if vuln.CVEID == "" {
			vuln.CVEID = v.ID
		}

		// Extract CVSS score from the severity array
		for _, sev := range v.Severity {
			if strings.Contains(sev.Type, "CVSS") {
				if score := parseCVSSVector(sev.Score); score > vuln.CVSS {
					vuln.CVSS = score
				}
			}
		}

		vulns = append(vulns, vuln)
	}

	// Deduplicate advisories that share the same CVE ID (e.g., GHSA + PYSEC for the same CVE),
	// merging CVSS, FixedVersion, and Summary so the richest metadata is preserved.
	var deduped []Vulnerability
	idxByCVE := make(map[string]int)
	for _, v := range vulns {
		if existingIdx, exists := idxByCVE[v.CVEID]; exists {
			ex := &deduped[existingIdx]
			if v.CVSS > ex.CVSS {
				ex.CVSS = v.CVSS
			}
			if ex.FixedVersion == "" && v.FixedVersion != "" {
				ex.FixedVersion = v.FixedVersion
			}
			if ex.Summary == "" && v.Summary != "" {
				ex.Summary = v.Summary
			}
			continue
		}
		idxByCVE[v.CVEID] = len(deduped)
		deduped = append(deduped, v)
	}

	return deduped
}

func QueryOSVBatch(packages []Package) (map[string][]Vulnerability, error) {
	resultMap := make(map[string][]Vulnerability)
	if len(packages) == 0 {
		return resultMap, nil
	}

	const maxBatchSize = 1000
	for i := 0; i < len(packages); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(packages) {
			end = len(packages)
		}
		chunk := packages[i:end]

		var bq osvBatchQuery
		for _, pkg := range chunk {
			if err := validateQueryVersion(pkg); err != nil {
				return nil, err
			}
			version := pkg.Version
			var q osvQuery
			q.Package.Name = pkg.Name
			q.Package.Ecosystem = pkg.Ecosystem
			q.Version = version
			bq.Queries = append(bq.Queries, q)
		}

		body, err := json.Marshal(bq)
		if err != nil {
			return nil, fmt.Errorf("osv batch marshal: %w", err)
		}

		resp, err := httpClient.Post(osvBatchURL, "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("osv batch request failed: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("osv batch returned status %d", resp.StatusCode)
		}

		var batchResp osvBatchResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&batchResp)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("osv batch decode: %w", decodeErr)
		}

		if len(batchResp.Results) != len(chunk) {
			return nil, fmt.Errorf("osv batch returned %d results for %d queries", len(batchResp.Results), len(chunk))
		}

		// Only packages with >= 1 vulnerability in the batch response need a full detail query
		var vulnPkgs []Package
		for idx, item := range batchResp.Results {
			if len(item.Vulns) > 0 {
				vulnPkgs = append(vulnPkgs, chunk[idx])
			} else {
				resultMap[chunk[idx].Key()] = nil
			}
		}

		if len(vulnPkgs) > 0 {
			sem := make(chan struct{}, 20)
			var mu sync.Mutex
			var detailErr error
			var wg sync.WaitGroup
			for _, vp := range vulnPkgs {
				wg.Add(1)
				go func(p Package) {
					defer wg.Done()
					sem <- struct{}{}
					vulns, err := QueryOSV(p)
					<-sem
					mu.Lock()
					if err != nil {
						detailErr = err
					} else {
						resultMap[p.Key()] = vulns
					}
					mu.Unlock()
				}(vp)
			}
			wg.Wait()
			if detailErr != nil {
				return nil, fmt.Errorf("osv detail query: %w", detailErr)
			}
		}
	}

	return resultMap, nil
}

func QueryOSV(pkg Package) ([]Vulnerability, error) {
	if err := validateQueryVersion(pkg); err != nil {
		return nil, err
	}
	version := pkg.Version

	// Build the request body
	var q osvQuery
	q.Package.Name = pkg.Name
	q.Package.Ecosystem = pkg.Ecosystem
	q.Version = version

	body, err := json.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("osv marshal: %w", err)
	}

	// POST to OSV
	resp, err := httpClient.Post(osvURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv request failed for %s: %w", pkg.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv returned %d for %s", resp.StatusCode, pkg.Name)
	}

	// Decode the response
	var result osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("osv decode: %w", err)
	}

	return parseVulns(result, pkg), nil
}

// parseCVSSVector extracts or calculates the base score from a CVSS vector string locally.
// If OSV returns a numeric string, it is parsed directly.
// If it is a CVSS v3.0 / v3.1 vector string, the base score is calculated instantly
// using the official FIRST CVSS v3 specification formula (0ms, no network calls).
func parseCVSSVector(vector string) float64 {
	// If it is already a plain number, parse directly
	if f, err := strconv.ParseFloat(vector, 64); err == nil {
		return f
	}

	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0
	}

	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	avMap := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acMap := map[string]float64{"L": 0.77, "H": 0.44}
	uiMap := map[string]float64{"N": 0.85, "R": 0.62}
	cMap := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	iMap := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	aMap := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}

	av, ok1 := avMap[metrics["AV"]]
	ac, ok2 := acMap[metrics["AC"]]
	ui, ok3 := uiMap[metrics["UI"]]
	c, ok4 := cMap[metrics["C"]]
	i, ok5 := iMap[metrics["I"]]
	a, ok6 := aMap[metrics["A"]]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return 0
	}

	scopeChanged := metrics["S"] == "C"

	var pr float64
	switch metrics["PR"] {
	case "N":
		pr = 0.85
	case "L":
		if scopeChanged {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if scopeChanged {
			pr = 0.50
		} else {
			pr = 0.27
		}
	default:
		return 0
	}

	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui

	var baseScore float64
	if scopeChanged {
		baseScore = math.Min(1.08*(impact+exploitability), 10.0)
	} else {
		baseScore = math.Min(impact+exploitability, 10.0)
	}

	// CVSS v3 Roundup
	return math.Ceil(baseScore*10.0) / 10.0
}
