package intel

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
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Withdrawn string   `json:"withdrawn"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity any `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		DatabaseSpecific struct {
			// RustSec marks notices that are not vulnerabilities, such as
			// "unmaintained", as informational.
			Informational string `json:"informational"`
		} `json:"database_specific"`
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
					inRange = atOrAfterIntroduced(pkg.Version, ev.Introduced, pkg.Ecosystem)
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

// atOrAfterIntroduced reports whether version is at or after an introduced
// event. A qualifier such as "2.0-beta9" orders versions only within one
// numeric release, so when the qualified form cannot be ordered, a version
// whose numeric release is strictly greater is still known to be later.
// Versions sharing the numeric release are left undecided.
func atOrAfterIntroduced(version, introduced, ecosystem string) bool {
	if introduced == "0" {
		return true
	}
	if cmp, ok := compareVersions(version, introduced, ecosystem); ok {
		return cmp >= 0
	}
	i := strings.IndexAny(introduced, "-+")
	if i <= 0 {
		return false
	}
	cmp, ok := compareVersions(version, introduced[:i], ecosystem)
	return ok && cmp > 0
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
	var vulnIDs [][]string // each advisory's ID and aliases, for merging
	for _, v := range res.Vulns {
		if v.Withdrawn != "" || isInformationalNotice(v, pkg) {
			continue
		}
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

		if label, ok := v.DatabaseSpecific.Severity.(string); ok {
			vuln.Severity = normalizeSeverityLabel(label)
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
		vulnIDs = append(vulnIDs, append([]string{v.ID, vuln.CVEID}, v.Aliases...))
	}

	// Merge advisories that describe the same vulnerability: they share a CVE
	// or one lists the other as an alias (GHSA + PYSEC, RUSTSEC + GHSA). The
	// richest metadata is kept.
	var deduped []Vulnerability
	idxByID := make(map[string]int)
	for i, v := range vulns {
		existingIdx, exists := -1, false
		for _, id := range vulnIDs[i] {
			if idx, ok := idxByID[id]; ok {
				existingIdx, exists = idx, true
				break
			}
		}
		if !exists {
			existingIdx = len(deduped)
			deduped = append(deduped, v)
		}
		for _, id := range vulnIDs[i] {
			if _, ok := idxByID[id]; !ok {
				idxByID[id] = existingIdx
			}
		}
		if exists {
			ex := &deduped[existingIdx]
			if !strings.HasPrefix(ex.CVEID, "CVE-") && strings.HasPrefix(v.CVEID, "CVE-") {
				ex.CVEID = v.CVEID
			}
			if v.CVSS > ex.CVSS {
				ex.CVSS = v.CVSS
			}
			if severityLabelScore(v.Severity) > severityLabelScore(ex.Severity) {
				ex.Severity = v.Severity
			}
			if ex.FixedVersion == "" && v.FixedVersion != "" {
				ex.FixedVersion = v.FixedVersion
			}
			if ex.Summary == "" && v.Summary != "" {
				ex.Summary = v.Summary
			}
		}
	}

	return deduped
}

// isInformationalNotice reports RustSec notices that are not vulnerabilities:
// "unmaintained" crates and general notices. "unsound" notices describe
// memory-safety problems and stay.
func isInformationalNotice(v osvVulnerability, pkg Package) bool {
	for _, aff := range v.Affected {
		if aff.Package.Name != pkg.Name || aff.Package.Ecosystem != pkg.Ecosystem {
			continue
		}
		switch strings.ToLower(aff.DatabaseSpecific.Informational) {
		case "unmaintained", "notice":
			return true
		}
	}
	return false
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

		// osvBatchQuery contains only strings and slices of structs.
		body, _ := json.Marshal(bq)

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

	// osvQuery contains only strings.
	body, _ := json.Marshal(q)

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
// If it is a CVSS v3.0 / v3.1 / v4.0 vector string, the score is calculated instantly
// using the official FIRST CVSS v3 and v4 specifications (0ms, no network calls).
func parseCVSSVector(vector string) float64 {
	// If it is already a plain number, parse directly
	if f, err := strconv.ParseFloat(vector, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 && f <= 10 {
		return f
	}

	if strings.HasPrefix(vector, "CVSS:4.0/") {
		return parseCVSSv4Vector(vector)
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

	if metrics["S"] != "C" && metrics["S"] != "U" {
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

var (
	cvss4AV  = map[string]int{"N": 0, "A": 1, "L": 2, "P": 3}
	cvss4AC  = map[string]int{"L": 0, "H": 1}
	cvss4AT  = map[string]int{"N": 0, "P": 1}
	cvss4PR  = map[string]int{"N": 0, "L": 1, "H": 2}
	cvss4UI  = map[string]int{"N": 0, "P": 1, "A": 2}
	cvss4V   = map[string]int{"H": 0, "L": 1, "N": 2}
	cvss4SC  = map[string]int{"H": 1, "L": 2, "N": 3}
	cvss4SIA = map[string]int{"S": 0, "H": 1, "L": 2, "N": 3}
	cvss4Req = map[string]int{"H": 0, "M": 1, "L": 2}
	cvss4E   = map[string]int{"A": 0, "P": 1, "U": 2}

	cvss4EQ1Max = [][][]int{{{0, 0, 0}}, {{1, 0, 0}, {0, 1, 0}, {0, 0, 1}}, {{3, 0, 0}, {1, 1, 1}}}
	cvss4EQ2Max = [][][]int{{{0, 0}}, {{1, 0}, {0, 1}}}
	cvss4EQ36Max = [][][][]int{
		{{{0, 0, 0, 0, 0, 0}}, {{0, 0, 1, 1, 1, 0}, {0, 0, 0, 1, 1, 1}}},
		{{{1, 0, 0, 0, 0, 0}, {0, 1, 0, 0, 0, 0}}, {{1, 0, 1, 0, 1, 0}, {1, 0, 0, 0, 1, 1}, {0, 1, 0, 1, 0, 1}, {0, 1, 1, 1, 0, 0}, {1, 1, 0, 0, 0, 1}}},
		{nil, {{1, 1, 1, 0, 0, 0}}},
	}
	cvss4EQ4Max = [][][]int{{{1, 0, 0}}, {{1, 1, 1}}, {{2, 2, 2}}}

	cvss4MaxSev1  = []float64{1, 4, 5}
	cvss4MaxSev2  = []float64{1, 2}
	cvss4MaxSev36 = [][]float64{{7, 6}, {8, 8}, {0, 10}}
	cvss4MaxSev4  = []float64{6, 5, 4}

	cvss4Lookup = map[[6]int]float64{
		{0, 0, 0, 0, 0, 0}: 10, {0, 0, 0, 0, 0, 1}: 9.9, {0, 0, 0, 0, 1, 0}: 9.8, {0, 0, 0, 0, 1, 1}: 9.5, {0, 0, 0, 0, 2, 0}: 9.5, {0, 0, 0, 0, 2, 1}: 9.2,
		{0, 0, 0, 1, 0, 0}: 10, {0, 0, 0, 1, 0, 1}: 9.6, {0, 0, 0, 1, 1, 0}: 9.3, {0, 0, 0, 1, 1, 1}: 8.7, {0, 0, 0, 1, 2, 0}: 9.1, {0, 0, 0, 1, 2, 1}: 8.1,
		{0, 0, 0, 2, 0, 0}: 9.3, {0, 0, 0, 2, 0, 1}: 9, {0, 0, 0, 2, 1, 0}: 8.9, {0, 0, 0, 2, 1, 1}: 8, {0, 0, 0, 2, 2, 0}: 8.1, {0, 0, 0, 2, 2, 1}: 6.8,
		{0, 0, 1, 0, 0, 0}: 9.8, {0, 0, 1, 0, 0, 1}: 9.5, {0, 0, 1, 0, 1, 0}: 9.5, {0, 0, 1, 0, 1, 1}: 9.2, {0, 0, 1, 0, 2, 0}: 9, {0, 0, 1, 0, 2, 1}: 8.4,
		{0, 0, 1, 1, 0, 0}: 9.3, {0, 0, 1, 1, 0, 1}: 9.2, {0, 0, 1, 1, 1, 0}: 8.9, {0, 0, 1, 1, 1, 1}: 8.1, {0, 0, 1, 1, 2, 0}: 8.1, {0, 0, 1, 1, 2, 1}: 6.5,
		{0, 0, 1, 2, 0, 0}: 8.8, {0, 0, 1, 2, 0, 1}: 8, {0, 0, 1, 2, 1, 0}: 7.8, {0, 0, 1, 2, 1, 1}: 7, {0, 0, 1, 2, 2, 0}: 6.9, {0, 0, 1, 2, 2, 1}: 4.8,
		{0, 0, 2, 0, 0, 1}: 9.2, {0, 0, 2, 0, 1, 1}: 8.2, {0, 0, 2, 0, 2, 1}: 7.2, {0, 0, 2, 1, 0, 1}: 7.9, {0, 0, 2, 1, 1, 1}: 6.9, {0, 0, 2, 1, 2, 1}: 5,
		{0, 0, 2, 2, 0, 1}: 6.9, {0, 0, 2, 2, 1, 1}: 5.5, {0, 0, 2, 2, 2, 1}: 2.7,
		{0, 1, 0, 0, 0, 0}: 9.9, {0, 1, 0, 0, 0, 1}: 9.7, {0, 1, 0, 0, 1, 0}: 9.5, {0, 1, 0, 0, 1, 1}: 9.2, {0, 1, 0, 0, 2, 0}: 9.2, {0, 1, 0, 0, 2, 1}: 8.5,
		{0, 1, 0, 1, 0, 0}: 9.5, {0, 1, 0, 1, 0, 1}: 9.1, {0, 1, 0, 1, 1, 0}: 9, {0, 1, 0, 1, 1, 1}: 8.3, {0, 1, 0, 1, 2, 0}: 8.4, {0, 1, 0, 1, 2, 1}: 7.1,
		{0, 1, 0, 2, 0, 0}: 9.2, {0, 1, 0, 2, 0, 1}: 8.1, {0, 1, 0, 2, 1, 0}: 8.2, {0, 1, 0, 2, 1, 1}: 7.1, {0, 1, 0, 2, 2, 0}: 7.2, {0, 1, 0, 2, 2, 1}: 5.3,
		{0, 1, 1, 0, 0, 0}: 9.5, {0, 1, 1, 0, 0, 1}: 9.3, {0, 1, 1, 0, 1, 0}: 9.2, {0, 1, 1, 0, 1, 1}: 8.5, {0, 1, 1, 0, 2, 0}: 8.5, {0, 1, 1, 0, 2, 1}: 7.3,
		{0, 1, 1, 1, 0, 0}: 9.2, {0, 1, 1, 1, 0, 1}: 8.2, {0, 1, 1, 1, 1, 0}: 8, {0, 1, 1, 1, 1, 1}: 7.2, {0, 1, 1, 1, 2, 0}: 7, {0, 1, 1, 1, 2, 1}: 5.9,
		{0, 1, 1, 2, 0, 0}: 8.4, {0, 1, 1, 2, 0, 1}: 7, {0, 1, 1, 2, 1, 0}: 7.1, {0, 1, 1, 2, 1, 1}: 5.2, {0, 1, 1, 2, 2, 0}: 5, {0, 1, 1, 2, 2, 1}: 3,
		{0, 1, 2, 0, 0, 1}: 8.6, {0, 1, 2, 0, 1, 1}: 7.5, {0, 1, 2, 0, 2, 1}: 5.2, {0, 1, 2, 1, 0, 1}: 7.1, {0, 1, 2, 1, 1, 1}: 5.2, {0, 1, 2, 1, 2, 1}: 2.9,
		{0, 1, 2, 2, 0, 1}: 6.3, {0, 1, 2, 2, 1, 1}: 2.9, {0, 1, 2, 2, 2, 1}: 1.7,
		{1, 0, 0, 0, 0, 0}: 9.8, {1, 0, 0, 0, 0, 1}: 9.5, {1, 0, 0, 0, 1, 0}: 9.4, {1, 0, 0, 0, 1, 1}: 8.7, {1, 0, 0, 0, 2, 0}: 9.1, {1, 0, 0, 0, 2, 1}: 8.1,
		{1, 0, 0, 1, 0, 0}: 9.4, {1, 0, 0, 1, 0, 1}: 8.9, {1, 0, 0, 1, 1, 0}: 8.6, {1, 0, 0, 1, 1, 1}: 7.4, {1, 0, 0, 1, 2, 0}: 7.7, {1, 0, 0, 1, 2, 1}: 6.4,
		{1, 0, 0, 2, 0, 0}: 8.7, {1, 0, 0, 2, 0, 1}: 7.5, {1, 0, 0, 2, 1, 0}: 7.4, {1, 0, 0, 2, 1, 1}: 6.3, {1, 0, 0, 2, 2, 0}: 6.3, {1, 0, 0, 2, 2, 1}: 4.9,
		{1, 0, 1, 0, 0, 0}: 9.4, {1, 0, 1, 0, 0, 1}: 8.9, {1, 0, 1, 0, 1, 0}: 8.8, {1, 0, 1, 0, 1, 1}: 7.7, {1, 0, 1, 0, 2, 0}: 7.6, {1, 0, 1, 0, 2, 1}: 6.7,
		{1, 0, 1, 1, 0, 0}: 8.6, {1, 0, 1, 1, 0, 1}: 7.6, {1, 0, 1, 1, 1, 0}: 7.4, {1, 0, 1, 1, 1, 1}: 5.8, {1, 0, 1, 1, 2, 0}: 5.9, {1, 0, 1, 1, 2, 1}: 5,
		{1, 0, 1, 2, 0, 0}: 7.2, {1, 0, 1, 2, 0, 1}: 5.7, {1, 0, 1, 2, 1, 0}: 5.7, {1, 0, 1, 2, 1, 1}: 5.2, {1, 0, 1, 2, 2, 0}: 5.2, {1, 0, 1, 2, 2, 1}: 2.5,
		{1, 0, 2, 0, 0, 1}: 8.3, {1, 0, 2, 0, 1, 1}: 7, {1, 0, 2, 0, 2, 1}: 5.4, {1, 0, 2, 1, 0, 1}: 6.5, {1, 0, 2, 1, 1, 1}: 5.8, {1, 0, 2, 1, 2, 1}: 2.6,
		{1, 0, 2, 2, 0, 1}: 5.3, {1, 0, 2, 2, 1, 1}: 2.1, {1, 0, 2, 2, 2, 1}: 1.3,
		{1, 1, 0, 0, 0, 0}: 9.5, {1, 1, 0, 0, 0, 1}: 9, {1, 1, 0, 0, 1, 0}: 8.8, {1, 1, 0, 0, 1, 1}: 7.6, {1, 1, 0, 0, 2, 0}: 7.6, {1, 1, 0, 0, 2, 1}: 7,
		{1, 1, 0, 1, 0, 0}: 9, {1, 1, 0, 1, 0, 1}: 7.7, {1, 1, 0, 1, 1, 0}: 7.5, {1, 1, 0, 1, 1, 1}: 6.2, {1, 1, 0, 1, 2, 0}: 6.1, {1, 1, 0, 1, 2, 1}: 5.3,
		{1, 1, 0, 2, 0, 0}: 7.7, {1, 1, 0, 2, 0, 1}: 6.6, {1, 1, 0, 2, 1, 0}: 6.8, {1, 1, 0, 2, 1, 1}: 5.9, {1, 1, 0, 2, 2, 0}: 5.2, {1, 1, 0, 2, 2, 1}: 3,
		{1, 1, 1, 0, 0, 0}: 8.9, {1, 1, 1, 0, 0, 1}: 7.8, {1, 1, 1, 0, 1, 0}: 7.6, {1, 1, 1, 0, 1, 1}: 6.7, {1, 1, 1, 0, 2, 0}: 6.2, {1, 1, 1, 0, 2, 1}: 5.8,
		{1, 1, 1, 1, 0, 0}: 7.4, {1, 1, 1, 1, 0, 1}: 5.9, {1, 1, 1, 1, 1, 0}: 5.7, {1, 1, 1, 1, 1, 1}: 5.7, {1, 1, 1, 1, 2, 0}: 4.7, {1, 1, 1, 1, 2, 1}: 2.3,
		{1, 1, 1, 2, 0, 0}: 6.1, {1, 1, 1, 2, 0, 1}: 5.2, {1, 1, 1, 2, 1, 0}: 5.7, {1, 1, 1, 2, 1, 1}: 2.9, {1, 1, 1, 2, 2, 0}: 2.4, {1, 1, 1, 2, 2, 1}: 1.6,
		{1, 1, 2, 0, 0, 1}: 7.1, {1, 1, 2, 0, 1, 1}: 5.9, {1, 1, 2, 0, 2, 1}: 3, {1, 1, 2, 1, 0, 1}: 5.8, {1, 1, 2, 1, 1, 1}: 2.6, {1, 1, 2, 1, 2, 1}: 1.5,
		{1, 1, 2, 2, 0, 1}: 2.3, {1, 1, 2, 2, 1, 1}: 1.3, {1, 1, 2, 2, 2, 1}: 0.6,
		{2, 0, 0, 0, 0, 0}: 9.3, {2, 0, 0, 0, 0, 1}: 8.7, {2, 0, 0, 0, 1, 0}: 8.6, {2, 0, 0, 0, 1, 1}: 7.2, {2, 0, 0, 0, 2, 0}: 7.5, {2, 0, 0, 0, 2, 1}: 5.8,
		{2, 0, 0, 1, 0, 0}: 8.6, {2, 0, 0, 1, 0, 1}: 7.4, {2, 0, 0, 1, 1, 0}: 7.4, {2, 0, 0, 1, 1, 1}: 6.1, {2, 0, 0, 1, 2, 0}: 5.6, {2, 0, 0, 1, 2, 1}: 3.4,
		{2, 0, 0, 2, 0, 0}: 7, {2, 0, 0, 2, 0, 1}: 5.4, {2, 0, 0, 2, 1, 0}: 5.2, {2, 0, 0, 2, 1, 1}: 4, {2, 0, 0, 2, 2, 0}: 4, {2, 0, 0, 2, 2, 1}: 2.2,
		{2, 0, 1, 0, 0, 0}: 8.5, {2, 0, 1, 0, 0, 1}: 7.5, {2, 0, 1, 0, 1, 0}: 7.4, {2, 0, 1, 0, 1, 1}: 5.5, {2, 0, 1, 0, 2, 0}: 6.2, {2, 0, 1, 0, 2, 1}: 5.1,
		{2, 0, 1, 1, 0, 0}: 7.2, {2, 0, 1, 1, 0, 1}: 5.7, {2, 0, 1, 1, 1, 0}: 5.5, {2, 0, 1, 1, 1, 1}: 4.1, {2, 0, 1, 1, 2, 0}: 4.6, {2, 0, 1, 1, 2, 1}: 1.9,
		{2, 0, 1, 2, 0, 0}: 5.3, {2, 0, 1, 2, 0, 1}: 3.6, {2, 0, 1, 2, 1, 0}: 3.4, {2, 0, 1, 2, 1, 1}: 1.9, {2, 0, 1, 2, 2, 0}: 1.9, {2, 0, 1, 2, 2, 1}: 0.8,
		{2, 0, 2, 0, 0, 1}: 6.4, {2, 0, 2, 0, 1, 1}: 5.1, {2, 0, 2, 0, 2, 1}: 2, {2, 0, 2, 1, 0, 1}: 4.7, {2, 0, 2, 1, 1, 1}: 2.1, {2, 0, 2, 1, 2, 1}: 1.1,
		{2, 0, 2, 2, 0, 1}: 2.4, {2, 0, 2, 2, 1, 1}: 0.9, {2, 0, 2, 2, 2, 1}: 0.4,
		{2, 1, 0, 0, 0, 0}: 8.8, {2, 1, 0, 0, 0, 1}: 7.5, {2, 1, 0, 0, 1, 0}: 7.3, {2, 1, 0, 0, 1, 1}: 5.3, {2, 1, 0, 0, 2, 0}: 6, {2, 1, 0, 0, 2, 1}: 5,
		{2, 1, 0, 1, 0, 0}: 7.3, {2, 1, 0, 1, 0, 1}: 5.5, {2, 1, 0, 1, 1, 0}: 5.9, {2, 1, 0, 1, 1, 1}: 4, {2, 1, 0, 1, 2, 0}: 4.1, {2, 1, 0, 1, 2, 1}: 2,
		{2, 1, 0, 2, 0, 0}: 5.4, {2, 1, 0, 2, 0, 1}: 4.3, {2, 1, 0, 2, 1, 0}: 4.5, {2, 1, 0, 2, 1, 1}: 2.2, {2, 1, 0, 2, 2, 0}: 2, {2, 1, 0, 2, 2, 1}: 1.1,
		{2, 1, 1, 0, 0, 0}: 7.5, {2, 1, 1, 0, 0, 1}: 5.5, {2, 1, 1, 0, 1, 0}: 5.8, {2, 1, 1, 0, 1, 1}: 4.5, {2, 1, 1, 0, 2, 0}: 4, {2, 1, 1, 0, 2, 1}: 2.1,
		{2, 1, 1, 1, 0, 0}: 6.1, {2, 1, 1, 1, 0, 1}: 5.1, {2, 1, 1, 1, 1, 0}: 4.8, {2, 1, 1, 1, 1, 1}: 1.8, {2, 1, 1, 1, 2, 0}: 2, {2, 1, 1, 1, 2, 1}: 0.9,
		{2, 1, 1, 2, 0, 0}: 4.6, {2, 1, 1, 2, 0, 1}: 1.8, {2, 1, 1, 2, 1, 0}: 1.7, {2, 1, 1, 2, 1, 1}: 0.7, {2, 1, 1, 2, 2, 0}: 0.8, {2, 1, 1, 2, 2, 1}: 0.2,
		{2, 1, 2, 0, 0, 1}: 5.3, {2, 1, 2, 0, 1, 1}: 2.4, {2, 1, 2, 0, 2, 1}: 1.4, {2, 1, 2, 1, 0, 1}: 2.4, {2, 1, 2, 1, 1, 1}: 1.2, {2, 1, 2, 1, 2, 1}: 0.5,
		{2, 1, 2, 2, 0, 1}: 1, {2, 1, 2, 2, 1, 1}: 0.3, {2, 1, 2, 2, 2, 1}: 0.1,
	}
)

func cvss4Distance(cur []int, maxVectors [][]int) float64 {
	var dist float64
	for _, mv := range maxVectors {
		sum := 0
		ok := true
		for i, c := range cur {
			if c < mv[i] {
				ok = false
				break
			}
			sum += c - mv[i]
		}
		if ok {
			dist = float64(sum)
			break
		}
	}
	return dist
}

func parseCVSSv4Vector(vector string) float64 {
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/")[1:] {
		if k, v, ok := strings.Cut(part, ":"); ok {
			metrics[k] = v
		}
	}
	for _, req := range []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"} {
		if metrics[req] == "" {
			return 0
		}
	}
	eff := func(name, def string) string {
		if mod := metrics["M"+name]; mod != "" && mod != "X" {
			return mod
		}
		if v := metrics[name]; v != "" && v != "X" {
			return v
		}
		return def
	}

	av, ok1 := cvss4AV[eff("AV", "")]
	ac, ok2 := cvss4AC[eff("AC", "")]
	at, ok3 := cvss4AT[eff("AT", "")]
	pr, ok4 := cvss4PR[eff("PR", "")]
	ui, ok5 := cvss4UI[eff("UI", "")]
	vc, ok6 := cvss4V[eff("VC", "")]
	vi, ok7 := cvss4V[eff("VI", "")]
	va, ok8 := cvss4V[eff("VA", "")]
	sc, ok9 := cvss4SC[eff("SC", "")]
	si, ok10 := cvss4SIA[eff("SI", "")]
	sa, ok11 := cvss4SIA[eff("SA", "")]
	_, baseSIOK := cvss4SC[metrics["SI"]]
	_, baseSAOK := cvss4SC[metrics["SA"]]
	cr, ok12 := cvss4Req[eff("CR", "H")]
	ir, ok13 := cvss4Req[eff("IR", "H")]
	ar, ok14 := cvss4Req[eff("AR", "H")]
	e, ok15 := cvss4E[eff("E", "A")]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 || !ok8 || !ok9 || !ok10 || !ok11 || !baseSIOK || !baseSAOK || !ok12 || !ok13 || !ok14 || !ok15 {
		return 0
	}

	if vc == 2 && vi == 2 && va == 2 && sc == 3 && si == 3 && sa == 3 {
		return 0
	}

	eq1 := 2
	if av == 0 && pr == 0 && ui == 0 {
		eq1 = 0
	} else if (av == 0 || pr == 0 || ui == 0) && av != 3 {
		eq1 = 1
	}
	eq2 := 1
	if ac == 0 && at == 0 {
		eq2 = 0
	}
	eq3 := 2
	if vc == 0 && vi == 0 {
		eq3 = 0
	} else if vc == 0 || vi == 0 || va == 0 {
		eq3 = 1
	}
	eq4 := 2
	if si == 0 || sa == 0 {
		eq4 = 0
	} else if sc == 1 || si == 1 || sa == 1 {
		eq4 = 1
	}
	eq5 := e
	eq6 := 1
	if (cr == 0 && vc == 0) || (ir == 0 && vi == 0) || (ar == 0 && va == 0) {
		eq6 = 0
	}

	baseVal := cvss4Lookup[[6]int{eq1, eq2, eq3, eq4, eq5, eq6}]

	next36Key := [6]int{eq1, eq2, eq3 + 1, eq4, eq5, eq6}
	if eq3 == 1 && eq6 == 0 {
		next36Key = [6]int{eq1, eq2, 1, eq4, eq5, 1}
	}
	next36Score, next36OK := cvss4Lookup[next36Key]
	if eq3 == 0 && eq6 == 0 {
		left := cvss4Lookup[[6]int{eq1, eq2, 0, eq4, eq5, 1}]
		right := cvss4Lookup[[6]int{eq1, eq2, 1, eq4, eq5, 0}]
		next36Score, next36OK = max(left, right), true
	}

	type eqStep struct {
		nextScore float64
		exists    bool
		dist      float64
		maxSev    float64
	}
	s1, okN1 := cvss4Lookup[[6]int{eq1 + 1, eq2, eq3, eq4, eq5, eq6}]
	s2, okN2 := cvss4Lookup[[6]int{eq1, eq2 + 1, eq3, eq4, eq5, eq6}]
	s4, okN4 := cvss4Lookup[[6]int{eq1, eq2, eq3, eq4 + 1, eq5, eq6}]
	s5, okN5 := cvss4Lookup[[6]int{eq1, eq2, eq3, eq4, eq5 + 1, eq6}]

	steps := []eqStep{
		{s1, okN1, cvss4Distance([]int{av, pr, ui}, cvss4EQ1Max[eq1]), cvss4MaxSev1[eq1]},
		{s2, okN2, cvss4Distance([]int{ac, at}, cvss4EQ2Max[eq2]), cvss4MaxSev2[eq2]},
		{next36Score, next36OK, cvss4Distance([]int{vc, vi, va, cr, ir, ar}, cvss4EQ36Max[eq3][eq6]), cvss4MaxSev36[eq3][eq6]},
		{s4, okN4, cvss4Distance([]int{sc, si, sa}, cvss4EQ4Max[eq4]), cvss4MaxSev4[eq4]},
		{s5, okN5, 0, 1},
	}

	nExisting := 0
	sumNormalized := 0.0
	for _, st := range steps {
		if st.exists {
			nExisting++
			sumNormalized += (baseVal - st.nextScore) * (st.dist / st.maxSev)
		}
	}
	if nExisting > 0 {
		baseVal -= sumNormalized / float64(nExisting)
	}
	return math.Round(math.Max(0, math.Min(10, baseVal))*10) / 10
}
