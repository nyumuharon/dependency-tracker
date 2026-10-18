package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	osvURL      = "https://api.osv.dev/v1/query"
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

type Vulnerability struct {
	CVEID   string
	Summary string
	CVSS    float64
	ID      string
	EPSS    float64
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
	Vulns []struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases"`
		Summary  string   `json:"summary"`
		Details  string   `json:"details"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
	} `json:"vulns"`
}

type osvBatchQuery struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []osvResponse `json:"results"`
}

func parseVulns(res osvResponse) []Vulnerability {
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

		vuln := Vulnerability{
			ID:      v.ID,
			Summary: summary,
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
				vuln.CVSS = parseCVSSVector(sev.Score)
				break
			}
		}

		vulns = append(vulns, vuln)
	}

	return vulns
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
			var q osvQuery
			q.Package.Name = pkg.Name
			q.Package.Ecosystem = pkg.Ecosystem
			q.Version = pkg.Version
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

		for idx, item := range batchResp.Results {
			pkg := chunk[idx]
			resultMap[pkg.Name] = parseVulns(item)
		}
	}

	return resultMap, nil
}

func QueryOSV(pkg Package) ([]Vulnerability, error) {
	// Build the request body
	var q osvQuery
	q.Package.Name = pkg.Name
	q.Package.Ecosystem = pkg.Ecosystem
	q.Version = pkg.Version

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

	return parseVulns(result), nil
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
