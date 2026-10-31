package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
)

const epssURL = "https://api.first.org/data/v1/epss"

func QueryEPSS(cveIDs []string) (map[string]float64, error) {
	scores := make(map[string]float64)
	var issues []error
	if len(cveIDs) == 0 {
		return scores, nil
	}

	// Batch in groups of 50
	for i := 0; i < len(cveIDs); i += 50 {
		end := i + 50
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[i:end]

		url := fmt.Sprintf("%s?cve=%s", epssURL, strings.Join(batch, ","))
		resp, err := httpClient.Get(url)
		if err != nil {
			return scores, fmt.Errorf("epss request failed: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return scores, fmt.Errorf("epss returned status %d", resp.StatusCode)
		}

		var result struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}

		decodeErr := json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if decodeErr != nil {
			return scores, fmt.Errorf("epss decode: %w", decodeErr)
		}

		requested := make(map[string]bool)
		for _, id := range batch {
			requested[id] = true
		}
		seen := make(map[string]bool)
		for _, entry := range result.Data {
			if !requested[entry.CVE] {
				continue
			}
			if seen[entry.CVE] {
				delete(scores, entry.CVE)
				issues = append(issues, fmt.Errorf("duplicate EPSS score for %s", entry.CVE))
				continue
			}
			seen[entry.CVE] = true
			f, err := strconv.ParseFloat(entry.EPSS, 64)
			if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1 {
				issues = append(issues, fmt.Errorf("invalid EPSS score for %s", entry.CVE))
				continue
			}
			scores[entry.CVE] = f
		}
		for id := range requested {
			if !seen[id] {
				issues = append(issues, fmt.Errorf("EPSS score unavailable for %s", id))
			}
		}
	}

	return scores, errors.Join(issues...)
}
