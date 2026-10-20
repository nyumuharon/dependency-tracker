package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const epssURL = "https://api.first.org/data/v1/epss"

func QueryEPSS(cveIDs []string) (map[string]float64, error) {
	scores := make(map[string]float64)
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

		for _, entry := range result.Data {
			if f, err := strconv.ParseFloat(entry.EPSS, 64); err == nil {
				scores[entry.CVE] = f
			}
		}
	}

	return scores, nil
}
