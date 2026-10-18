package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const nvdURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

func QueryNVD(cveID string) (float64, error) {
	time.Sleep(1 * time.Second)

	url := fmt.Sprintf("%s?cveId=%s", nvdURL, cveID)
	resp, err := httpClient.Get(url)
	if err != nil {
		return 0, fmt.Errorf("nvd request failed for %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("nvd returned %d for %s", resp.StatusCode, cveID)
	}

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSSMetricV30 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
					CVSSMetricV2 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("nvd decode: %w", err)
	}

	if len(result.Vulnerabilities) == 0 {
		return 0, nil
	}

	metrics := result.Vulnerabilities[0].CVE.Metrics

	// Prefer v3.1, fall back to v3.0, then v2
	if len(metrics.CVSSMetricV31) > 0 {
		return metrics.CVSSMetricV31[0].CVSSData.BaseScore, nil
	}
	if len(metrics.CVSSMetricV30) > 0 {
		return metrics.CVSSMetricV30[0].CVSSData.BaseScore, nil
	}
	if len(metrics.CVSSMetricV2) > 0 {
		return metrics.CVSSMetricV2[0].CVSSData.BaseScore, nil
	}

	return 0, nil
}
