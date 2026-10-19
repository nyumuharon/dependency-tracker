package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	cisaKEVURL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	cisaCacheTTL = 24 * time.Hour
)

type KEVEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

type KEVCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// getKEVCachePath returns the path to the local KEV cache file.
func getKEVCachePath() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "dependency_risk_tracker")
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "cisa_kev.json")
}

// FetchKEVCatalog downloads or loads the cached CISA KEV catalog.
// It returns a map of CVE ID to KEVEntry.
func FetchKEVCatalog() (map[string]KEVEntry, error) {
	cachePath := getKEVCachePath()

	// 1. Check if cache is fresh
	if fi, err := os.Stat(cachePath); err == nil {
		if time.Since(fi.ModTime()) < cisaCacheTTL {
			data, err := os.ReadFile(cachePath)
			if err == nil {
				catalog, err := parseKEVData(data)
				if err == nil {
					return catalog, nil
				}
			}
		}
	}

	// 2. Fetch fresh catalog from CISA
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", cisaKEVURL, nil)
	if err != nil {
		return loadStaleCacheOrError(cachePath, err)
	}
	req.Header.Set("User-Agent", "dependency-risk-tracker/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return loadStaleCacheOrError(cachePath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return loadStaleCacheOrError(cachePath, fmt.Errorf("HTTP %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return loadStaleCacheOrError(cachePath, err)
	}

	// 3. Save to disk cache
	_ = os.WriteFile(cachePath, body, 0644)

	return parseKEVData(body)
}

func parseKEVData(data []byte) (map[string]KEVEntry, error) {
	var catalog KEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("failed to unmarshal KEV catalog: %w", err)
	}

	result := make(map[string]KEVEntry, len(catalog.Vulnerabilities))
	for _, entry := range catalog.Vulnerabilities {
		id := strings.TrimSpace(entry.CVEID)
		if id != "" {
			result[id] = entry
		}
	}
	return result, nil
}

func loadStaleCacheOrError(cachePath string, originalErr error) (map[string]KEVEntry, error) {
	data, err := os.ReadFile(cachePath)
	if err == nil {
		catalog, parseErr := parseKEVData(data)
		if parseErr == nil {
			return catalog, nil
		}
	}
	return nil, fmt.Errorf("could not fetch CISA KEV catalog: %w", originalErr)
}
