package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	nvdURL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdCacheTTL = 24 * time.Hour
)

type nvdCacheEntry struct {
	Score    float64   `json:"score"`
	CachedAt time.Time `json:"cached_at"`
}

var (
	nvdCacheOnce sync.Once
	nvdCacheMu   sync.RWMutex
	nvdCacheData map[string]nvdCacheEntry
)

func getNVDCachePath() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "dependency_risk_tracker")
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "nvd_cache.json")
}

func loadNVDCache() {
	nvdCacheOnce.Do(func() {
		nvdCacheData = make(map[string]nvdCacheEntry)
		if data, err := os.ReadFile(getNVDCachePath()); err == nil {
			_ = json.Unmarshal(data, &nvdCacheData)
		}
	})
}

func SaveNVDCache() {
	nvdCacheMu.RLock()
	if len(nvdCacheData) == 0 {
		nvdCacheMu.RUnlock()
		return
	}
	data, err := json.Marshal(nvdCacheData)
	nvdCacheMu.RUnlock()
	if err == nil {
		_ = os.WriteFile(getNVDCachePath(), data, 0644)
	}
}

func QueryNVD(cveID string) (float64, error) {
	loadNVDCache()

	nvdCacheMu.RLock()
	if entry, ok := nvdCacheData[cveID]; ok && time.Since(entry.CachedAt) < nvdCacheTTL {
		nvdCacheMu.RUnlock()
		return entry.Score, nil
	}
	nvdCacheMu.RUnlock()

	url := fmt.Sprintf("%s?cveId=%s", nvdURL, cveID)
	resp, err := httpClient.Get(url)
	if err != nil {
		return 0, fmt.Errorf("nvd request failed for %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		nvdCacheMu.Lock()
		nvdCacheData[cveID] = nvdCacheEntry{Score: 0, CachedAt: time.Now()}
		nvdCacheMu.Unlock()
		return 0, nil
	}
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

	var score float64
	if len(result.Vulnerabilities) > 0 {
		metrics := result.Vulnerabilities[0].CVE.Metrics
		if len(metrics.CVSSMetricV31) > 0 {
			score = metrics.CVSSMetricV31[0].CVSSData.BaseScore
		} else if len(metrics.CVSSMetricV30) > 0 {
			score = metrics.CVSSMetricV30[0].CVSSData.BaseScore
		} else if len(metrics.CVSSMetricV2) > 0 {
			score = metrics.CVSSMetricV2[0].CVSSData.BaseScore
		}
	}

	nvdCacheMu.Lock()
	nvdCacheData[cveID] = nvdCacheEntry{Score: score, CachedAt: time.Now()}
	nvdCacheMu.Unlock()

	return score, nil
}
