package intel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

func getNVDCachePath() string { return cacheFile("nvd_cache.json") }

func loadNVDCache() {
	nvdCacheOnce.Do(func() {
		nvdCacheData = make(map[string]nvdCacheEntry)
		if data, err := os.ReadFile(getNVDCachePath()); err == nil {
			_ = json.Unmarshal(data, &nvdCacheData)
			if nvdCacheData == nil {
				nvdCacheData = make(map[string]nvdCacheEntry)
			}
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
		writeCacheFile(getNVDCachePath(), data)
	}
}

// NVD allows 5 requests per rolling 30 seconds without an API key and 50 with
// one (NVD_API_KEY). Requests are paced to stay inside that window, and
// rate-limit or overload responses are retried, so that a scan needing many
// lookups is slower rather than incomplete.
var (
	nvdWindow       = 30 * time.Second
	nvdRetryDelay   = 6 * time.Second
	nvdMaxAttempts  = 4
	nvdLimiterMu    sync.Mutex
	nvdRequestTimes []time.Time
	nvdSleep        = time.Sleep
	nvdNow          = time.Now
)

func nvdRequestLimit() int {
	if os.Getenv("NVD_API_KEY") != "" {
		return 50
	}
	return 5
}

// nvdWait blocks until another request fits in the rate-limit window.
func nvdWait() {
	nvdLimiterMu.Lock()
	defer nvdLimiterMu.Unlock()
	for {
		now := nvdNow()
		recent := nvdRequestTimes[:0]
		for _, t := range nvdRequestTimes {
			if now.Sub(t) < nvdWindow {
				recent = append(recent, t)
			}
		}
		nvdRequestTimes = recent
		if len(recent) < nvdRequestLimit() {
			nvdRequestTimes = append(nvdRequestTimes, now)
			return
		}
		nvdSleep(nvdWindow - now.Sub(recent[0]))
	}
}

func nvdGet(url string) (*http.Response, error) {
	for attempt := 1; ; attempt++ {
		nvdWait()
		// url combines the constant NVD endpoint with a CVE identifier.
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		if key := os.Getenv("NVD_API_KEY"); key != "" {
			req.Header.Set("apiKey", key)
		}
		resp, err := httpClient.Do(req)
		retry := err != nil || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusForbidden
		if !retry || attempt == nvdMaxAttempts {
			return resp, err
		}
		if resp != nil {
			resp.Body.Close()
		}
		nvdSleep(time.Duration(attempt) * nvdRetryDelay)
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
	resp, err := nvdGet(url)
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
					CVSSMetricV40 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV40"`
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
		} else if len(metrics.CVSSMetricV40) > 0 {
			// Newer CVEs may carry only a CVSS v4.0 score.
			score = metrics.CVSSMetricV40[0].CVSSData.BaseScore
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
