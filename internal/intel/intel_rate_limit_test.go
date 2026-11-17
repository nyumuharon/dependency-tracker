package intel

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestStaleKEVCacheIsUsefulButIncomplete(t *testing.T) {
	root := t.TempDir()
	path := writeFixture(t, root, "kev.json", `{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`)
	catalog, err := loadStaleCacheOrError(path, fmt.Errorf("service unavailable"))
	if err == nil || len(catalog) != 1 {
		t.Fatalf("stale data must retain findings with an explicit refresh error: %v, %v", catalog, err)
	}
}

func TestNVDRateLimitAndRetry(t *testing.T) {
	oldWindow, oldSleep, oldNow := nvdWindow, nvdSleep, nvdNow
	t.Cleanup(func() { nvdWindow, nvdSleep, nvdNow = oldWindow, oldSleep, oldNow; nvdRequestTimes = nil })
	clock := time.Unix(0, 0)
	var slept []time.Duration
	nvdWindow = 30 * time.Second
	nvdNow = func() time.Time { return clock }
	nvdSleep = func(d time.Duration) { slept = append(slept, d); clock = clock.Add(d) }
	nvdRequestTimes = nil

	// Six requests without a key: the sixth waits for the window to clear.
	for i := 0; i < 6; i++ {
		nvdWait()
	}
	if len(slept) != 1 || slept[0] != 30*time.Second {
		t.Fatalf("expected one 30s wait, got %v", slept)
	}
	t.Setenv("NVD_API_KEY", "key")
	if nvdRequestLimit() != 50 {
		t.Fatal("API key limit not applied")
	}

	// 429 and 503 are retried; the API key is sent; the last answer is returned.
	nvdRequestTimes, slept = nil, nil
	calls := 0
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("apiKey") != "key" {
			t.Errorf("API key not sent")
		}
		switch calls {
		case 1:
			return response(429, ""), nil
		case 2:
			return nil, errors.New("reset")
		case 3:
			return response(503, ""), nil
		}
		return response(200, `{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV40":[{"cvssData":{"baseScore":8.7}}]}}}]}`), nil
	})
	t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
	ResetCaches()
	if score, err := QueryNVD("CVE-2026-40000"); err != nil || score != 8.7 || calls != 4 {
		t.Fatalf("retry or v4 score failed: %v %v calls=%d", score, err, calls)
	}
	calls = 0
	mockHTTP(t, func(r *http.Request) (*http.Response, error) { calls++; return response(429, ""), nil })
	ResetCaches()
	if _, err := QueryNVD("CVE-2026-40001"); err == nil || calls != nvdMaxAttempts {
		t.Fatalf("persistent rate limiting accepted: %v calls=%d", err, calls)
	}
}
