package intel

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestIntelAliasesAndCaches(t *testing.T) {
	t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
	ResetCaches()
	SaveNVDCache()       // empty cache
	SaveStalenessCache() // empty cache

	if HTTPClient() == nil {
		t.Fatal("expected non-nil HTTPClient")
	}
	SetHTTPClient(HTTPClient())

	// Test ParseVulns, ParseCVSSVector, ParseKEVData
	_ = ParseVulns(OSVResponse{}, Package{Name: "a", Version: "1.0.0", Ecosystem: "npm"})
	if s := ParseCVSSVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); s != 9.8 {
		t.Fatalf("expected 9.8 for CVSS vector, got %f", s)
	}
	for _, vec := range []string{
		"invalid",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
	} {
		if s := ParseCVSSVector(vec); s != 0 {
			t.Fatalf("expected 0 for %s, got %f", vec, s)
		}
	}
	if s := ParseCVSSVector("9.8"); s != 9.8 {
		t.Fatalf("expected 9.8, got %f", s)
	}
	if _, err := ParseKEVData([]byte(`{"vulnerabilities":[]}`)); err != nil {
		t.Fatalf("unexpected ParseKEVData error: %v", err)
	}

	// Save caches
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Host, "nvd") {
			return response(200, `{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5}}]}}}]}`), nil
		}
		if strings.Contains(r.URL.Host, "registry.npmjs.org") {
			return response(200, `{"dist-tags":{"latest":"1.0.0"},"time":{"1.0.0":"2026-01-01T00:00:00Z"}}`), nil
		}
		return response(200, `{"vulnerabilities":[]}`), nil
	})
	_, _ = QueryNVD("CVE-2026-9999")
	SaveNVDCache()
	SaveNVDCache() // when not dirty
	_, _ = CheckStaleness(Package{Name: "example", Version: "1.0.0", Ecosystem: "npm"})
	SaveStalenessCache()
	SaveStalenessCache() // when not dirty
	_, _ = FetchKEVCatalog()

	// KEV HTTP error
	t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(503, "unavailable"), nil
	})
	_, _ = FetchKEVCatalog()
}

func TestEPSSQueries(t *testing.T) {
	// Empty
	scores, err := QueryEPSS(nil)
	if err != nil || len(scores) != 0 {
		t.Fatalf("expected empty map for nil CVEs: %v %v", scores, err)
	}

	// Network error
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})
	if _, err := QueryEPSS([]string{"CVE-2026-1"}); err == nil {
		t.Fatal("expected network error")
	}

	// Non-200
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(503, "unavailable"), nil
	})
	if _, err := QueryEPSS([]string{"CVE-2026-1"}); err == nil {
		t.Fatal("expected HTTP 503 error")
	}

	// Invalid JSON
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(200, "{bad"), nil
	})
	if _, err := QueryEPSS([]string{"CVE-2026-1"}); err == nil {
		t.Fatal("expected JSON error")
	}

	// Batching > 100 CVEs + invalid float
	var ids []string
	for i := 0; i < 105; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2026-%04d", i))
	}
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"data":[{"cve":"CVE-2026-0001","epss":"0.45"},{"cve":"CVE-2026-0002","epss":"not-a-float"}]}`), nil
	})
	scores, err = QueryEPSS(ids)
	if err == nil || scores["CVE-2026-0001"] != 0.45 {
		t.Fatalf("unexpected EPSS batch result: %v %v", scores, err)
	}

	// Single valid batch
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"data":[{"cve":"CVE-2026-0001","epss":"0.45"}]}`), nil
	})
	scores, err = QueryEPSS([]string{"CVE-2026-0001"})
	if err != nil || scores["CVE-2026-0001"] != 0.45 {
		t.Fatalf("unexpected single EPSS result: %v %v", scores, err)
	}

	// Duplicate CVE entry
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"data":[{"cve":"CVE-2026-0001","epss":"0.45"},{"cve":"CVE-2026-0001","epss":"0.50"}]}`), nil
	})
	if _, err := QueryEPSS([]string{"CVE-2026-0001"}); err == nil {
		t.Fatal("expected error for duplicate EPSS entry")
	}
}

func TestOSVDirectAndBatchErrors(t *testing.T) {
	// QueryOSV invalid version
	if _, err := QueryOSV(Package{Name: "a", Version: "^1.0", Ecosystem: "npm", VersionSource: "constraint"}); err == nil {
		t.Fatal("expected version error")
	}

	// QueryOSV network error
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})
	if _, err := QueryOSV(Package{Name: "a", Version: "1.0.0", Ecosystem: "npm"}); err == nil {
		t.Fatal("expected network error")
	}

	// QueryOSV non-200
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(500, "err"), nil
	})
	if _, err := QueryOSV(Package{Name: "a", Version: "1.0.0", Ecosystem: "npm"}); err == nil {
		t.Fatal("expected 500 error")
	}

	// QueryOSV invalid JSON
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(200, "{bad"), nil
	})
	if _, err := QueryOSV(Package{Name: "a", Version: "1.0.0", Ecosystem: "npm"}); err == nil {
		t.Fatal("expected JSON error")
	}

	// QueryOSV valid
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"vulns":[{"id":"GHSA-1"}]}`), nil
	})
	vulns, err := QueryOSV(Package{Name: "a", Version: "1.0.0", Ecosystem: "npm"})
	if err != nil || len(vulns) != 1 {
		t.Fatalf("unexpected QueryOSV result: %v %v", vulns, err)
	}

	// QueryOSVBatch empty
	res, err := QueryOSVBatch(nil)
	if err != nil || len(res) != 0 {
		t.Fatalf("expected empty batch: %v %v", res, err)
	}

	// QueryOSVBatch invalid version in package
	if _, err := QueryOSVBatch([]Package{{Name: "a", Version: "^1.0", Ecosystem: "npm", VersionSource: "constraint"}}); err == nil {
		t.Fatal("expected invalid version error in batch")
	}

	pkg := Package{Name: "a", Version: "1.0.0", Ecosystem: "npm"}

	// QueryOSVBatch network error
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})
	if _, err := QueryOSVBatch([]Package{pkg}); err == nil {
		t.Fatal("expected batch network error")
	}

	// QueryOSVBatch non-200
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(500, "err"), nil
	})
	if _, err := QueryOSVBatch([]Package{pkg}); err == nil {
		t.Fatal("expected batch 500 error")
	}

	// QueryOSVBatch invalid JSON
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(200, "{bad"), nil
	})
	if _, err := QueryOSVBatch([]Package{pkg}); err == nil {
		t.Fatal("expected batch JSON error")
	}

	// QueryOSVBatch mismatched count
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `{"results":[]}`), nil
	})
	if _, err := QueryOSVBatch([]Package{pkg}); err == nil {
		t.Fatal("expected batch count mismatch error")
	}

	// QueryOSVBatch with vulns + detail fetch failure
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/querybatch") {
			return response(200, `{"results":[{"vulns":[{"id":"GHSA-1"}]}]}`), nil
		}
		return response(500, "detail error"), nil
	})
	if _, err := QueryOSVBatch([]Package{pkg}); err == nil {
		t.Fatal("expected batch detail error")
	}

	// QueryOSVBatch with vulns + detail network error
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/querybatch") {
			return response(200, `{"results":[{"vulns":[{"id":"GHSA-1"}]}]}`), nil
		}
		return nil, errors.New("detail offline")
	})
	if _, err := QueryOSVBatch([]Package{pkg}); err == nil {
		t.Fatal("expected batch detail network error")
	}

	// QueryOSVBatch with vulns + detail bad JSON
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/querybatch") {
			return response(200, `{"results":[{"vulns":[{"id":"GHSA-1"}]}]}`), nil
		}
		return response(200, "{bad"), nil
	})
	if _, err := QueryOSVBatch([]Package{pkg}); err == nil {
		t.Fatal("expected batch detail JSON error")
	}

	// QueryOSVBatch success with vulns
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/querybatch") {
			return response(200, `{"results":[{"vulns":[{"id":"GHSA-1"}]}]}`), nil
		}
		return response(200, `{"id":"GHSA-1","aliases":["CVE-2026-1"]}`), nil
	})
	res, err = QueryOSVBatch([]Package{pkg})
	if err != nil || res == nil {
		t.Fatalf("unexpected batch success: %v %v", res, err)
	}
}
