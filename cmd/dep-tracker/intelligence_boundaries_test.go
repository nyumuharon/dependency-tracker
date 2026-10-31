package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKEVCatalogCacheAndFailureContracts(t *testing.T) {
	for _, mode := range []string{"fresh-cache", "bad-cache", "transport", "body-read", "bad-json", "missing-array", "blank-id"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
			calls := 0
			if mode == "fresh-cache" {
				if err := os.WriteFile(getKEVCachePath(), []byte(`{"vulnerabilities":[{"cveID":"CVE-2026-11111"}]}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "bad-cache" {
				if err := os.WriteFile(getKEVCachePath(), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			mockHTTP(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if mode == "transport" {
					return nil, errors.New("offline")
				}
				if mode == "body-read" {
					return &http.Response{StatusCode: 200, Body: failingBody{}, Header: make(http.Header)}, nil
				}
				if mode == "bad-json" {
					return response(200, "invalid"), nil
				}
				if mode == "missing-array" {
					return response(200, `{}`), nil
				}
				if mode == "blank-id" {
					return response(200, `{"vulnerabilities":[{"cveID":"  "}]}`), nil
				}
				return response(200, `{"vulnerabilities":[{"cveID":"CVE-2026-11111"}]}`), nil
			})
			catalog, err := FetchKEVCatalog()
			bad := mode == "transport" || mode == "body-read" || mode == "bad-json" || mode == "missing-array"
			if (err != nil) != bad {
				t.Fatalf("unexpected catalog outcome: %v", err)
			}
			if mode == "fresh-cache" && calls != 0 {
				t.Fatal("fresh catalog unnecessarily downloaded")
			}
			if !bad && mode != "blank-id" && len(catalog) != 1 {
				t.Fatalf("catalog lost entries: %v", catalog)
			}
			if mode == "blank-id" && len(catalog) != 0 {
				t.Fatal("blank CVE indexed")
			}
		})
	}
}

func TestNVDTransportDecodeAndNotFound(t *testing.T) {
	for _, mode := range []string{"transport", "decode", "not-found"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
			nvdCacheOnce = sync.Once{}
			mockHTTP(t, func(r *http.Request) (*http.Response, error) {
				if mode == "transport" {
					return nil, errors.New("offline")
				}
				if mode == "decode" {
					return response(200, "invalid"), nil
				}
				return response(404, ""), nil
			})
			score, err := QueryNVD("CVE-2026-11111")
			if mode == "not-found" {
				if err != nil || score != 0 {
					t.Fatalf("%v %v", score, err)
				}
			} else if err == nil {
				t.Fatal("unavailable NVD accepted")
			}
		})
	}
}

func TestRegistryTransportFailures(t *testing.T) {
	for _, eco := range []string{"npm", "PyPI", "Maven", "NuGet", "Go", "crates.io", "Packagist", "RubyGems", "ConanCenter", "Pub", "Hex", "Unsupported"} {
		t.Run(eco, func(t *testing.T) {
			t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
			stalenessCacheOnce = sync.Once{}
			mockHTTP(t, func(r *http.Request) (*http.Response, error) { return nil, errors.New("offline") })
			name := "example"
			if eco == "Maven" {
				name = "org.example:library"
			}
			if _, err := CheckStaleness(Package{Name: name, Ecosystem: eco}); err == nil {
				t.Fatal("unavailable registry accepted")
			}
		})
	}
	if _, err := checkMavenStaleness("invalid"); err == nil {
		t.Fatal("invalid coordinate accepted")
	}
}

func TestRegistryUnknownDateVariants(t *testing.T) {
	cases := []struct{ eco, name, body string }{
		{"npm", "example", `{"dist-tags":{"latest":"1.0.0"},"time":{"1.0.0":"bad"}}`},
		{"npm", "example", `{"dist-tags":{"latest":"1.0.0"},"time":{}}`},
		{"NuGet", "example", `{"items":[{"upper":"1.0.0","items":[]}]}`},
		{"NuGet", "example", `{"items":[{"items":[{"catalogEntry":{"version":"1.0.0","published":"bad"}}]}]}`},
		{"Maven", "org.example:library", `{"response":{"docs":[{"latestVersion":"1.0.0"}]}}`},
		{"crates.io", "example", `{"crate":{"max_version":"1.0.0","updated_at":"bad"}}`},
		{"Packagist", "example/example", `{"packages":{"example/example":[{"version":"1.0.0","time":"bad"}]}}`},
		{"RubyGems", "example", `{"version":"1.0.0","version_created_at":"bad"}`},
		{"Pub", "example", `{"latest":{"version":"1.0.0","published":"bad"}}`},
		{"Hex", "example", `{"releases":[{"version":"1.0.0","inserted_at":"bad"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.eco+tc.body, func(t *testing.T) {
			t.Setenv("DEP_TRACKER_CACHE_DIR", t.TempDir())
			stalenessCacheOnce = sync.Once{}
			mockHTTP(t, func(r *http.Request) (*http.Response, error) { return response(200, tc.body), nil })
			if _, err := CheckStaleness(Package{Name: tc.name, Ecosystem: tc.eco}); err == nil {
				t.Fatal("missing date was reported as maintained/stale")
			}
		})
	}
	for _, body := range []string{`{"info":{"version":"1.0.0"},"urls":[]}`, `{"info":{"version":"1.0.0"},"urls":[{"upload_time_iso_8601":"bad"}]}`} {
		mockHTTP(t, func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, "/rss/") {
				return response(503, ""), nil
			}
			return response(200, body), nil
		})
		result, err := checkPyPIStaleness("example")
		if err != nil || !result.LastUpdated.IsZero() {
			t.Fatalf("unknown date invented: %+v %v", result, err)
		}
	}
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(200, fmt.Sprintf(`<rss><channel><item><title>2.0.0rc1</title><pubDate>bad</pubDate></item><item><title>1.0.0</title><pubDate>%s</pubDate></item></channel></rss>`, time.Now().UTC().Format(time.RFC1123))), nil
	})
	if result, err := checkPyPIStaleness("example"); err != nil || result.LatestVersion != "1.0.0" {
		t.Fatalf("prerelease selected: %+v %v", result, err)
	}
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return response(200, `<rss><channel><item><title>1.0.0</title><pubDate>bad</pubDate></item></channel></rss>`), nil
	})
	if result, err := checkPyPIStaleness("example"); err != nil || !result.LastUpdated.IsZero() {
		t.Fatalf("unknown RSS date invented: %+v %v", result, err)
	}
	for _, body := range []string{"unrelated: true\n", "versions:\nnext-section:\n"} {
		mockHTTP(t, func(r *http.Request) (*http.Response, error) { return response(200, body), nil })
		if result, err := checkConanStaleness("example"); err != nil || result.LatestVersion != "" {
			t.Fatalf("version invented: %+v %v", result, err)
		}
	}
	mockHTTP(t, func(r *http.Request) (*http.Response, error) { return response(404, ""), nil })
	if _, err := checkConanStaleness("example"); err != nil {
		t.Fatal(err)
	}
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: failingBody{}, Header: make(http.Header)}, nil
	})
	if _, err := checkConanStaleness("example"); err == nil {
		t.Fatal("truncated recipe accepted")
	}
}
