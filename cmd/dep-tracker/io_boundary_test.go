package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type faultUpdateFile struct {
	*os.File
	writeFailure, closeFailure bool
}

func (f faultUpdateFile) Write(p []byte) (int, error) {
	if f.writeFailure {
		return 0, errors.New("disk full")
	}
	return f.File.Write(p)
}
func (f faultUpdateFile) WriteString(s string) (int, error) { return f.Write([]byte(s)) }

func (f faultUpdateFile) Close() error {
	err := f.File.Close()
	if f.closeFailure {
		return errors.New("close failed")
	}
	return err
}

func TestVerifiedDownloadIOFailureContracts(t *testing.T) {
	sum := sha256.Sum256([]byte("verified binary"))
	manifest := hex.EncodeToString(sum[:]) + "  dep-tracker-linux-amd64\n"
	for _, mode := range []string{"checksum-network", "checksum-read", "binary-network", "binary-read", "create", "write", "close"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if strings.HasSuffix(r.URL.Path, "SHA256SUMS.txt") {
					if mode == "checksum-network" {
						return nil, errors.New("offline")
					}
					if mode == "checksum-read" {
						return &http.Response{StatusCode: 200, Body: failingBody{}, Header: make(http.Header)}, nil
					}
					return response(200, manifest), nil
				}
				if mode == "binary-network" {
					return nil, errors.New("offline")
				}
				if mode == "binary-read" {
					return &http.Response{StatusCode: 200, Body: failingBody{}, Header: make(http.Header)}, nil
				}
				return response(200, "verified binary"), nil
			})}
			create := func(dir, pattern string) (updateTempFile, error) {
				if mode == "create" {
					return nil, errors.New("read-only directory")
				}
				f, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				return faultUpdateFile{File: f, writeFailure: mode == "write", closeFailure: mode == "close"}, nil
			}
			if _, err := downloadVerifiedUpdateTo(client, "https://example.com", "dep-tracker-linux-amd64", root, create); err == nil {
				t.Fatal("failed download accepted")
			}
			if calls == 0 {
				t.Fatal("did not attempt the download")
			}
			if files, _ := filepath.Glob(filepath.Join(root, ".dep-tracker-update-*")); len(files) != 0 {
				t.Fatalf("failed download leaked: %v", files)
			}
		})
	}
}

func TestCachePlatformPathAndUnavailableService(t *testing.T) {
	t.Setenv("DEP_TRACKER_CACHE_DIR", "")
	old := platformCacheDir
	t.Cleanup(func() { platformCacheDir = old })
	root := t.TempDir()
	platformCacheDir = func() (string, error) { return root, nil }
	if got := cacheFile("cache.json"); got != filepath.Join(root, "dependency_risk_tracker", "cache.json") {
		t.Fatal(got)
	}
	platformCacheDir = func() (string, error) { return "", errors.New("platform cache unavailable") }
	if got := cacheFile("cache.json"); got != filepath.Join(os.TempDir(), "dependency_risk_tracker", "cache.json") {
		t.Fatal(got)
	}
}

// Filesystem behavior for deleted working directories differs between macOS
// and Linux. Test the failing service contract explicitly on every platform.
func TestWorkingDirectoryServiceFailureContracts(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	unavailable := errors.New("working directory unavailable")
	if _, err := inspectNodeModulesWithPath(".", func(string) (string, error) { return "", unavailable }); !errors.Is(err, unavailable) {
		t.Fatalf("directory failure was lost: %v", err)
	}
	if err := generateSARIFWithDirectory([]ScanResult{{Pkg: Package{Name: "example", Version: "1.0.0", ManifestPath: "relative.json"}, Vulnerabilities: []Vulnerability{{CVEID: "CVE-2026-11111"}}}}, filepath.Join(root, "report.sarif"), func() (string, error) { return "", unavailable }); err != nil {
		t.Fatalf("report must tolerate an unavailable relative base: %v", err)
	}
}
