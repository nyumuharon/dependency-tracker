package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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

func TestDeletedWorkingDirectoryContracts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows locks the current directory")
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	doomed := filepath.Join(root, "deleted")
	if err := os.Mkdir(doomed, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(doomed); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := os.Remove(doomed); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectNodeModules("."); err == nil {
		t.Fatal("relative environment with no working directory accepted")
	}
	if err := GenerateSARIF([]ScanResult{{Pkg: Package{Name: "example", Version: "1.0.0", ManifestPath: "relative.json"}, Vulnerabilities: []Vulnerability{{CVEID: "CVE-2026-11111"}}}}, filepath.Join(root, "report.sarif")); err != nil {
		t.Fatalf("report must tolerate an unavailable relative base: %v", err)
	}
}
