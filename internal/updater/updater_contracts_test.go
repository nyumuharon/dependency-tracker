package updater

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func writeFixture(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (failingBody) Close() error               { return nil }

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

func (f faultUpdateFile) Close() error {
	_ = f.File.Close()
	if f.closeFailure {
		return errors.New("close failure")
	}
	return nil
}

func TestUpdaterPlatformAndFailureContracts(t *testing.T) {
	appVersion := "1.1.1"
	cases := []struct {
		name, platform string
		fail           bool
	}{
		{"linux-success", "linux", false}, {"darwin-success", "darwin", false}, {"windows-success", "windows", false},
		{"windows-backup-failure", "windows", true}, {"windows-install-failure", "windows", true}, {"windows-rollback-failure", "windows", true},
		{"chmod-failure", "linux", true}, {"rename-failure", "linux", true}, {"permission-failure", "linux", true},
		{"executable-failure", "linux", true}, {"symlink-failure", "linux", true}, {"unsupported-platform", "plan9", true},
		{"api-request-failure", "linux", true}, {"api-network-failure", "linux", true}, {"api-status-failure", "linux", true},
		{"api-json-failure", "linux", true}, {"invalid-version", "linux", true}, {"current-version", "linux", false},
		{"old-version", "linux", false}, {"checksum-failure", "linux", true},
		{"downgrade", "linux", false}, {"target-current", "linux", false}, {"target-missing", "linux", true}, {"target-invalid", "linux", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			exe := writeFixture(t, root, "dep-tracker", "original executable")
			sum := sha256.Sum256([]byte("verified new executable"))
			hash := hex.EncodeToString(sum[:])
			options := DefaultUpdater(appVersion)
			options.Platform = tc.platform
			options.Arch = "amd64"
			options.ApiURL = "https://api.example/latest"
			options.ReleaseBase = "https://releases.example"
			options.Executable = func() (string, error) {
				if tc.name == "executable-failure" {
					return "", errors.New("executable unavailable")
				}
				return exe, nil
			}
			options.Resolve = func(p string) (string, error) {
				if tc.name == "symlink-failure" {
					return "", errors.New("broken link")
				}
				return p, nil
			}
			realRename := options.Fs.Rename
			options.Fs.Rename = func(old, new string) error {
				if tc.name == "windows-backup-failure" && old == exe {
					return errors.New("backup failed")
				}
				if (tc.name == "windows-install-failure" || tc.name == "windows-rollback-failure") && strings.Contains(old, ".dep-tracker-update-") {
					return errors.New("install failed")
				}
				if tc.name == "windows-rollback-failure" && strings.HasSuffix(old, ".old") {
					return errors.New("rollback failed")
				}
				if tc.name == "rename-failure" {
					return errors.New("rename failed")
				}
				if tc.name == "permission-failure" {
					return &os.PathError{Op: "rename", Path: new, Err: syscall.EACCES}
				}
				return realRename(old, new)
			}
			if tc.name == "chmod-failure" {
				options.Fs.Chmod = func(string, os.FileMode) error { return errors.New("chmod failed") }
			}
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "api.example" {
					if r.Header.Get("User-Agent") != "dep-tracker-updater" {
						t.Error("missing update user agent")
					}
					switch tc.name {
					case "api-network-failure":
						return nil, errors.New("offline")
					case "api-status-failure":
						return response(503, "unavailable"), nil
					case "api-json-failure":
						return response(200, "invalid JSON"), nil
					case "invalid-version":
						return response(200, `{"tag_name":"invalid"}`), nil
					case "current-version":
						return response(200, fmt.Sprintf(`{"tag_name":%q}`, "v"+appVersion)), nil
					case "old-version":
						return response(200, `{"tag_name":"v0.0.1"}`), nil
					}
					// update --version X asks for that release, not the latest.
					if strings.Contains(r.URL.Path, "/tags/") {
						switch tc.name {
						case "target-missing":
							return response(404, ""), nil
						case "target-current":
							return response(200, fmt.Sprintf(`{"tag_name":%q}`, "v"+appVersion)), nil
						}
						if r.URL.Path != "/tags/v0.0.1" {
							t.Errorf("wrong release requested: %s", r.URL.Path)
						}
						return response(200, `{"tag_name":"v0.0.1"}`), nil
					}
					return response(200, `{"tag_name":" v99.0.0 "}`), nil
				}
				binary := "dep-tracker-" + tc.platform + "-amd64"
				if tc.platform == "windows" {
					binary += ".exe"
				}
				if strings.HasSuffix(r.URL.Path, "SHA256SUMS.txt") {
					if tc.name == "checksum-failure" {
						return response(200, "invalid manifest"), nil
					}
					return response(200, hash+"  "+binary+"\n"), nil
				}
				return response(200, "verified new executable"), nil
			})}
			options.ApiClient = client
			options.DownloadClient = client
			if tc.name == "api-request-failure" {
				options.ApiURL = "\ninvalid"
			}
			switch tc.name {
			case "downgrade":
				options.Version = "v0.0.1"
			case "target-current":
				options.Version = appVersion
			case "target-missing":
				options.Version = "9.9.9"
			case "target-invalid":
				options.Version = "not-a-version"
			}
			err := RunUpdateWith(options)
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected update outcome: %v", err)
			}
			if tc.name == "windows-rollback-failure" {
				if _, err := os.Stat(exe); err == nil {
					t.Fatal("simulated rollback failure left an executable behind")
				}
				return
			}
			data, err := os.ReadFile(exe)
			if err != nil {
				t.Fatal(err)
			}
			upgraded := !tc.fail && tc.name != "current-version" && tc.name != "old-version" && tc.name != "target-current"
			if upgraded && string(data) != "verified new executable" {
				t.Fatal("verified binary was not installed")
			}
			if !upgraded && string(data) != "original executable" {
				t.Fatal("failed update changed the existing binary")
			}
			if files, _ := filepath.Glob(filepath.Join(root, ".dep-tracker-update-*")); len(files) > 0 {
				t.Fatalf("download files leaked: %v", files)
			}
			if _, err := os.Stat(exe + ".old"); !os.IsNotExist(err) {
				t.Fatal("backup file leaked")
			}
		})
	}
}

func TestVerifiedDownloadIOFailures(t *testing.T) {
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
			create := func(dir, pattern string) (UpdateTempFile, error) {
				if mode == "create" {
					return nil, errors.New("read-only directory")
				}
				f, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				return faultUpdateFile{File: f, writeFailure: mode == "write", closeFailure: mode == "close"}, nil
			}
			if _, err := DownloadVerifiedUpdateTo(client, "https://example.com", "dep-tracker-linux-amd64", root, create); err == nil {
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

func TestRunUpdateDirect(t *testing.T) {
	// Simple RunUpdate wrapper call
	oldTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = oldTransport }()
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return response(200, `{"tag_name":"v1.1.1"}`), nil
	})
	if err := RunUpdate("1.1.1", ""); err != nil {
		t.Fatalf("unexpected RunUpdate error: %v", err)
	}
}

func TestDownloadVerifiedUpdateDirect(t *testing.T) {
	root := t.TempDir()
	sum := sha256.Sum256([]byte("verified binary"))
	manifest := hex.EncodeToString(sum[:]) + "  dep-tracker-linux-amd64\n"
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "SHA256SUMS.txt") {
			return response(200, manifest), nil
		}
		return response(200, "verified binary"), nil
	})}
	p, err := DownloadVerifiedUpdate(client, "https://example.com", "dep-tracker-linux-amd64", root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = os.Remove(p)
}

func TestDownloadVerifiedUpdateHTTPStatusesAndMismatch(t *testing.T) {
	root := t.TempDir()
	sum := sha256.Sum256([]byte("verified binary"))
	manifest := hex.EncodeToString(sum[:]) + "  dep-tracker-linux-amd64\n"

	// Non-200 checksum status
	c1 := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return response(404, "not found"), nil
	})}
	if _, err := DownloadVerifiedUpdate(c1, "https://example.com", "dep-tracker-linux-amd64", root); err == nil {
		t.Fatal("expected error on 404 checksum")
	}

	// Non-200 binary status
	c2 := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "SHA256SUMS.txt") {
			return response(200, manifest), nil
		}
		return response(500, "server error"), nil
	})}
	if _, err := DownloadVerifiedUpdate(c2, "https://example.com", "dep-tracker-linux-amd64", root); err == nil {
		t.Fatal("expected error on 500 binary")
	}

	// Checksum mismatch
	c3 := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "SHA256SUMS.txt") {
			return response(200, manifest), nil
		}
		return response(200, "tampered binary content"), nil
	})}
	if _, err := DownloadVerifiedUpdate(c3, "https://example.com", "dep-tracker-linux-amd64", root); err == nil {
		t.Fatal("expected error on checksum mismatch")
	}
}

func TestReleaseChecksumErrors(t *testing.T) {
	// Missing checksum
	if _, err := ReleaseChecksum("", "foo"); err == nil {
		t.Fatal("expected error for empty manifest")
	}
	// Duplicate checksum
	dup := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 foo\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 foo"
	if _, err := ReleaseChecksum(dup, "foo"); err == nil {
		t.Fatal("expected error for duplicate checksum")
	}
	// Invalid hex length
	badLen := "1234 foo"
	if _, err := ReleaseChecksum(badLen, "foo"); err == nil {
		t.Fatal("expected error for invalid checksum length")
	}
}
