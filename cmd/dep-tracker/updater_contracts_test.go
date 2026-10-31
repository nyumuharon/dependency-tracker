package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestUpdaterPlatformAndFailureContracts(t *testing.T) {
	cases := []struct {
		name, platform string
		fail           bool
	}{
		{"linux-success", "linux", false}, {"darwin-success", "darwin", false}, {"windows-success", "windows", false},
		{"windows-backup-failure", "windows", true}, {"windows-install-failure", "windows", true},
		{"chmod-failure", "linux", true}, {"rename-failure", "linux", true}, {"permission-failure", "linux", true},
		{"executable-failure", "linux", true}, {"symlink-failure", "linux", true}, {"unsupported-platform", "plan9", true},
		{"api-request-failure", "linux", true}, {"api-network-failure", "linux", true}, {"api-status-failure", "linux", true},
		{"api-json-failure", "linux", true}, {"invalid-version", "linux", true}, {"current-version", "linux", false},
		{"old-version", "linux", false}, {"checksum-failure", "linux", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			exe := writeFixture(t, root, "dep-tracker", "original executable")
			sum := sha256.Sum256([]byte("verified new executable"))
			hash := hex.EncodeToString(sum[:])
			options := defaultUpdater()
			options.platform = tc.platform
			options.arch = "amd64"
			options.apiURL = "https://api.example/latest"
			options.releaseBase = "https://releases.example"
			options.executable = func() (string, error) {
				if tc.name == "executable-failure" {
					return "", errors.New("executable unavailable")
				}
				return exe, nil
			}
			options.resolve = func(p string) (string, error) {
				if tc.name == "symlink-failure" {
					return "", errors.New("broken link")
				}
				return p, nil
			}
			realRename := options.fs.rename
			options.fs.rename = func(old, new string) error {
				if tc.name == "windows-backup-failure" && old == exe {
					return errors.New("backup failed")
				}
				if tc.name == "windows-install-failure" && strings.Contains(old, ".dep-tracker-update-") {
					return errors.New("install failed")
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
				options.fs.chmod = func(string, os.FileMode) error { return errors.New("chmod failed") }
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
			options.apiClient = client
			options.downloadClient = client
			if tc.name == "api-request-failure" {
				options.apiURL = "\ninvalid"
			}
			err := runUpdateWith(options)
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected update outcome: %v", err)
			}
			data, readErr := os.ReadFile(exe)
			if readErr != nil {
				t.Fatal(readErr)
			}
			upgraded := !tc.fail && tc.name != "current-version" && tc.name != "old-version"
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

func TestCLICommandsAndProcessExit(t *testing.T) {
	oldArgs, oldExit := os.Args, exitProcess
	t.Cleanup(func() { os.Args = oldArgs; exitProcess = oldExit })
	for _, args := range [][]string{{"help"}, {"version"}, {"--help"}, {"-h"}, {"--version"}, {"-v"}} {
		if code := run(args); code != 0 {
			t.Errorf("%v: %d", args, code)
		}
	}
	if code := run(nil); code != 1 {
		t.Fatalf("missing command: %d", code)
	}
	if code := run([]string{"scan", "--invalid"}); code != 1 {
		t.Fatal("invalid arguments")
	}
	if code := run([]string{"scan", filepath.Join(t.TempDir(), "missing")}); code != 1 {
		t.Fatal("missing target")
	}
	os.Args = []string{"dep-tracker", "version"}
	called := false
	exitProcess = func(code int) {
		called = true
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	}
	main()
	if !called {
		t.Fatal("main did not forward the command result")
	}
	oldTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	for _, status := range []int{200, 503} {
		http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return response(status, fmt.Sprintf(`{"tag_name":%q}`, appVersion)), nil
		})
		got := run([]string{"update"})
		want := 0
		if status != 200 {
			want = 1
		}
		if got != want {
			t.Fatalf("update exit=%d want=%d", got, want)
		}
	}
}
