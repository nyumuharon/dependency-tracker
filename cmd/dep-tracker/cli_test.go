package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	// update --version accepts both spellings; anything else is a usage error.
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return response(200, fmt.Sprintf(`{"tag_name":%q}`, "v"+appVersion)), nil
	})
	for args, want := range map[string]int{"update --version " + appVersion: 0, "update --version=" + appVersion: 0, "update --force": 1, "update --version": 1} {
		if got := run(strings.Fields(args)); got != want {
			t.Errorf("%s: exit=%d want=%d", args, got, want)
		}
	}
}

func TestCLIEqualsOptions(t *testing.T) {
	opts, path, err := parseArgs([]string{"scan", ".", "--sbom", "bom.json", "--sarif=results.sarif"})
	if err != nil || path != "." || opts.sbomPath != "bom.json" || opts.sarifPath != "results.sarif" {
		t.Fatalf("%+v %s %v", opts, path, err)
	}
}

func TestUpdaterDelegationWrappers(t *testing.T) {
	opts := defaultUpdater()
	opts.ApiURL = "http://127.0.0.1:0/invalid"
	_ = runUpdateWith(opts)
}

