package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Opt-in integration test: public clones stay outside the source tree. The
// report records exact commits and differences rather than hiding mismatches.
func TestRealWorldInventories(t *testing.T) {
	root := os.Getenv("REALWORLD_ROOT")
	syft := os.Getenv("SYFT_BINARY")
	if root == "" || syft == "" {
		t.Skip("REALWORLD_ROOT and SYFT_BINARY required")
	}
	type comparison struct {
		Name, Commit, Manifest string
		Tracker, Reference     int
		Missing, Extra         []string
		Duration               string
	}
	var report []comparison
	for _, tc := range []struct {
		name, file, eco, kind string
		companions            []string
	}{
		{"axios", "package-lock.json", "npm", "npm", nil},
		{"gin", "go.mod", "Go", "go-module", []string{"go.sum"}},
		{"bat", "Cargo.lock", "crates.io", "rust-crate", []string{"Cargo.toml"}},
		{"poetry", "poetry.lock", "PyPI", "python", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			project := filepath.Join(root, tc.name)
			revision, err := exec.Command("git", "-C", project, "rev-parse", "HEAD").Output()
			if err != nil {
				t.Fatal(err)
			}
			actual, err := ParseManifest(filepath.Join(project, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			stage := t.TempDir()
			for _, name := range append([]string{tc.file}, tc.companions...) {
				data, err := os.ReadFile(filepath.Join(project, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(stage, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(syft, "scan", "dir:"+stage, "-o", "syft-json", "--quiet")
			cmd.Env = append(os.Environ(), "SYFT_CHECK_FOR_APP_UPDATE=false", "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true")
			output, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			var bom struct {
				Artifacts []struct{ Name, Version, Type string } `json:"artifacts"`
			}
			if err := json.Unmarshal(output, &bom); err != nil {
				t.Fatal(err)
			}
			got, want := make(map[string]bool), make(map[string]bool)
			var application struct{ Name, Version string }
			if tc.kind == "npm" {
				raw, err := os.ReadFile(filepath.Join(project, tc.file))
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(raw, &application); err != nil {
					t.Fatal(err)
				}
			}
			normalize := func(name string) string {
				if tc.eco == "PyPI" {
					return strings.ReplaceAll(strings.ToLower(name), "_", "-")
				}
				return name
			}
			for _, p := range actual {
				got[normalize(p.Name)+"@"+p.Version] = true
			}
			for _, p := range bom.Artifacts {
				if p.Type == tc.kind && p.Name != "stdlib" && !(tc.kind == "npm" && p.Name == application.Name && p.Version == application.Version) {
					want[normalize(p.Name)+"@"+p.Version] = true
				}
			}
			row := comparison{Name: tc.name, Commit: strings.TrimSpace(string(revision)), Manifest: tc.file, Tracker: len(got), Reference: len(want), Duration: time.Since(start).String()}
			for key := range want {
				if !got[key] {
					row.Missing = append(row.Missing, key)
				}
			}
			for key := range got {
				if !want[key] {
					row.Extra = append(row.Extra, key)
				}
			}
			sort.Strings(row.Missing)
			sort.Strings(row.Extra)
			report = append(report, row)
			t.Logf("tracker=%d reference=%d missing=%d extra=%d", row.Tracker, row.Reference, len(row.Missing), len(row.Extra))
			if len(row.Missing) > 0 || len(row.Extra) > 0 {
				t.Errorf("inventory mismatch: missing=%v extra=%v", row.Missing, row.Extra)
			}
		})
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "inventory-comparison.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
