package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

type corpusCase struct {
	Name     string   `json:"name"`
	File     string   `json:"file"`
	Expected []string `json:"expected"`
}

func corpusCases(t testing.TB) []corpusCase {
	t.Helper()
	data, err := os.ReadFile("testdata/corpus/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []corpusCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}
func inventory(pkgs []Package) []string {
	seen := make(map[string]bool)
	var out []string
	for _, p := range pkgs {
		key := p.Ecosystem + "|" + p.Name + "|" + p.Version
		if !seen[key] {
			out = append(out, key)
			seen[key] = true
		}
	}
	sort.Strings(out)
	return out
}
func TestParserAccuracyCorpus(t *testing.T) {
	for _, tc := range corpusCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			path := filepath.Join("testdata/corpus", tc.File)
			pkgs, err := ParseManifest(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := inventory(pkgs); !reflect.DeepEqual(got, tc.Expected) {
				t.Fatalf("inventory mismatch\ngot  %v\nwant %v", got, tc.Expected)
			}
			root := t.TempDir()
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				data, err := os.ReadFile(filepath.Join(filepath.Dir(path), entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				writeFixture(t, root, entry.Name(), string(data))
			}
			pkgs, _, err = DiscoverDependencies(root)
			if err != nil {
				t.Fatal(err)
			}
			if got := inventory(pkgs); !reflect.DeepEqual(got, tc.Expected) {
				t.Fatalf("directory discovery mismatch\ngot %v\nwant %v", got, tc.Expected)
			}
		})
	}
}

// npm computes its own dependency tree from the fixture's lockfile. This is an
// independent offline reference, rather than expected data derived by our parser.
func TestNpmInventoryAgainstPackageManager(t *testing.T) {
	npm, err := exec.LookPath("npm")
	if err != nil {
		if os.Getenv("REQUIRE_NPM_REFERENCE") == "1" {
			t.Fatal(err)
		}
		t.Skip("npm is not installed")
	}
	root, err := filepath.Abs("testdata/corpus/npm-v3")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(npm, "ls", "--package-lock-only", "--all", "--json", "--offline", "--ignore-scripts", "--prefix", root)
	cmd.Env = append(os.Environ(), "npm_config_cache="+t.TempDir(), "npm_config_update_notifier=false")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("npm reference failed: %v: %s", err, output)
	}
	type tree struct {
		Name         string                     `json:"name"`
		Version      string                     `json:"version"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	var top tree
	if err := json.Unmarshal(output, &top); err != nil {
		t.Fatal(err)
	}
	var reference []Package
	var visit func(map[string]json.RawMessage)
	visit = func(deps map[string]json.RawMessage) {
		for name, raw := range deps {
			var node tree
			if err := json.Unmarshal(raw, &node); err != nil {
				t.Fatal(err)
			}
			reference = append(reference, Package{Name: name, Version: node.Version, Ecosystem: "npm"})
			visit(node.Dependencies)
		}
	}
	visit(top.Dependencies)
	actual, err := ParseManifest(filepath.Join(root, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inventory(actual), inventory(reference)) {
		t.Fatalf("npm disagreement: tracker=%v npm=%v", inventory(actual), inventory(reference))
	}
}

// Set SYFT_BINARY to an independently installed Syft to compare the same fixture
// against its SBOM inventory. This test performs no network requests.
func TestNpmInventoryAgainstSyft(t *testing.T) {
	syft := os.Getenv("SYFT_BINARY")
	if syft == "" {
		t.Skip("SYFT_BINARY not configured")
	}
	root, err := filepath.Abs("testdata/corpus/npm-v3")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(syft, "scan", "dir:"+root, "-o", "syft-json", "--quiet")
	cmd.Env = append(os.Environ(), "SYFT_CHECK_FOR_APP_UPDATE=false", "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Syft reference failed: %v: %s", err, output)
	}
	var bom struct {
		Artifacts []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(output, &bom); err != nil {
		t.Fatal(err)
	}
	var reference []Package
	for _, p := range bom.Artifacts {
		if p.Type == "npm" && p.Name != "fixture-root" {
			reference = append(reference, Package{Name: p.Name, Version: p.Version, Ecosystem: "npm"})
		}
	}
	actual, err := ParseManifest(filepath.Join(root, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inventory(actual), inventory(reference)) {
		t.Fatalf("Syft disagreement: tracker=%v syft=%v", inventory(actual), inventory(reference))
	}
}

func BenchmarkParserCorpus(b *testing.B) {
	for _, tc := range corpusCases(b) {
		b.Run(tc.Name, func(b *testing.B) {
			path := filepath.Join("testdata/corpus", tc.File)
			b.ReportAllocs()
			for b.Loop() {
				pkgs, err := ParseManifest(path)
				if err != nil {
					b.Fatal(err)
				}
				if len(pkgs) == 0 {
					b.Fatal("empty inventory")
				}
			}
		})
	}
}
