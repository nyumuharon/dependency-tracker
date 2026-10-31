package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEPSSMissingInvalidAndZero(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		known      bool
		want       float64
	}{
		{"missing", `{"data":[]}`, false, 0},
		{"unrequested", `{"data":[{"cve":"CVE-2026-99999","epss":"0.2"}]}`, false, 0},
		{"zero", `{"data":[{"cve":"CVE-2026-11111","epss":"0"}]}`, true, 0},
		{"positive", `{"data":[{"cve":"CVE-2026-11111","epss":"0.9"}]}`, true, .9},
		{"invalid", `{"data":[{"cve":"CVE-2026-11111","epss":"bad"}]}`, false, 0},
		{"negative", `{"data":[{"cve":"CVE-2026-11111","epss":"-0.1"}]}`, false, 0},
		{"too-large", `{"data":[{"cve":"CVE-2026-11111","epss":"1.1"}]}`, false, 0},
		{"nan", `{"data":[{"cve":"CVE-2026-11111","epss":"NaN"}]}`, false, 0},
		{"infinite", `{"data":[{"cve":"CVE-2026-11111","epss":"+Inf"}]}`, false, 0},
		{"duplicate", `{"data":[{"cve":"CVE-2026-11111","epss":"0.2"},{"cve":"CVE-2026-11111","epss":"0.3"}]}`, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockHTTP(t, func(r *http.Request) (*http.Response, error) { return response(200, tc.body), nil })
			scores, err := QueryEPSS([]string{"CVE-2026-11111"})
			value, known := scores["CVE-2026-11111"]
			if known != tc.known || value != tc.want || (err == nil) != tc.known {
				t.Fatalf("scores=%v error=%v", scores, err)
			}
			v := Vulnerability{CVEID: "CVE-2026-11111", EPSS: value, EPSSKnown: known}
			data, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if (decoded["EPSS"] != nil) != known {
				t.Fatalf("missing score serialized as zero: %s", data)
			}
			if !known && v.epssDisplay() != "unknown" {
				t.Fatal("missing score not labeled unknown")
			}
			if known && value == 0 && v.epssDisplay() != "0.00000" {
				t.Fatal("confirmed zero not preserved")
			}
		})
	}
}

func TestMalformedInstalledEnvironmentsMakeDiscoveryIncomplete(t *testing.T) {
	for _, tc := range []struct{ name, path, content string }{
		{"python", ".venv/lib/python3.12/site-packages/broken-1.dist-info/METADATA", "Name: broken\n\n"},
		{"python-direct-url", ".venv/lib/python3.12/site-packages/broken-1.dist-info/direct_url.json", "{bad"},
		{"node", "node_modules/broken/package.json", "{bad"},
		{"node-lock-shape", "node_modules/.package-lock.json", "{}"},
		{"dotnet-type", "obj/project.assets.json", `{"libraries":{"example/1.0.0":{}}}`},
		{"composer", "vendor/composer/installed.json", "{bad"},
		{"dotnet", "obj/project.assets.json", "{\"libraries\":{\"invalid\":{\"type\":\"package\"}}}"},
		{"ruby", "vendor/bundle/ruby/3.3.0/specifications/broken.gemspec", "# unreadable version"},
		{"vcpkg", "vcpkg_installed/vcpkg/status", "Package: broken\nStatus: install ok installed\n\n"},
		{"dart", ".dart_tool/package_config.json", `{"packages":[{"name":"broken"}]}`},
		{"go", "vendor/modules.txt", "# example.com/broken bad-version\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "package.json", `{"dependencies":{"safe":"1.0.0"}}`)
			writeFixture(t, root, tc.path, tc.content)
			if tc.name == "python-direct-url" {
				writeFixture(t, root, ".venv/lib/python3.12/site-packages/broken-1.dist-info/METADATA", "Name: broken\nVersion: 1.0\n\n")
			}
			pkgs, _, err := DiscoverDependencies(root)
			var incomplete *DiscoveryError
			if !errors.As(err, &incomplete) {
				t.Fatalf("bad environment was silently ignored: %v", err)
			}
			if !strings.Contains(err.Error(), filepath.Base(tc.path)) {
				t.Fatalf("missing input path: %v", err)
			}
			if len(pkgs) == 0 {
				t.Fatal("readable manifests should be preserved with the error")
			}
		})
	}
}

func TestUnreadableInstalledMetadataIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file mode test")
	}
	root := t.TempDir()
	path := writeFixture(t, root, "node_modules/example/package.json", `{"name":"example","version":"1.0.0"}`)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0600)
	if _, err := os.ReadFile(path); err == nil {
		t.Skip("test account can bypass file permissions")
	}
	if _, _, err := DiscoverDependencies(root); err == nil {
		t.Fatal("unreadable installed package was silently ignored")
	}
}

func TestInstalledMetadataVariantsAndSymlinkCycle(t *testing.T) {
	t.Run("composer-v1-and-v2", func(t *testing.T) {
		for _, body := range []string{`[{"name":"monolog/monolog","version":"v3.7.0"}]`, `{"packages":[{"name":"monolog/monolog","version":"v3.7.0"}]}`} {
			path := writeFixture(t, t.TempDir(), "installed.json", body)
			pkgs, err := inspectComposerInstalled(path)
			if err != nil || len(pkgs) != 1 || pkgs[0].Version != "3.7.0" {
				t.Fatalf("%+v %v", pkgs, err)
			}
		}
	})
	t.Run("ruby", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "bundle/ruby/3.3.0/specifications/rack-3.1.7.gemspec", "# fixture")
		pkgs, err := inspectRubyVendorBundle(root)
		if err != nil || len(pkgs) != 1 || pkgs[0].Name != "rack" {
			t.Fatalf("%+v %v", pkgs, err)
		}
	})
	t.Run("symlink-cycle", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "example/package.json", `{"name":"example","version":"1.0.0"}`)
		nested := filepath.Join(root, "example", "node_modules")
		if err := os.MkdirAll(nested, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "example"), filepath.Join(nested, "cycle")); err != nil {
			t.Skip(err)
		}
		pkgs, err := inspectNodeModules(root)
		if err != nil || len(pkgs) != 1 {
			t.Fatalf("cycle should terminate without losing the package: %+v %v", pkgs, err)
		}
	})
}
