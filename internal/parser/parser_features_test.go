package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConanFile(t *testing.T) {
	content := `
# Configuration for conan project
[requires]
openssl/3.1.4
zlib/1.3.1@user/channel
fmt/10.1.1#1234abcd5678
boost/1.83.0 # needed for networking

[generators]
CMakeDeps
CMakeToolchain
`
	tmp := filepath.Join(t.TempDir(), "conanfile.txt")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}

	pkgs, err := parseConanFile(tmp)
	if err != nil {
		t.Fatalf("parseConanFile failed: %v", err)
	}

	if len(pkgs) != 4 {
		t.Fatalf("expected 4 packages, got %d", len(pkgs))
	}

	expected := map[string]string{
		"openssl": "3.1.4",
		"zlib":    "1.3.1",
		"fmt":     "10.1.1",
		"boost":   "1.83.0",
	}

	for _, p := range pkgs {
		if p.Ecosystem != "ConanCenter" {
			t.Errorf("expected ConanCenter ecosystem, got %s", p.Ecosystem)
		}
		ver, ok := expected[p.Name]
		if !ok {
			t.Errorf("unexpected package: %s", p.Name)
		} else if ver != p.Version {
			t.Errorf("package %s expected version %s, got %s", p.Name, ver, p.Version)
		}
	}
}

func TestParseConanLock(t *testing.T) {
	content := `{
		"version": "0.5",
		"graph_lock": {
			"nodes": {
				"0": {
					"ref": "myapp/1.0.0"
				},
				"1": {
					"ref": "openssl/3.1.4#f33783a3ec02ba44c4b92b5bbd097241"
				},
				"2": {
					"ref": "zlib/1.3.1#e1d4b1a1"
				}
			}
		}
	}`
	tmp := filepath.Join(t.TempDir(), "conan.lock")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}

	pkgs, err := parseConanLock(tmp)
	if err != nil {
		t.Fatalf("parseConanLock failed: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 dependency packages (excluding node 0 root), got %d", len(pkgs))
	}

	for _, p := range pkgs {
		if p.Ecosystem != "ConanCenter" {
			t.Errorf("expected ConanCenter ecosystem, got %s", p.Ecosystem)
		}
	}
}

func TestParseVcpkg(t *testing.T) {
	content := `{
		"name": "my-application",
		"version-string": "1.0.0",
		"dependencies": [
			"fmt",
			{
				"name": "openssl",
				"version>=": "3.1.0"
			},
			{
				"name": "zlib",
				"version": "1.2.11"
			}
		],
		"overrides": [
			{
				"name": "zlib",
				"version": "1.3.1"
			}
		]
	}`
	tmp := filepath.Join(t.TempDir(), "vcpkg.json")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}

	pkgs, err := parseVcpkg(tmp)
	if err != nil {
		t.Fatalf("parseVcpkg failed: %v", err)
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	pkgMap := make(map[string]string)
	for _, p := range pkgs {
		pkgMap[p.Name] = p.Version
		if p.Ecosystem != "ConanCenter" {
			t.Errorf("expected ConanCenter ecosystem, got %s", p.Ecosystem)
		}
	}

	if pkgMap["zlib"] != "1.3.1" {
		t.Errorf("expected zlib version 1.3.1 (overridden), got %s", pkgMap["zlib"])
	}
	if pkgMap["openssl"] != ">=3.1.0" {
		t.Errorf("expected openssl constraint >=3.1.0, got %s", pkgMap["openssl"])
	}
	if pkgMap["fmt"] != "latest" {
		t.Errorf("expected fmt version latest, got %s", pkgMap["fmt"])
	}
}

func TestParsePyProjectToml(t *testing.T) {
	content := `
[build-system]
requires = ["hatchling>=1.24"]
build-backend = "hatchling.build"

[project]
name = "alpha-miner"
version = "0.1.0"
dependencies = [
  "pydantic>=2.8,<3",
  "lark>=1.1,<2",
  "networkx[default]>=3.2,<4",
  "google-genai>=1.0",
]

[project.optional-dependencies]
dev = [
  "mypy>=1.10",
  "pytest>=8.2",
  "ruff>=0.5",
]
`
	tmp := filepath.Join(t.TempDir(), "pyproject.toml")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}

	pkgs, err := parsePyProjectToml(tmp)
	if err != nil {
		t.Fatalf("parsePyProjectToml failed: %v", err)
	}

	if len(pkgs) != 7 {
		t.Fatalf("expected 7 packages, got %d", len(pkgs))
	}

	expected := map[string]string{
		"pydantic":     ">=2.8,<3",
		"lark":         ">=1.1,<2",
		"networkx":     ">=3.2,<4",
		"google-genai": ">=1.0",
		"mypy":         ">=1.10",
		"pytest":       ">=8.2",
		"ruff":         ">=0.5",
	}

	for _, p := range pkgs {
		if p.Ecosystem != "PyPI" {
			t.Errorf("expected PyPI ecosystem, got %s", p.Ecosystem)
		}
		if ver, ok := expected[p.Name]; !ok {
			t.Errorf("unexpected package %s", p.Name)
		} else if p.Version != ver {
			t.Errorf("package %s expected version %s, got %s", p.Name, ver, p.Version)
		}
	}
}
