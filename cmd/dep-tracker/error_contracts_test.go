package main

import (
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsersRejectUnreadableInputs(t *testing.T) {
	parsers := map[string]func(string) ([]Package, error){
		"npm": parseNPM, "python": parsePyPI, "maven": parseMaven, "nuget": parseNuGet, "go-mod": parseGoMod, "cargo-lock": parseCargoLock, "cargo-toml": parseCargoToml, "composer": parseComposer, "ruby": parseRubyGem, "npm-lock": parseNPMLock, "yarn": parseYarnLock, "pnpm": parsePnpmLock, "pyproject": parsePyProjectToml, "poetry": parsePoetryLock, "pipfile": parsePipfileLock, "composer-lock": parseComposerLock, "go-sum": parseGoSum, "nuget-lock": parseNuGetLock, "conan": parseConanFile, "conan-lock": parseConanLock, "vcpkg": parseVcpkg, "content": parseByContent,
	}
	missing := filepath.Join(t.TempDir(), "missing")
	for name, parse := range parsers {
		t.Run(name, func(t *testing.T) {
			if _, err := parse(missing); err == nil {
				t.Fatal("unreadable manifest must return an error")
			}
		})
	}
}

func TestStructuredParsersRejectMalformedData(t *testing.T) {
	for name, parse := range map[string]func(string) ([]Package, error){"npm": parseNPM, "maven": parseMaven, "nuget": parseNuGet, "composer": parseComposer, "npm-lock": parseNPMLock, "pipfile": parsePipfileLock, "composer-lock": parseComposerLock, "nuget-lock": parseNuGetLock, "conan-lock": parseConanLock, "vcpkg": parseVcpkg} {
		t.Run(name, func(t *testing.T) {
			path := writeFixture(t, t.TempDir(), "invalid", `{ "incomplete":`)
			if _, err := parse(path); err == nil {
				t.Fatal("malformed manifest must return an error")
			}
		})
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (failingBody) Close() error             { return nil }

func TestIntelligenceNetworkAndDecodeFailures(t *testing.T) {
	queries := map[string]func() error{
		"osv": func() error {
			_, err := QueryOSV(Package{Name: "example", Version: "1.0.0", Ecosystem: "npm"})
			return err
		},
		"osv-batch": func() error {
			_, err := QueryOSVBatch([]Package{{Name: "example", Version: "1.0.0", Ecosystem: "npm"}})
			return err
		},
		"epss": func() error { _, err := QueryEPSS([]string{"CVE-2026-11111"}); return err },
	}
	for name, query := range queries {
		for _, mode := range []string{"transport", "decode"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				mockHTTP(t, func(r *http.Request) (*http.Response, error) {
					if mode == "transport" {
						return nil, errors.New("connection refused")
					}
					return response(200, "not JSON"), nil
				})
				if err := query(); err == nil {
					t.Fatal("unavailable intelligence must return an error")
				}
			})
		}
	}
}

func TestVersionOrderingBoundaryForms(t *testing.T) {
	for _, tc := range []struct {
		a, b, eco string
		want      int
		ok        bool
	}{
		{"1.0.0", "invalid", "npm", 0, false}, {"184467440737095516160.0.0", "1.0.0", "npm", 0, false},
		{"1.0", "1.0.0", "npm", 0, false}, {"1", "1.0.0", "PyPI", 0, true}, {"2.0.0", "1.0.0", "npm", 1, true},
		{"1.0.0-alpha.2", "1.0.0-alpha.1", "npm", 1, true}, {"1.0.0-2", "1.0.0-alpha", "npm", -1, true},
		{"1.0.0-alpha", "1.0.0-2", "npm", 1, true}, {"1.0.0-beta", "1.0.0-alpha", "npm", 1, true},
		{"1.0.0-alpha", "1.0.0-alpha.1", "npm", -1, true}, {"1.0.0-alpha.1", "1.0.0-alpha", "npm", 1, true},
	} {
		got, ok := compareVersions(tc.a, tc.b, tc.eco)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("%+v: got %v,%v", tc, got, ok)
		}
	}
	for _, name := range []string{"package.json", "build.gradle", "project.fsproj", "project.vbproj"} {
		if !isNamedDependencyFile(name) {
			t.Error(name)
		}
	}
	if isNamedDependencyFile("random.cfg") {
		t.Fatal("unrelated configuration must not be treated as a manifest")
	}
	if normalizeExactPin(" =1.0.0 ", "npm") != "1.0.0" {
		t.Fatal("equality pin")
	}
	if v := (Vulnerability{CVEID: "GHSA-example"}).epssDisplay(); !strings.Contains(v, "not applicable") {
		t.Fatal(v)
	}
}
