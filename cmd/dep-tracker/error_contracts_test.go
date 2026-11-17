package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

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
	if v := (Vulnerability{CVEID: "GHSA-example"}).EPSSDisplay(); !strings.Contains(v, "not applicable") {
		t.Fatal(v)
	}
}
