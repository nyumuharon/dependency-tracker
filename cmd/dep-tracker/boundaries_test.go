package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestCLIArguments(t *testing.T) {
	for _, tc := range []struct {
		name              string
		args              []string
		path, sbom, sarif string
		json, stale, fail bool
	}{
		{name: "defaults", args: []string{"scan", "."}, path: ".", sbom: "sbom.json", sarif: "results.sarif"},
		{name: "implicit-scan", args: []string{"project"}, path: "project", sbom: "sbom.json", sarif: "results.sarif"},
		{name: "all-options", args: []string{"scan", "--json", "--sbom=reports/bom.json", "project", "--sarif", "reports/result.sarif", "--stale-only"}, path: "project", sbom: "reports/bom.json", sarif: "reports/result.sarif", json: true, stale: true},
		{name: "missing-path", args: []string{"scan"}, fail: true},
		{name: "extra-path", args: []string{"scan", "a", "b"}, fail: true},
		{name: "missing-sbom-value", args: []string{"scan", ".", "--sbom"}, fail: true},
		{name: "missing-sarif-value", args: []string{"scan", ".", "--sarif"}, fail: true},
		{name: "unknown-option", args: []string{"scan", ".", "--typo"}, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, path, err := parseArgs(tc.args)
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if tc.fail {
				return
			}
			if path != tc.path || opts.sbomPath != tc.sbom || opts.sarifPath != tc.sarif || opts.jsonOut != tc.json || opts.staleOnly != tc.stale {
				t.Fatalf("unexpected options: %+v, path %q", opts, path)
			}
		})
	}
}

func TestRiskPolicyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		cvss, epss float64
		kev        bool
		want       string
	}{
		{0, 0, false, "LOW"}, {3.9, 1, false, "LOW"}, {4, 0, false, "MEDIUM"}, {6.9, 1, false, "MEDIUM"},
		{7, .19999, false, "HIGH"}, {7, .2, false, "CRITICAL-EXPLOITABLE"}, {0, 0, true, "CRITICAL-EXPLOITABLE"},
	} {
		if got := Score(tc.cvss, tc.epss, true, tc.kev); got != tc.want {
			t.Errorf("%+v: got %s", tc, got)
		}
	}
	if got := ScoreVulnerabilities(nil); got != "NONE" {
		t.Fatalf("empty findings: %s", got)
	}
}

func TestCVSSVectorValidationAndKnownScores(t *testing.T) {
	for _, tc := range []struct {
		vector string
		want   float64
	}{
		{"9.8", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
		{"CVSS:3.1/AV:N/AC:L/PR:INVALID/UI:N/S:U/C:H/I:H/A:H", 0},
		{"CVSS:3.1/AV:INVALID/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0},
		{"CVSS:3.1/AV:N", 0}, {"not-a-vector", 0},
	} {
		if got := parseCVSSVector(tc.vector); got != tc.want {
			t.Errorf("%s: got %.1f, want %.1f", tc.vector, got, tc.want)
		}
	}
}

func TestEPSSBatchingAndPartialFailure(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		t.Run(fmt.Sprint(failSecond), func(t *testing.T) {
			var batches []int
			mockHTTP(t, func(r *http.Request) (*http.Response, error) {
				ids := strings.Split(r.URL.Query().Get("cve"), ",")
				batches = append(batches, len(ids))
				if failSecond && len(batches) == 2 {
					return response(http.StatusServiceUnavailable, `{}`), nil
				}
				data := []map[string]string{}
				for _, id := range ids {
					data = append(data, map[string]string{"cve": id, "epss": "0.25"})
				}
				body, err := json.Marshal(map[string]any{"data": data})
				if err != nil {
					return nil, err
				}
				return response(http.StatusOK, string(body)), nil
			})
			ids := make([]string, 101)
			for i := range ids {
				ids[i] = fmt.Sprintf("CVE-2026-%05d", i)
			}
			scores, err := QueryEPSS(ids)
			if failSecond {
				if err == nil || len(scores) != 50 {
					t.Fatalf("expected explicit failure preserving first batch: %d, %v", len(scores), err)
				}
				return
			}
			if err != nil || len(scores) != 101 || fmt.Sprint(batches) != "[50 50 1]" {
				t.Fatalf("wrong batching: %v, %d scores, %v", batches, len(scores), err)
			}
			if scores[ids[100]] != .25 {
				t.Fatal("last batch score lost")
			}
		})
	}
}
