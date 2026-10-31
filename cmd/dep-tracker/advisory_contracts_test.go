package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestAdvisoryMetadataMergeAndRangeBoundaries(t *testing.T) {
	var response osvResponse
	body := `{"vulns":[
 {"id":"GHSA-first","aliases":["CVE-2026-11111"]},
 {"id":"GHSA-rich","aliases":["OTHER","CVE-2026-11111"],"summary":"Rich summary","severity":[{"type":"CVSS_V4","score":"unsupported"},{"type":"CVSS_V3","score":"9.8"}],"affected":[{"package":{"name":"example","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"3.0.0"},{"introduced":"0"},{"fixed":"2.0.0"}]}]}]},
 {"id":"GHSA-lower","aliases":["CVE-2026-11111"],"severity":[{"type":"CVSS_V3","score":"7.5"}]},
 {"id":"GHSA-details","details":" First line\nSecond line","affected":[{"package":{"name":"example","ecosystem":"npm"},"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]},
 {"id":"GHSA-closed","affected":[{"package":{"name":"example","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"0.5.0"},{"fixed":"2.0.0"}]}]}]}
 ]}`
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}
	vulns := parseVulns(response, Package{Name: "example", Version: "1.0.0", Ecosystem: "npm"})
	if len(vulns) != 3 || vulns[0].CVSS != 9.8 || vulns[0].Summary != "Rich summary" || vulns[0].FixedVersion != "2.0.0" {
		t.Fatalf("rich metadata lost: %+v", vulns)
	}
	if vulns[1].Summary != "First line" || vulns[1].FixedVersion != "" || vulns[2].FixedVersion != "" {
		t.Fatalf("unsupported/closed range invented a fix: %+v", vulns)
	}
}

func TestOSVQueryVersionValidationAndBatchChunks(t *testing.T) {
	p := Package{Name: "example", Version: "^1.0.0", Ecosystem: "npm", VersionSource: "constraint"}
	if _, err := QueryOSV(p); err == nil {
		t.Fatal("unresolved query accepted")
	}
	if _, err := QueryOSVBatch([]Package{p}); err == nil {
		t.Fatal("unresolved batch accepted")
	}
	calls := 0
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		calls++
		var batch osvBatchQuery
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			return nil, err
		}
		results := make([]map[string]any, len(batch.Queries))
		for i := range results {
			results[i] = map[string]any{}
		}
		body, err := json.Marshal(map[string]any{"results": results})
		if err != nil {
			return nil, err
		}
		return response(200, string(body)), nil
	})
	pkgs := make([]Package, 1001)
	for i := range pkgs {
		pkgs[i] = Package{Name: fmt.Sprintf("example-%d", i), Version: "1.0.0", Ecosystem: "npm"}
	}
	results, err := QueryOSVBatch(pkgs)
	if err != nil || len(results) != 1001 || calls != 2 {
		t.Fatalf("batch boundary: results=%d calls=%d err=%v", len(results), calls, err)
	}
}

func TestCVSSPrivilegeMonotonicityAndInvalidNumbers(t *testing.T) {
	for _, scope := range []string{"U", "C"} {
		previous := 11.0
		for _, privilege := range []string{"N", "L", "H"} {
			vector := fmt.Sprintf("CVSS:3.1/AV:N/AC:L/PR:%s/UI:N/S:%s/C:H/I:H/A:H", privilege, scope)
			score := parseCVSSVector(vector)
			if score <= 0 || score > 10 || score > previous {
				t.Fatalf("privilege score ordering: %s -> %.1f after %.1f", vector, score, previous)
			}
			previous = score
		}
	}
	for _, bad := range []string{"NaN", "+Inf", "-1", "12.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"} {
		if score := parseCVSSVector(bad); score != 0 {
			t.Errorf("invalid score accepted: %s -> %v", bad, score)
		}
	}
}
