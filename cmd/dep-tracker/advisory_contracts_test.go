package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
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

func TestFixedReleaseWithQualifiedIntroducedVersion(t *testing.T) {
	cases := []struct{ scanned, introduced, want string }{
		{"2.24.0", "2.0-beta9", "2.25.3"}, // later numeric release than the qualified introduction
		{"2.24.0", "2.24.0-beta1", ""},    // same numeric release: qualifier ordering is not guessed
		{"2.24.0", "2.25.0-beta1", ""},    // before the introduction
		{"2.24.0", "-beta", ""},           // no numeric release to compare
		{"2.24.0", "release", ""},         // unordered without a qualifier
		{"2.24.0", "2.0", "2.25.3"},       // plain versions keep their existing ordering
		{"2.24.0", "0", "2.25.3"},
	}
	for _, tc := range cases {
		var v osvVulnerability
		body := fmt.Sprintf(`{"affected":[{"package":{"name":"org.example:lib","ecosystem":"Maven"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":%q},{"fixed":"2.25.3"}]}]}]}`, tc.introduced)
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		pkg := Package{Name: "org.example:lib", Version: tc.scanned, Ecosystem: "Maven"}
		if got := fixedRelease(v, pkg); got != tc.want {
			t.Errorf("scanned %s, introduced %s: fixed release %q, want %q", tc.scanned, tc.introduced, got, tc.want)
		}
	}
}

func TestMavenStalenessUsesNewestPublishedVersion(t *testing.T) {
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("core") != "gav" {
			t.Errorf("Maven staleness must query individual versions: %s", r.URL)
		}
		return response(200, fmt.Sprintf(`{"response":{"docs":[{"v":"2.26.0","timestamp":%d}]}}`, time.Now().UnixMilli())), nil
	})
	result, err := checkMavenStaleness("org.example:lib")
	if err != nil || result.LatestVersion != "2.26.0" || result.IsStale {
		t.Fatalf("newest published version not used: %+v %v", result, err)
	}
}

func TestUnscoredAdvisoriesUseDatabaseRatingOrStayUnknown(t *testing.T) {
	for label, want := range map[string]string{"low": "LOW", " Moderate ": "MEDIUM", "MEDIUM": "MEDIUM", "high": "HIGH", "CRITICAL": "CRITICAL", "severe": "", "": ""} {
		if got := normalizeSeverityLabel(label); got != want {
			t.Errorf("label %q normalised to %q, want %q", label, got, want)
		}
	}
	cases := []struct {
		name  string
		vulns []Vulnerability
		want  string
	}{
		{"no score and no rating", []Vulnerability{{CVEID: "CVE-2026-1"}}, "UNKNOWN"},
		{"rated low", []Vulnerability{{CVEID: "GHSA-a", Severity: "LOW"}}, "LOW"},
		{"rated medium", []Vulnerability{{CVEID: "GHSA-a", Severity: "MEDIUM"}}, "MEDIUM"},
		{"rated high", []Vulnerability{{CVEID: "GHSA-a", Severity: "HIGH"}}, "HIGH"},
		{"rated critical", []Vulnerability{{CVEID: "GHSA-a", Severity: "CRITICAL"}}, "HIGH"},
		{"rated high and likely exploited", []Vulnerability{{CVEID: "CVE-2026-1", Severity: "HIGH", EPSS: 0.5, EPSSKnown: true}}, "CRITICAL-EXPLOITABLE"},
		{"score wins over rating", []Vulnerability{{CVEID: "CVE-2026-1", CVSS: 5, Severity: "CRITICAL"}}, "MEDIUM"},
		{"known tier kept beside an unscored advisory", []Vulnerability{{CVEID: "CVE-2026-1", CVSS: 2}, {CVEID: "CVE-2026-2"}}, "LOW"},
		{"unscored but in KEV", []Vulnerability{{CVEID: "CVE-2026-1", IsKEV: true}}, "CRITICAL-EXPLOITABLE"},
	}
	for _, tc := range cases {
		if got := ScoreVulnerabilities(tc.vulns); got != tc.want {
			t.Errorf("%s: tier %s, want %s", tc.name, got, tc.want)
		}
	}
	for v, want := range map[Vulnerability]string{{CVSS: 7.5, Severity: "LOW"}: "7.5", {Severity: "HIGH"}: "unscored, rated HIGH", {}: "unknown"} {
		if got := v.CVSSDisplay(); got != want {
			t.Errorf("%+v displayed as %q, want %q", v, got, want)
		}
	}
}

func TestParseVulnsReadsAndMergesDatabaseRating(t *testing.T) {
	var res osvResponse
	body := `{"vulns":[
 {"id":"GHSA-rated","database_specific":{"severity":"MODERATE"}},
 {"id":"GHSA-odd","database_specific":{"severity":{"level":"high"}}},
 {"id":"GHSA-one","aliases":["CVE-2026-33333"],"database_specific":{"severity":"LOW"}},
 {"id":"PYSEC-two","aliases":["CVE-2026-33333"],"database_specific":{"severity":"HIGH"}},
 {"id":"OTHER-three","aliases":["CVE-2026-33333"]}]}`
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	vulns := parseVulns(res, Package{Name: "example", Version: "1.0.0", Ecosystem: "PyPI"})
	if len(vulns) != 3 || vulns[0].Severity != "MEDIUM" || vulns[1].Severity != "" || vulns[2].Severity != "HIGH" {
		t.Fatalf("database ratings not read or merged: %+v", vulns)
	}
}

func TestAdvisoryNoticesWithdrawalsAndAliasMerging(t *testing.T) {
	var res osvResponse
	body := `{"vulns":[
 {"id":"RUSTSEC-2025-0025","affected":[{"package":{"name":"demo","ecosystem":"crates.io"},"database_specific":{"informational":"unmaintained"}}]},
 {"id":"RUSTSEC-2025-0100","affected":[{"package":{"name":"other","ecosystem":"crates.io"},"database_specific":{"informational":"unmaintained"}}]},
 {"id":"RUSTSEC-2025-0200","affected":[{"package":{"name":"demo","ecosystem":"crates.io"},"database_specific":{"informational":"unsound"}}]},
 {"id":"GHSA-old","withdrawn":"2024-01-01T00:00:00Z"},
 {"id":"RUSTSEC-2022-0004","aliases":["GHSA-2226-4v3c-cff8"]},
 {"id":"GHSA-2226-4v3c-cff8","aliases":["RUSTSEC-2022-0004","CVE-2022-99999"],"database_specific":{"severity":"MODERATE"}}]}`
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	vulns := parseVulns(res, Package{Name: "demo", Version: "1.0.0", Ecosystem: "crates.io"})
	var ids []string
	for _, v := range vulns {
		ids = append(ids, v.ID+"/"+v.CVEID+"/"+v.Severity)
	}
	want := []string{"RUSTSEC-2025-0100/RUSTSEC-2025-0100/", "RUSTSEC-2025-0200/RUSTSEC-2025-0200/", "RUSTSEC-2022-0004/CVE-2022-99999/MEDIUM"}
	if strings.Join(ids, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v, want %v", ids, want)
	}
}

func TestStalenessUsesReleaseDates(t *testing.T) {
	recent := time.Now().UTC().Add(-24 * time.Hour)
	old := "2000-01-01T00:00:00Z"
	t.Run("nuget-pages-and-prereleases", func(t *testing.T) {
		mockHTTP(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/page/2.json") {
				return response(200, fmt.Sprintf(`{"items":[{"catalogEntry":{"version":"2.0.0","published":%q}},{"catalogEntry":{"version":"2.1.0","published":%q,"listed":false}},{"catalogEntry":{"version":"3.0.0-beta1","published":%q}}]}`, recent.Format(time.RFC3339), old, old)), nil
			}
			return response(200, `{"items":[{"upper":"1.0.0","items":[{"catalogEntry":{"version":"1.0.0","published":"2000-01-01T00:00:00Z"}}]},{"@id":"https://api.nuget.org/page/2.json","upper":"3.0.0-beta1"}]}`), nil
		})
		res, err := checkNuGetStaleness("Example")
		if err != nil || res.LatestVersion != "2.0.0" || res.IsStale || res.LastUpdated.IsZero() {
			t.Fatalf("%+v %v", res, err)
		}
		mockHTTP(t, func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, "/page/") {
				return response(500, ""), nil
			}
			return response(200, `{"items":[{"@id":"https://api.nuget.org/page/2.json","upper":"3.0.0"}]}`), nil
		})
		if _, err := checkNuGetStaleness("Example"); err == nil {
			t.Fatal("unavailable page accepted")
		}
		mockHTTP(t, func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, "/page/") {
				return nil, errors.New("offline")
			}
			return response(200, `{"items":[{"@id":"https://api.nuget.org/page/2.json"},{"items":[{"catalogEntry":{"version":"1.0.0-rc1"}}]}]}`), nil
		})
		if _, err := checkNuGetStaleness("Example"); err == nil {
			t.Fatal("offline page accepted")
		}
		mockHTTP(t, func(r *http.Request) (*http.Response, error) {
			return response(200, `{"items":[{"items":[{"catalogEntry":{"version":"1.0.0-rc1"}}]}]}`), nil
		})
		if res, err := checkNuGetStaleness("Example"); err != nil || res.LatestVersion != "" {
			t.Fatalf("prerelease-only package: %+v %v", res, err)
		}
	})
	t.Run("crates-without-matching-version", func(t *testing.T) {
		mockHTTP(t, func(r *http.Request) (*http.Response, error) {
			return response(200, `{"crate":{"max_version":"2.0.0-rc1"},"versions":[{"num":"2.0.0-rc1","created_at":"bad"}]}`), nil
		})
		if res, err := checkCratesStaleness("example"); err != nil || res.LatestVersion != "2.0.0-rc1" || !res.LastUpdated.IsZero() {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("conan-first-revision", func(t *testing.T) {
		mockHTTP(t, func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, "/revisions") {
				return response(200, `{"revisions":[{"time":"2025-12-09T12:51:39.337+0000"},{"time":"2019-02-22T09:20:06.497+0000"},{"time":"bad"}]}`), nil
			}
			return response(200, "sources:\n  \"1.3.1\":\n    url: x\nversions:\n  \"1.3.1\":\n    folder: all\n"), nil
		})
		res, err := checkConanStaleness("zlib")
		if err != nil || res.LatestVersion != "1.3.1" || res.LastUpdated.Year() != 2019 || !res.IsStale {
			t.Fatalf("%+v %v", res, err)
		}
		for _, failure := range []func(*http.Request) (*http.Response, error){
			func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") },
			func(*http.Request) (*http.Response, error) { return response(404, ""), nil },
			func(*http.Request) (*http.Response, error) { return response(200, "invalid"), nil },
		} {
			mockHTTP(t, func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, "/revisions") {
					return failure(r)
				}
				return response(200, "versions:\n  \"1.3.1\":\n    folder: all\n"), nil
			})
			if res, err := checkConanStaleness("zlib"); err == nil || res.LatestVersion != "1.3.1" {
				t.Fatalf("revision failure accepted: %+v %v", res, err)
			}
		}
	})
}
