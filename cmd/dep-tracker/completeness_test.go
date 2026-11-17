package main

import (
	"encoding/json"
	"net/http"
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
			if !known && v.EPSSDisplay() != "unknown" {
				t.Fatal("missing score not labeled unknown")
			}
			if known && value == 0 && v.EPSSDisplay() != "0.00000" {
				t.Fatal("confirmed zero not preserved")
			}
		})
	}
}
