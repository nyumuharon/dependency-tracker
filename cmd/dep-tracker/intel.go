package main

import (
	"net/http"

	"github.com/nyumuharon/dependency-tracker/internal/intel"
)

type KEVEntry = intel.KEVEntry
type osvResponse = intel.OSVResponse

var nvdMaxAttempts = intel.NVDMaxAttempts

func SaveNVDCache() {
	intel.SaveNVDCache()
}

func SaveStalenessCache() {
	intel.SaveStalenessCache()
}

func parseVulns(res osvResponse, pkg Package) []Vulnerability {
	return intel.ParseVulns(res, pkg)
}

func parseCVSSVector(vector string) float64 {
	return intel.ParseCVSSVector(vector)
}

func parseKEVData(data []byte) (map[string]KEVEntry, error) {
	return intel.ParseKEVData(data)
}

func QueryOSVBatch(packages []Package) (map[string][]Vulnerability, error) {
	return intel.QueryOSVBatch(packages)
}

func QueryOSV(pkg Package) ([]Vulnerability, error) {
	return intel.QueryOSV(pkg)
}

func QueryNVD(cveID string) (float64, error) {
	return intel.QueryNVD(cveID)
}

func QueryEPSS(cveIDs []string) (map[string]float64, error) {
	return intel.QueryEPSS(cveIDs)
}

func FetchKEVCatalog() (map[string]KEVEntry, error) {
	return intel.FetchKEVCatalog()
}

func CheckStaleness(pkg Package) (StalenessResult, error) {
	return intel.CheckStaleness(pkg)
}

func resetIntelCaches() {
	intel.ResetCaches()
}

func setIntelHTTPClient(c *http.Client) *http.Client {
	return intel.SetHTTPClient(c)
}

func disableIntelRateLimit() {
	intel.DisableRateLimitForTesting()
}
