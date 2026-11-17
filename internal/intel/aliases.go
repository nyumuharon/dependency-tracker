package intel

import (
	"net/http"
	"sync"
	"time"

	"github.com/nyumuharon/dependency-tracker/internal/cache"
	"github.com/nyumuharon/dependency-tracker/internal/model"
	"github.com/nyumuharon/dependency-tracker/internal/version"
)

type Package = model.Package
type Vulnerability = model.Vulnerability
type ScanResult = model.ScanResult
type StalenessResult = model.StalenessResult
type OSVResponse = osvResponse

var NVDMaxAttempts = nvdMaxAttempts

func HTTPClient() *http.Client { return httpClient }

func ParseVulns(res OSVResponse, pkg Package) []Vulnerability {
	return parseVulns(res, pkg)
}

func ParseCVSSVector(vector string) float64 {
	return parseCVSSVector(vector)
}

func ParseKEVData(data []byte) (map[string]KEVEntry, error) {
	return parseKEVData(data)
}

func cacheFile(name string) string               { return cache.File(name) }
func writeCacheFile(path string, data []byte)    { cache.WriteFile(path, data) }
func validateQueryVersion(p Package) error       { return version.ValidateQueryVersion(p) }
func compareVersions(a, b, e string) (int, bool) { return version.CompareVersions(a, b, e) }
func normalizeSeverityLabel(label string) string { return model.NormalizeSeverityLabel(label) }
func severityLabelScore(label string) float64    { return model.SeverityLabelScore(label) }

func ResetCaches() {
	stalenessCacheOnce = sync.Once{}
	nvdCacheOnce = sync.Once{}
}

func SetHTTPClient(c *http.Client) *http.Client {
	old := httpClient
	httpClient = c
	return old
}

func DisableRateLimitForTesting() {
	nvdSleep = func(time.Duration) {}
	nvdWindow = 0
}
