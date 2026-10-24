package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type StalenessResult struct {
	CheckError    string    `json:"check_error,omitempty"`
	LatestVersion string    `json:"latest_version"`
	LastUpdated   time.Time `json:"last_updated"`
	IsStale       bool      `json:"is_stale"`
	CachedAt      time.Time `json:"cached_at"`
}

const stalenessCacheTTL = 12 * time.Hour

var (
	stalenessCacheOnce sync.Once
	stalenessCacheMu   sync.RWMutex
	stalenessCacheData map[string]StalenessResult
)

func getStalenessCachePath() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "dependency_risk_tracker")
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "staleness_cache.json")
}

func loadStalenessCache() {
	stalenessCacheOnce.Do(func() {
		stalenessCacheData = make(map[string]StalenessResult)
		data, err := os.ReadFile(getStalenessCachePath())
		if err == nil {
			_ = json.Unmarshal(data, &stalenessCacheData)
		}
	})
}

func SaveStalenessCache() {
	stalenessCacheMu.RLock()
	if len(stalenessCacheData) == 0 {
		stalenessCacheMu.RUnlock()
		return
	}
	data, err := json.Marshal(stalenessCacheData)
	stalenessCacheMu.RUnlock()
	if err == nil {
		_ = os.WriteFile(getStalenessCachePath(), data, 0644)
	}
}

func CheckStaleness(pkg Package) (StalenessResult, error) {
	loadStalenessCache()
	cacheKey := strings.ToLower(pkg.Name) + "@" + pkg.Ecosystem

	stalenessCacheMu.RLock()
	if cached, ok := stalenessCacheData[cacheKey]; ok && time.Since(cached.CachedAt) < stalenessCacheTTL && cached.LatestVersion != "" {
		stalenessCacheMu.RUnlock()
		return cached, nil
	}
	stalenessCacheMu.RUnlock()

	var res StalenessResult
	var err error
	switch pkg.Ecosystem {
	case "npm":
		res, err = checkNPMStaleness(pkg.Name)
	case "PyPI":
		res, err = checkPyPIStaleness(pkg.Name)
	case "Maven":
		res, err = checkMavenStaleness(pkg.Name)
	case "NuGet":
		res, err = checkNuGetStaleness(pkg.Name)
	case "Go":
		res, err = checkGoStaleness(pkg.Name)
	case "crates.io":
		res, err = checkCratesStaleness(pkg.Name)
	case "Packagist":
		res, err = checkPackagistStaleness(pkg.Name)
	case "RubyGems":
		res, err = checkRubyGemsStaleness(pkg.Name)
	case "ConanCenter":
		res, err = checkConanStaleness(pkg.Name)
	case "Pub":
		res, err = checkPubStaleness(pkg.Name)
	case "Hex":
		res, err = checkHexStaleness(pkg.Name)
	default:
		return StalenessResult{}, fmt.Errorf("unsupported ecosystem: %s", pkg.Ecosystem)
	}

	if err == nil && res.LastUpdated.IsZero() {
		err = fmt.Errorf("release date unavailable for %s", pkg.Name)
	}
	if err == nil && res.LatestVersion != "" {
		res.CachedAt = time.Now()
		stalenessCacheMu.Lock()
		stalenessCacheData[cacheKey] = res
		stalenessCacheMu.Unlock()
	}
	return res, err
}

func isStale(t time.Time) bool {
	return time.Since(t) > 730*24*time.Hour
}

// ── npm ───────────────────────────────────────────────────────────────────────
func checkNPMStaleness(name string) (StalenessResult, error) {
	resp, err := httpClient.Get("https://registry.npmjs.org/" + name)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, fmt.Errorf("npm registry returned %d", resp.StatusCode)
	}

	var data struct {
		DistTags struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`
		Time map[string]string `json:"time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	latest := data.DistTags.Latest
	timeStr, ok := data.Time[latest]
	if !ok {
		return StalenessResult{LatestVersion: latest}, nil
	}

	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return StalenessResult{LatestVersion: latest}, nil
	}

	return StalenessResult{
		LatestVersion: latest,
		LastUpdated:   t,
		IsStale:       isStale(t),
	}, nil
}

// ── PyPI ──────────────────────────────────────────────────────────────────────
func checkPyPIStaleness(name string) (StalenessResult, error) {
	// Use PyPI's lightweight RSS releases feed (~10 KB vs multi-MB full JSON history)
	rssURL := "https://pypi.org/rss/project/" + url.PathEscape(name) + "/releases.xml"
	if resp, err := httpClient.Get(rssURL); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var feed struct {
				Items []struct {
					Title   string `xml:"title"`
					PubDate string `xml:"pubDate"`
				} `xml:"channel>item"`
			}
			if xml.NewDecoder(resp.Body).Decode(&feed) == nil && len(feed.Items) > 0 {
				chosen := feed.Items[0]
				for _, item := range feed.Items {
					v := strings.ToLower(strings.TrimSpace(item.Title))
					if !strings.Contains(v, "a") && !strings.Contains(v, "b") && !strings.Contains(v, "rc") && !strings.Contains(v, "dev") {
						chosen = item
						break
					}
				}
				latest := strings.TrimSpace(chosen.Title)
				t, parseErr := time.Parse(time.RFC1123, strings.TrimSpace(chosen.PubDate))
				if parseErr != nil {
					t, parseErr = time.Parse(time.RFC1123Z, strings.TrimSpace(chosen.PubDate))
				}
				if parseErr == nil {
					return StalenessResult{
						LatestVersion: latest,
						LastUpdated:   t,
						IsStale:       isStale(t),
					}, nil
				}
				return StalenessResult{LatestVersion: latest}, nil
			}
		}
	}

	// Fallback to JSON API if RSS feed is unavailable
	resp, err := httpClient.Get("https://pypi.org/pypi/" + url.PathEscape(name) + "/json")
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, fmt.Errorf("pypi returned %d", resp.StatusCode)
	}

	var data struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		URLs []struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	latest := data.Info.Version
	if len(data.URLs) == 0 {
		return StalenessResult{LatestVersion: latest}, nil
	}

	t, err := time.Parse(time.RFC3339, data.URLs[0].UploadTime)
	if err != nil {
		return StalenessResult{LatestVersion: latest}, nil
	}

	return StalenessResult{
		LatestVersion: latest,
		LastUpdated:   t,
		IsStale:       isStale(t),
	}, nil
}

// ── Maven ─────────────────────────────────────────────────────────────────────
func checkMavenStaleness(name string) (StalenessResult, error) {
	// name is "groupId:artifactId"
	parts := splitMavenName(name)
	if len(parts) != 2 {
		return StalenessResult{}, fmt.Errorf("invalid maven name: %s", name)
	}

	q := url.QueryEscape(fmt.Sprintf("g:%s AND a:%s", parts[0], parts[1]))
	apiURL := fmt.Sprintf("https://search.maven.org/solrsearch/select?q=%s&rows=1&wt=json", q)

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, fmt.Errorf("maven search returned %d", resp.StatusCode)
	}

	var data struct {
		Response struct {
			Docs []struct {
				LatestVersion string `json:"latestVersion"`
				Timestamp     int64  `json:"timestamp"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	if len(data.Response.Docs) == 0 {
		return StalenessResult{}, nil
	}

	doc := data.Response.Docs[0]
	t := time.UnixMilli(doc.Timestamp)

	return StalenessResult{
		LatestVersion: doc.LatestVersion,
		LastUpdated:   t,
		IsStale:       isStale(t),
	}, nil
}

func splitMavenName(name string) []string {
	for i, c := range name {
		if c == ':' {
			return []string{name[:i], name[i+1:]}
		}
	}
	return []string{name}
}

// ── NuGet ─────────────────────────────────────────────────────────────────────
func checkNuGetStaleness(name string) (StalenessResult, error) {
	apiURL := fmt.Sprintf(
		"https://api.nuget.org/v3/registration5-gz-semver2/%s/index.json",
		url.PathEscape(strings.ToLower(name)),
	)

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, fmt.Errorf("nuget returned %d", resp.StatusCode)
	}

	var data struct {
		Items []struct {
			Upper string `json:"upper"`
			Items []struct {
				CatalogEntry struct {
					Version   string `json:"version"`
					Published string `json:"published"`
				} `json:"catalogEntry"`
			} `json:"items"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	if len(data.Items) == 0 {
		return StalenessResult{}, nil
	}

	// Last page, last item = latest version
	lastPage := data.Items[len(data.Items)-1]
	if len(lastPage.Items) == 0 {
		return StalenessResult{LatestVersion: lastPage.Upper}, nil
	}

	entry := lastPage.Items[len(lastPage.Items)-1].CatalogEntry
	t, err := time.Parse(time.RFC3339, entry.Published)
	if err != nil {
		return StalenessResult{LatestVersion: entry.Version}, nil
	}

	return StalenessResult{
		LatestVersion: entry.Version,
		LastUpdated:   t,
		IsStale:       isStale(t),
	}, nil
}

// ── Go ────────────────────────────────────────────────────────────────────────
func checkGoStaleness(name string) (StalenessResult, error) {
	escapedName := escapeGoPath(name)
	apiURL := fmt.Sprintf("https://proxy.golang.org/%s/@latest", escapedName)

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, fmt.Errorf("go proxy returned %d", resp.StatusCode)
	}

	var data struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	return StalenessResult{
		LatestVersion: data.Version,
		LastUpdated:   data.Time,
		IsStale:       isStale(data.Time),
	}, nil
}

func escapeGoPath(path string) string {
	var b strings.Builder
	for _, r := range path {
		if 'A' <= r && r <= 'Z' {
			b.WriteRune('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ── Rust (crates.io) ──────────────────────────────────────────────────────────
func checkCratesStaleness(name string) (StalenessResult, error) {
	apiURL := "https://crates.io/api/v1/crates/" + url.PathEscape(name)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return StalenessResult{}, err
	}
	req.Header.Set("User-Agent", "dependency-risk-tracker (security-scanner)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, fmt.Errorf("crates.io returned %d", resp.StatusCode)
	}

	var data struct {
		Crate struct {
			MaxVersion string `json:"max_version"`
			UpdatedAt  string `json:"updated_at"`
		} `json:"crate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	t, err := time.Parse(time.RFC3339, data.Crate.UpdatedAt)
	if err != nil {
		return StalenessResult{LatestVersion: data.Crate.MaxVersion}, nil
	}

	return StalenessResult{
		LatestVersion: data.Crate.MaxVersion,
		LastUpdated:   t,
		IsStale:       isStale(t),
	}, nil
}

// ── PHP (Packagist) ───────────────────────────────────────────────────────────
func checkPackagistStaleness(name string) (StalenessResult, error) {
	apiURL := fmt.Sprintf("https://repo.packagist.org/p2/%s.json", name)
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, fmt.Errorf("packagist returned %d", resp.StatusCode)
	}

	var data struct {
		Packages map[string][]struct {
			Version string `json:"version"`
			Time    string `json:"time"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	releases, ok := data.Packages[name]
	if !ok || len(releases) == 0 {
		return StalenessResult{}, nil
	}

	latest := releases[0]
	t, err := time.Parse(time.RFC3339, latest.Time)
	if err != nil {
		return StalenessResult{LatestVersion: latest.Version}, nil
	}

	return StalenessResult{
		LatestVersion: latest.Version,
		LastUpdated:   t,
		IsStale:       isStale(t),
	}, nil
}

// ── Ruby (RubyGems) ───────────────────────────────────────────────────────────
func checkRubyGemsStaleness(name string) (StalenessResult, error) {
	apiURL := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", url.PathEscape(name))
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, fmt.Errorf("rubygems returned %d", resp.StatusCode)
	}

	var data struct {
		Version          string `json:"version"`
		VersionCreatedAt string `json:"version_created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	t, err := time.Parse(time.RFC3339, data.VersionCreatedAt)
	if err != nil {
		return StalenessResult{LatestVersion: data.Version}, nil
	}

	return StalenessResult{
		LatestVersion: data.Version,
		LastUpdated:   t,
		IsStale:       isStale(t),
	}, nil
}

// ── C / C++ (ConanCenter) ─────────────────────────────────────────────────────
func checkConanStaleness(name string) (StalenessResult, error) {
	// Query official ConanCenter recipe config
	configURL := fmt.Sprintf("https://raw.githubusercontent.com/conan-io/conan-center-index/master/recipes/%s/config.yml", url.PathEscape(name))
	resp, err := httpClient.Get(configURL)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, nil // Recipe not indexed in conan-center-index
	}

	scanner := bufio.NewScanner(resp.Body)
	inVersions := false
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		trimmed := strings.TrimSpace(line)

		if trimmed == "versions:" {
			inVersions = true
			continue
		}

		if inVersions {
			// Find the first version entry under versions: (e.g., `  "3.1.2":` or `  1.2.3:`)
			if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(trimmed, ":") {
				v := strings.TrimSuffix(trimmed, ":")
				v = strings.Trim(v, `"'`)
				if v != "" {
					return StalenessResult{LatestVersion: v}, nil
				}
			} else if !strings.HasPrefix(line, " ") && trimmed != "" {
				// Reached another top-level key
				break
			}
		}
	}

	return StalenessResult{}, nil
}

// ── Dart / Flutter (Pub) ──────────────────────────────────────────────────────
func checkPubStaleness(name string) (StalenessResult, error) {
	apiURL := fmt.Sprintf("https://pub.dev/api/packages/%s", url.PathEscape(name))
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, fmt.Errorf("pub.dev returned %d", resp.StatusCode)
	}

	var data struct {
		Latest struct {
			Version   string `json:"version"`
			Published string `json:"published"`
		} `json:"latest"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	t, err := time.Parse(time.RFC3339, data.Latest.Published)
	if err != nil {
		return StalenessResult{LatestVersion: data.Latest.Version}, nil
	}

	return StalenessResult{
		LatestVersion: data.Latest.Version,
		LastUpdated:   t,
		IsStale:       isStale(t),
	}, nil
}

// ── Elixir (Hex) ──────────────────────────────────────────────────────────────
func checkHexStaleness(name string) (StalenessResult, error) {
	apiURL := fmt.Sprintf("https://hex.pm/api/packages/%s", url.PathEscape(name))
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StalenessResult{}, fmt.Errorf("hex.pm returned %d", resp.StatusCode)
	}

	var data struct {
		Releases []struct {
			Version    string `json:"version"`
			InsertedAt string `json:"inserted_at"`
		} `json:"releases"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	if len(data.Releases) == 0 {
		return StalenessResult{}, nil
	}

	latest := data.Releases[0]
	t, err := time.Parse(time.RFC3339, latest.InsertedAt)
	if err != nil {
		return StalenessResult{LatestVersion: latest.Version}, nil
	}

	return StalenessResult{
		LatestVersion: latest.Version,
		LastUpdated:   t,
		IsStale:       isStale(t),
	}, nil
}
