package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type StalenessResult struct {
	LatestVersion string
	LastUpdated   time.Time
	IsStale       bool
}

func CheckStaleness(pkg Package) (StalenessResult, error) {
	switch pkg.Ecosystem {
	case "npm":
		return checkNPMStaleness(pkg.Name)
	case "PyPI":
		return checkPyPIStaleness(pkg.Name)
	case "Maven":
		return checkMavenStaleness(pkg.Name)
	case "NuGet":
		return checkNuGetStaleness(pkg.Name)
	case "Go":
		return checkGoStaleness(pkg.Name)
	case "crates.io":
		return checkCratesStaleness(pkg.Name)
	case "Packagist":
		return checkPackagistStaleness(pkg.Name)
	case "RubyGems":
		return checkRubyGemsStaleness(pkg.Name)
	default:
		return StalenessResult{}, fmt.Errorf("unsupported ecosystem: %s", pkg.Ecosystem)
	}
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
	resp, err := httpClient.Get("https://pypi.org/pypi/" + name + "/json")
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

	var data struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return StalenessResult{}, err
	}

	latest := data.Info.Version
	releases, ok := data.Releases[latest]
	if !ok || len(releases) == 0 {
		return StalenessResult{LatestVersion: latest}, nil
	}

	t, err := time.Parse(time.RFC3339, releases[0].UploadTime)
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
		strings.ToLower(name),
	)

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return StalenessResult{}, err
	}
	defer resp.Body.Close()

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
