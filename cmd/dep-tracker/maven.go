package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nyumuharon/dependency-tracker/internal/intel"
)

// Maven resolves a dependency's version through the project's parent POMs and
// imported BOMs: a Spring Boot project declares most dependencies without a
// version and inherits them from spring-boot-starter-parent. This file builds
// that effective model. Parents are read from the local checkout first
// (<relativePath>, ../pom.xml by default) and otherwise from Maven Central,
// which is only contacted when a version is still missing.

// mavenRepositoryURL is the repository parent POMs and BOMs are fetched from;
// tests replace it.
var mavenRepositoryURL = "https://repo1.maven.org/maven2"

// maxMavenDepth bounds parent and import chains, which also stops cycles.
const maxMavenDepth = 12

// Maven Central rate-limits clients (429). Requests are retried after a short
// pause, honouring Retry-After up to mavenMaxRetryWait.
var (
	mavenAttempts     = 3
	mavenRetryDelay   = 2 * time.Second
	mavenMaxRetryWait = 20 * time.Second
	mavenSleep        = time.Sleep
	// mavenRateLimited stops further requests in this run once the repository
	// keeps refusing them, so a rate-limited scan finishes quickly with the
	// remaining versions reported as unresolved instead of waiting minutes.
	mavenRateLimited atomic.Bool
)

type pomProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type pomFile struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     struct {
		GroupID      string `xml:"groupId"`
		ArtifactID   string `xml:"artifactId"`
		Version      string `xml:"version"`
		RelativePath string `xml:"relativePath"`
	} `xml:"parent"`
	Properties struct {
		Entries []pomProperty `xml:",any"`
	} `xml:"properties"`
	Dependencies []mavenDep `xml:"dependencies>dependency"`
	DepMgmt      []mavenDep `xml:"dependencyManagement>dependencies>dependency"`
}

// mavenModel is a POM with its parents merged in, as Maven's inheritance does:
// a child's properties and managed versions override its parent's.
type mavenModel struct {
	props   map[string]string
	managed map[string]string // groupId:artifactId -> version as written
	imports []mavenDep        // imported BOMs, as written
}

// resolveMavenProperties substitutes ${name} references, including nested and
// embedded ones ("${major}.${minor}"). Unknown or cyclic references are left
// in place so that the version stays visibly unresolved.
func resolveMavenProperties(props map[string]string, val string) string {
	val = strings.TrimSpace(val)
	for depth := 0; depth < 10 && strings.Contains(val, "${"); depth++ {
		start := strings.Index(val, "${")
		end := strings.Index(val[start:], "}")
		if end == -1 {
			break
		}
		resolved, ok := props[val[start+2:start+end]]
		if !ok {
			break
		}
		val = val[:start] + resolved + val[start+end+1:]
	}
	return val
}

var (
	mavenPOMCacheMu sync.Mutex
	mavenPOMCache   = map[string]mavenFetchResult{}
)

type mavenFetchResult struct {
	data []byte
	err  error
}

// fetchMavenPOM returns groupId:artifactId:version's POM. A published
// release never changes, so it is kept in the cache folder and downloaded
// once; snapshots are fetched each run. Results are also kept for the run.
func fetchMavenPOM(group, artifact, version string) ([]byte, error) {
	if group == "" || artifact == "" || version == "" || strings.Contains(group+artifact+version, "${") {
		return nil, fmt.Errorf("incomplete coordinates %s:%s:%s", group, artifact, version)
	}
	key := group + ":" + artifact + ":" + version
	mavenPOMCacheMu.Lock()
	cached, ok := mavenPOMCache[key]
	mavenPOMCacheMu.Unlock()
	if ok {
		return cached.data, cached.err
	}
	diskPath := ""
	if !strings.HasSuffix(version, "-SNAPSHOT") && !strings.ContainsAny(group+artifact+version, `/\:`) {
		diskPath = cacheFile(filepath.Join("maven", group+"__"+artifact+"__"+version+".pom"))
	}
	var res mavenFetchResult
	if diskPath != "" {
		if data, err := os.ReadFile(diskPath); err == nil {
			res.data = data
		}
	}
	if res.data == nil {
		url := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom", mavenRepositoryURL, strings.ReplaceAll(group, ".", "/"), artifact, version, artifact, version)
		res.data, res.err = getMavenPOM(url, key)
		if res.err == nil && diskPath != "" {
			_ = os.MkdirAll(filepath.Dir(diskPath), 0o755)
			writeCacheFile(diskPath, res.data)
		}
	}
	mavenPOMCacheMu.Lock()
	mavenPOMCache[key] = res
	mavenPOMCacheMu.Unlock()
	return res.data, res.err
}

func getMavenPOM(url, key string) ([]byte, error) {
	if mavenRateLimited.Load() {
		return nil, fmt.Errorf("maven repository is rate-limiting this client; skipped %s", key)
	}
	for attempt := 1; ; attempt++ {
		resp, err := intel.HTTPClient().Get(url)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK {
			data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
			resp.Body.Close()
			return data, err
		}
		resp.Body.Close()
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable
		if !retryable || attempt == mavenAttempts {
			if resp.StatusCode == http.StatusTooManyRequests {
				mavenRateLimited.Store(true)
			}
			return nil, fmt.Errorf("maven repository returned %d for %s", resp.StatusCode, key)
		}
		wait := time.Duration(attempt) * mavenRetryDelay
		if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 {
			wait = time.Duration(seconds) * time.Second
		}
		mavenSleep(min(wait, mavenMaxRetryWait))
	}
}

// findMavenParent returns the parent POM's path ("" when fetched) and content.
func findMavenParent(childPath string, pom pomFile, remote bool) (string, []byte, error) {
	if childPath != "" {
		rel := strings.TrimSpace(pom.Parent.RelativePath)
		if rel == "" {
			rel = filepath.Join("..", "pom.xml")
		}
		candidate := filepath.Join(filepath.Dir(childPath), rel)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			candidate = filepath.Join(candidate, "pom.xml")
		}
		if data, err := os.ReadFile(candidate); err == nil {
			var local pomFile
			if xml.Unmarshal(data, &local) == nil && strings.TrimSpace(local.ArtifactID) == strings.TrimSpace(pom.Parent.ArtifactID) {
				return candidate, data, nil
			}
		}
	}
	if !remote {
		return "", nil, fmt.Errorf("parent %s:%s not available locally", pom.Parent.GroupID, pom.Parent.ArtifactID)
	}
	data, err := fetchMavenPOM(strings.TrimSpace(pom.Parent.GroupID), strings.TrimSpace(pom.Parent.ArtifactID), strings.TrimSpace(pom.Parent.Version))
	return "", data, err
}

// loadMavenModel builds the inherited model of a POM. An unavailable parent
// leaves the versions it would have supplied unresolved. Each call builds a
// fresh model, so a child may extend its parent's maps in place.
func loadMavenModel(path string, data []byte, remote bool, depth int) (mavenModel, pomFile, error) {
	var pom pomFile
	if err := xml.Unmarshal(data, &pom); err != nil {
		return mavenModel{}, pom, err
	}
	model := mavenModel{props: map[string]string{}, managed: map[string]string{}}
	if pom.Parent.ArtifactID != "" && depth < maxMavenDepth {
		if parentPath, parentData, err := findMavenParent(path, pom, remote); err == nil {
			if parent, _, err := loadMavenModel(parentPath, parentData, remote, depth+1); err == nil {
				model = parent
			}
		}
	}
	set := func(key, value string) {
		if value = strings.TrimSpace(value); value != "" {
			model.props[key] = value
		}
	}
	set("project.parent.version", pom.Parent.Version)
	set("project.parent.groupId", pom.Parent.GroupID)
	set("project.version", pom.Parent.Version)
	set("project.groupId", pom.Parent.GroupID)
	set("project.version", pom.Version)
	set("pom.version", pom.Version)
	set("project.groupId", pom.GroupID)
	set("project.artifactId", pom.ArtifactID)
	for _, entry := range pom.Properties.Entries {
		model.props[entry.XMLName.Local] = strings.TrimSpace(entry.Value)
	}
	for _, dep := range pom.DepMgmt {
		if strings.TrimSpace(dep.Scope) == "import" {
			model.imports = append(model.imports, dep)
			continue
		}
		ga := resolveMavenProperties(model.props, dep.GroupID) + ":" + resolveMavenProperties(model.props, dep.ArtifactID)
		model.managed[ga] = dep.Version
	}
	return model, pom, nil
}

// managedVersions resolves a model's managed versions with its own effective
// properties, then fills gaps from imported BOMs, which are resolved with
// theirs (an import never overrides a version the POM manages itself). BOMs
// are only fetched while a coordinate in need is still missing.
func managedVersions(model mavenModel, need map[string]bool, remote bool, depth int) map[string]string {
	result := map[string]string{}
	for ga, raw := range model.managed {
		result[ga] = resolveMavenProperties(model.props, raw)
	}
	missing := func() bool {
		for ga := range need {
			if v, ok := result[ga]; !ok || v == "" || strings.Contains(v, "${") {
				return true
			}
		}
		return false
	}
	if !remote || depth >= maxMavenDepth {
		return result
	}
	for _, imp := range model.imports {
		if !missing() {
			break
		}
		group := resolveMavenProperties(model.props, imp.GroupID)
		artifact := resolveMavenProperties(model.props, imp.ArtifactID)
		version := resolveMavenProperties(model.props, imp.Version)
		data, err := fetchMavenPOM(group, artifact, version)
		if err != nil {
			continue
		}
		bom, _, err := loadMavenModel("", data, remote, depth+1)
		if err != nil {
			continue
		}
		for ga, v := range managedVersions(bom, need, remote, depth+1) {
			if _, ok := result[ga]; !ok {
				result[ga] = v
			}
		}
	}
	return result
}

func parseMavenWithProperties(filePath string, data []byte) ([]Package, error) {
	// Resolve offline first; contact the repository only for what is missing.
	pkgs, unresolved, err := mavenPackages(filePath, data, false)
	if err == nil && unresolved {
		pkgs, _, err = mavenPackages(filePath, data, true)
	}
	return pkgs, err
}

// mavenPackages reports a POM's dependencies and its own managed versions. A
// dependency whose version cannot be resolved is still reported, with the
// version as written, so the scan is marked incomplete rather than looking
// clean.
func mavenPackages(filePath string, data []byte, remote bool) ([]Package, bool, error) {
	model, pom, err := loadMavenModel(filePath, data, remote, 0)
	if err != nil {
		return nil, false, err
	}
	need := map[string]bool{}
	for _, dep := range pom.Dependencies {
		if strings.TrimSpace(dep.Version) == "" {
			need[resolveMavenProperties(model.props, dep.GroupID)+":"+resolveMavenProperties(model.props, dep.ArtifactID)] = true
		}
	}
	managed := managedVersions(model, need, remote, 0)
	var pkgs []Package
	seen := make(map[string]bool)
	unresolved := false
	add := func(dep mavenDep, ver string, required bool) {
		group := resolveMavenProperties(model.props, dep.GroupID)
		artifact := resolveMavenProperties(model.props, dep.ArtifactID)
		if group == "" || artifact == "" {
			return
		}
		if ver == "" || strings.Contains(ver, "${") {
			if !required {
				return // an unresolved pin is not itself a dependency
			}
			unresolved = true
			if ver == "" {
				ver = "unspecified"
			}
		}
		p := Package{Name: group + ":" + artifact, Version: ver, Ecosystem: "Maven", ManifestPath: filePath}
		if !seen[p.Key()] {
			seen[p.Key()] = true
			pkgs = append(pkgs, p)
		}
	}
	// dependencyManagement pins the versions of child-module and transitive
	// dependencies, so its entries are reported. An imported BOM (scope
	// import) is only a list of versions, not a dependency.
	for _, dep := range pom.DepMgmt {
		if strings.TrimSpace(dep.Scope) != "import" {
			add(dep, resolveMavenProperties(model.props, dep.Version), false)
		}
	}
	for _, dep := range pom.Dependencies {
		ver := resolveMavenProperties(model.props, dep.Version)
		if strings.TrimSpace(dep.Version) == "" {
			ga := resolveMavenProperties(model.props, dep.GroupID) + ":" + resolveMavenProperties(model.props, dep.ArtifactID)
			ver = managed[ga]
		}
		add(dep, ver, true)
	}
	return pkgs, unresolved, nil
}
