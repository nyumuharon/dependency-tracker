package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// alwaysSkipDirs are never project sources: VCS data, editor settings,
// installed dependencies (inspected separately) and test fixtures.
var alwaysSkipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"venv":         true,
	"obj":          true,
	"testdata":     true,
}

// buildOutputDirs hold generated output when they sit beside a project's
// dependency file. Elsewhere they are ordinary folders (a top-level build/
// tool, an app called target/) and are scanned.
var buildOutputDirs = map[string]bool{
	"target": true,
	"bin":    true,
	"dist":   true,
	"build":  true,
}

// isVirtualEnv reports whether dir is a Python virtual environment, whatever
// its name.
func isVirtualEnv(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "pyvenv.cfg"))
	return err == nil
}

// isBuildOutputDir reports whether dir is the output folder of a project
// declared in its parent directory.
func isBuildOutputDir(dir string) bool {
	// An unreadable parent has no visible manifest, so the folder is scanned.
	entries, _ := os.ReadDir(filepath.Dir(dir))
	for _, e := range entries {
		if !e.IsDir() && isCandidateDependencyFile(e.Name()) {
			return true
		}
	}
	return false
}

// continueAfterWalkError keeps a walk going after a recorded error: an
// unreadable directory is skipped, and anything else needs no special step.
func continueAfterWalkError(d os.DirEntry) error {
	if d != nil && d.IsDir() {
		return filepath.SkipDir
	}
	return nil
}

// skipSourceDir decides whether a directory below rootDir is skipped when
// looking for manifests and source imports. The scan root itself is never
// skipped, whatever its name.
func skipSourceDir(path, rootDir string) bool {
	if filepath.Clean(path) == filepath.Clean(rootDir) {
		return false
	}
	name := filepath.Base(path)
	if strings.HasPrefix(name, ".") || alwaysSkipDirs[name] || isVirtualEnv(path) {
		return true
	}
	return buildOutputDirs[name] && isBuildOutputDir(path)
}

// IsManifestFile returns true if fileName is a recognized dependency manifest or lockfile.
func IsManifestFile(fileName string) bool {
	switch {
	case strings.HasSuffix(fileName, "package-lock.json"),
		strings.HasSuffix(fileName, "yarn.lock"),
		strings.HasSuffix(fileName, "pnpm-lock.yaml"),
		strings.HasSuffix(fileName, "package.json"),
		strings.HasSuffix(fileName, "poetry.lock"),
		strings.HasSuffix(fileName, "Pipfile.lock"),
		strings.HasSuffix(fileName, "uv.lock"),
		strings.HasSuffix(fileName, "requirements.txt"),
		strings.HasSuffix(fileName, "pyproject.toml"),
		strings.HasSuffix(fileName, "go.sum"),
		strings.HasSuffix(fileName, "go.mod"),
		strings.HasSuffix(fileName, "Cargo.lock"),
		strings.HasSuffix(fileName, "Cargo.toml"),
		strings.HasSuffix(fileName, "composer.lock"),
		strings.HasSuffix(fileName, "composer.json"),
		strings.HasSuffix(fileName, "Gemfile.lock"),
		strings.HasSuffix(fileName, "pom.xml"),
		strings.HasSuffix(fileName, "packages.lock.json"),
		strings.HasSuffix(fileName, "packages.config"),
		strings.HasSuffix(fileName, ".csproj"),
		strings.HasSuffix(fileName, "conan.lock"),
		strings.HasSuffix(fileName, "conanfile.txt"),
		strings.HasSuffix(fileName, "vcpkg.json"):
		return true
	default:
		return false
	}
}

// lockfileNames are files that record exact resolved versions. A lockfile is
// preferred over the manifests of the same ecosystem in its directory, except
// for Go, where go.mod is authoritative and go.sum also lists old versions.
var lockfileNames = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"poetry.lock": true, "pipfile.lock": true, "uv.lock": true, "pdm.lock": true,
	"go.sum": true, "cargo.lock": true, "composer.lock": true, "gemfile.lock": true,
	"packages.lock.json": true, "paket.lock": true, "conan.lock": true,
	"pubspec.lock": true, "mix.lock": true, "package.resolved": true, "gradle.lockfile": true,
}

// filterDirManifests selects the best manifests in a directory (prioritizing lockfiles over loose manifests).
func filterDirManifests(paths []string) []string {
	hasLock := make(map[string]bool)
	for _, p := range paths {
		if base := strings.ToLower(filepath.Base(p)); lockfileNames[base] {
			hasLock[dependencyFileEcosystem(p)] = true
		}
	}
	var selected []string
	for _, p := range paths {
		base := strings.ToLower(filepath.Base(p))
		eco := dependencyFileEcosystem(p)
		switch {
		case eco == "" || base == "vcpkg.json" || base == "cmakelists.txt":
			// Unrecognised names, and vcpkg/CMake, which no Conan lock covers.
			selected = append(selected, p)
		case eco == "Go":
			if base != "go.sum" || !hasGoMod(paths) {
				selected = append(selected, p)
			}
		case lockfileNames[base] || !hasLock[eco]:
			selected = append(selected, p)
		}
	}
	return selected
}

func hasGoMod(paths []string) bool {
	for _, p := range paths {
		if strings.EqualFold(filepath.Base(p), "go.mod") {
			return true
		}
	}
	return false
}

// FindManifests recursively walks rootDir and returns all discovered dependency manifests/lockfiles.
func FindManifests(rootDir string) ([]string, error) {
	dirManifests := make(map[string][]string)

	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipSourceDir(path, rootDir) {
				return filepath.SkipDir
			}
			return nil
		}

		fileName := d.Name()
		if IsManifestFile(fileName) {
			dir := filepath.Dir(path)
			dirManifests[dir] = append(dirManifests[dir], path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var allSelected []string
	for _, files := range dirManifests {
		allSelected = append(allSelected, filterDirManifests(files)...)
	}
	sort.Strings(allSelected)
	return allSelected, nil
}

// ParsePath parses dependencies from either a single manifest file or an entire project directory.
func ParsePath(targetPath string) ([]Package, error) {
	fi, err := os.Stat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access path %s: %w", targetPath, err)
	}

	if fi.IsDir() {
		fmt.Fprintf(os.Stderr, "Discovering dependency manifests in directory: %s\n", targetPath)
		pkgs, sources, err := DiscoverDependencies(targetPath)
		if err == nil && len(sources) == 0 && len(pkgs) == 0 {
			return nil, fmt.Errorf("no dependencies, manifests, environments, or imports found in directory: %s", targetPath)
		}
		if len(sources) > 0 {
			fmt.Fprintf(os.Stderr, "Discovered %d dependency source(s):\n", len(sources))
			for _, s := range sources {
				fmt.Fprintf(os.Stderr, "  • %s\n", s)
			}
			fmt.Fprintln(os.Stderr)
		}
		if err != nil {
			return pkgs, fmt.Errorf("project discovery failed: %w", err)
		}
		return pkgs, nil
	}

	pkgs, err := ParseManifest(targetPath)
	if err != nil {
		return nil, err
	}
	var allPkgs []Package
	seen := make(map[string]bool)
	for _, p := range pkgs {
		key := p.Key()
		if !seen[key] {
			seen[key] = true
			allPkgs = append(allPkgs, p)
		}
	}
	return allPkgs, nil
}

func ParseManifest(filePath string) ([]Package, error) {
	pkgs, err := parseManifestRaw(filePath)
	if err != nil {
		return nil, err
	}
	for i := range pkgs {
		p := &pkgs[i]
		if p.ManifestPath == "" {
			p.ManifestPath = filePath
		}
		p.ProjectPath = filepath.Dir(filePath)
		p.VersionSource = "manifest"
		base := strings.ToLower(filepath.Base(filePath))
		if strings.HasSuffix(base, ".lock") || strings.HasSuffix(base, "-lock.json") || base == "pnpm-lock.yaml" || base == "packages.lock.json" || base == "package.resolved" || base == "go.sum" {
			p.VersionSource = "lockfile"
		}
		if base == "project.assets.json" || base == "installed.json" || base == "package_config.json" {
			p.VersionSource = "installed"
		}
		nugetRange := p.Ecosystem == "NuGet" && p.VersionSource == "manifest" && base != "packages.config" && !(strings.HasPrefix(p.Version, "[") && strings.HasSuffix(p.Version, "]") && !strings.Contains(p.Version, ","))
		cargoRange := base == "cargo.toml" && !strings.HasPrefix(p.Version, "=")
		p.Version = normalizeExactPin(p.Version, p.Ecosystem)
		if (!exactVersionRE.MatchString(p.Version) || wildcardVersionRE.MatchString(p.Version)) || cargoRange || nugetRange || base == "cmakelists.txt" {
			p.VersionSource = "constraint"
		}
	}
	return pkgs, nil
}

func parseManifestRaw(filePath string) ([]Package, error) {
	switch filepath.Base(filePath) {
	case "project.assets.json":
		return inspectDotNetAssets(filePath)
	case "package_config.json":
		return inspectDartPackageConfig(filePath)
	case "installed.json":
		return inspectComposerInstalled(filePath)
	case "METADATA", "PKG-INFO":
		name, version, err := parsePythonMetadataFile(filePath)
		if err != nil {
			return nil, err
		}
		return []Package{{Name: name, Version: version, Ecosystem: "PyPI", ManifestPath: filePath}}, nil
	}
	switch {
	// JavaScript / TypeScript lockfiles & manifests
	case strings.HasSuffix(filePath, "package-lock.json"):
		return parseNPMLock(filePath)
	case strings.HasSuffix(filePath, "yarn.lock"):
		return parseYarnLock(filePath)
	case strings.HasSuffix(filePath, "pnpm-lock.yaml"):
		return parsePnpmLock(filePath)
	case strings.HasSuffix(filePath, "package.json"):
		return parseNPM(filePath)

	// Python lockfiles & manifests
	case strings.HasSuffix(filePath, "poetry.lock"),
		strings.HasSuffix(filePath, "uv.lock"):
		return parsePoetryLock(filePath)
	case strings.HasSuffix(filePath, "Pipfile.lock"):
		return parsePipfileLock(filePath)
	case strings.HasSuffix(filePath, "requirements.txt"):
		return parsePyPI(filePath)
	case strings.HasSuffix(filePath, "pyproject.toml"):
		return parsePyProjectToml(filePath)

	// Go lockfiles & manifests
	case strings.HasSuffix(filePath, "go.sum"):
		return parseGoSum(filePath)
	case strings.HasSuffix(filePath, "go.mod"):
		return parseGoMod(filePath)

	// Rust
	case strings.HasSuffix(filePath, "Cargo.lock"):
		return parseCargoLock(filePath)
	case strings.HasSuffix(filePath, "Cargo.toml"):
		return parseCargoToml(filePath)

	// PHP
	case strings.HasSuffix(filePath, "composer.lock"):
		return parseComposerLock(filePath)
	case strings.HasSuffix(filePath, "composer.json"):
		return parseComposer(filePath)

	// Ruby
	case strings.HasSuffix(filePath, "Gemfile.lock"):
		return parseRubyGem(filePath)

	// Java / Maven
	case strings.HasSuffix(filePath, "pom.xml"):
		return parseMaven(filePath)

	// .NET / NuGet
	case strings.HasSuffix(filePath, "packages.lock.json"):
		return parseNuGetLock(filePath)
	case strings.HasSuffix(filePath, ".csproj"),
		strings.HasSuffix(filePath, "packages.config"):
		return parseNuGet(filePath)

	// C / C++ (Conan & vcpkg)
	case strings.HasSuffix(filePath, "conan.lock"):
		return parseConanLock(filePath)
	case strings.HasSuffix(filePath, "conanfile.txt"):
		return parseConanFile(filePath)
	case strings.HasSuffix(filePath, "vcpkg.json"):
		return parseVcpkg(filePath)

	default:
		return parseByContent(filePath)
	}
}

// ── npm (package.json) ────────────────────────────────────────────────────────

func parseNPM(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("invalid package.json: %w", err)
	}
	var pkgs []Package
	// npm installs optional dependencies whenever they build on the platform.
	for _, deps := range []map[string]string{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies} {
		for name, version := range deps {
			version = cleanNPMVersion(version)
			// "alias": "npm:real-package@^1.0.0" installs real-package.
			if real, rng := splitNPMSpec(strings.TrimPrefix(version, "npm:")); strings.HasPrefix(version, "npm:") && rng != "" {
				name, version = real, rng
			}
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   version,
				Ecosystem: "npm",
			})
		}
	}
	return pkgs, nil
}

func cleanNPMVersion(v string) string {
	return strings.TrimSpace(v)
}

// ── PyPI (requirements.txt) ───────────────────────────────────────────────────

func parsePyPI(filePath string) ([]Package, error) {
	return parseRequirementsFile(filePath, map[string]bool{})
}

// parseRequirementsFile reads a pip requirements file. It joins backslash
// continuations, drops per-requirement options such as --hash, and follows
// -r/--requirement includes relative to the including file. Constraint files
// (-c) only restrict versions and declare no dependencies, so they are skipped.
func parseRequirementsFile(filePath string, visited map[string]bool) ([]Package, error) {
	key := filePath
	if abs, err := filepath.Abs(filePath); err == nil {
		key = abs
	}
	if visited[key] {
		return nil, nil
	}
	visited[key] = true
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var pkgs []Package
	var logical []string
	var current strings.Builder
	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.HasSuffix(raw, "\\") {
			current.WriteString(strings.TrimSuffix(raw, "\\"))
			current.WriteString(" ")
			continue
		}
		current.WriteString(raw)
		logical = append(logical, current.String())
		current.Reset()
	}
	for _, line := range logical {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if strings.HasPrefix(line, "-") {
			fields := strings.Fields(strings.Replace(line, "=", " ", 1))
			if len(fields) == 2 && (fields[0] == "-r" || fields[0] == "--requirement") {
				included := fields[1]
				if !filepath.IsAbs(included) {
					included = filepath.Join(filepath.Dir(filePath), included)
				}
				sub, err := parseRequirementsFile(included, visited)
				if err != nil {
					return pkgs, fmt.Errorf("requirements include %s: %w", fields[1], err)
				}
				for _, p := range sub {
					if p.ManifestPath == "" {
						p.ManifestPath = included
					}
					pkgs = append(pkgs, p)
				}
			}
			continue
		}
		// Per-requirement options (--hash, --config-settings, ...) follow the
		// requirement itself.
		if idx := strings.Index(line, " --"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		// Local paths and bare URLs name no registry package.
		if strings.HasPrefix(line, ".") || strings.HasPrefix(line, "/") || (strings.Contains(line, "://") && !strings.Contains(line, "@")) {
			continue
		}
		name, ver := parsePEP508Spec(line)
		if name != "" && ver != "" {
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   ver,
				Ecosystem: "PyPI",
			})
		}
	}
	return pkgs, nil
}

// ── Maven (pom.xml) ───────────────────────────────────────────────────────────

type mavenPOM struct {
	Dependencies []mavenDep `xml:"dependencies>dependency"`
}

type mavenDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

func parseMaven(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	pkgs, err := parseMavenWithProperties(filePath, data)
	if err != nil {
		return nil, fmt.Errorf("invalid pom.xml: %w", err)
	}
	return pkgs, nil
}

// ── NuGet (.csproj / packages.config) ────────────────────────────────────────

type csproj struct {
	ItemGroups []struct {
		PackageRefs []struct {
			Include string `xml:"Include,attr"`
			Version string `xml:"Version,attr"`
		} `xml:"PackageReference"`
	} `xml:"ItemGroup"`
}

type packagesConfig struct {
	Packages []struct {
		ID      string `xml:"id,attr"`
		Version string `xml:"version,attr"`
	} `xml:"package"`
}

func parseNuGet(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	pkgs, err := parseDotNetXML(filePath, data)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", filePath, err)
	}
	return pkgs, nil
}

// ── Go (go.mod) ──────────────────────────────────────────────────────────────

func parseGoMod(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type goReplacement struct {
		oldVersion, newPath, newVersion string
	}
	var required []Package
	replacements := make(map[string][]goReplacement)
	scanner := bufio.NewScanner(f)
	block := ""

	handle := func(directive string, fields []string) {
		switch directive {
		case "require":
			if len(fields) >= 2 {
				required = append(required, Package{Name: fields[0], Version: fields[1], Ecosystem: "Go"})
			}
		case "replace":
			// old [v] => new [v]; a new path without a version is a local directory.
			arrow := -1
			for i, f := range fields {
				if f == "=>" {
					arrow = i
				}
			}
			if arrow < 1 || arrow > 2 || len(fields) <= arrow+1 {
				return
			}
			r := goReplacement{newPath: fields[arrow+1]}
			if arrow == 2 {
				r.oldVersion = fields[1]
			}
			if len(fields) > arrow+2 {
				r.newVersion = fields[arrow+2]
			}
			replacements[fields[0]] = append(replacements[fields[0]], r)
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.Index(line, "//"); i != -1 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if block != "" {
			if line == ")" {
				block = ""
				continue
			}
			handle(block, strings.Fields(line))
			continue
		}
		fields := strings.Fields(strings.Replace(line, "(", " ( ", 1))
		if len(fields) == 2 && fields[1] == "(" {
			block = fields[0]
			continue
		}
		if len(fields) > 1 {
			handle(fields[0], fields[1:])
		}
	}

	// A replace directive changes the module that is actually built, which is
	// the one that must be checked. A version-specific replacement wins over a
	// replacement of every version.
	var pkgs []Package
	for _, p := range required {
		var chosen *goReplacement
		for i, r := range replacements[p.Name] {
			if r.oldVersion == p.Version || (r.oldVersion == "" && chosen == nil) {
				chosen = &replacements[p.Name][i]
			}
		}
		if chosen != nil {
			if chosen.newVersion == "" {
				continue // replaced by a local directory, not a published module
			}
			p.Name, p.Version = chosen.newPath, chosen.newVersion
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, scanner.Err()
}

// ── Rust (Cargo.lock / Cargo.toml) ───────────────────────────────────────────

func parseCargoLock(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	scanner := bufio.NewScanner(f)
	var currentName, currentVersion, currentSource string

	// Entries without a registry source are the workspace's own crates or path
	// dependencies; a crates.io crate that happens to share the name is a
	// different package.
	flush := func() {
		if currentName != "" && currentVersion != "" && (strings.HasPrefix(currentSource, "registry+") || strings.HasPrefix(currentSource, "sparse+")) {
			pkgs = append(pkgs, Package{
				Name:      currentName,
				Version:   currentVersion,
				Ecosystem: "crates.io",
			})
		}
		currentName, currentVersion, currentSource = "", "", ""
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			flush()
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			currentName = strings.Trim(strings.TrimPrefix(line, "name = "), `"' `)
		} else if strings.HasPrefix(line, "version = ") {
			currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), `"' `)
		} else if strings.HasPrefix(line, "source = ") {
			currentSource = strings.Trim(strings.TrimPrefix(line, "source = "), `"' `)
		}
	}
	flush()
	return pkgs, scanner.Err()
}

func parseCargoToml(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	scanner := bufio.NewScanner(f)
	inDepSection := false
	// A [dependencies.name] subtable describes one dependency over several lines.
	subName, subVersion, subPackage, subLocal := "", "", "", false

	add := func(key, version, packageName string, local bool) {
		name := strings.Trim(key, `"' `)
		if packageName != "" {
			name = packageName // `alias = { package = "real-crate", ... }`
		}
		// Path and git dependencies are not crates.io releases; workspace = true
		// inherits a version reported from [workspace.dependencies].
		if name != "" && version != "" && !local {
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   cleanNPMVersion(version),
				Ecosystem: "crates.io",
			})
		}
	}
	flushSub := func() {
		if subName != "" {
			add(subName, subVersion, subPackage, subLocal)
		}
		subName, subVersion, subPackage, subLocal = "", "", "", false
	}
	isDepTable := func(sec string) bool {
		// [dependencies], [dev-dependencies], [build-dependencies],
		// [workspace.dependencies] and [target.'cfg(...)'.dependencies].
		last := sec
		if i := strings.LastIndex(sec, "."); i != -1 {
			last = sec[i+1:]
		}
		return last == "dependencies" || last == "dev-dependencies" || last == "build-dependencies"
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if i := strings.Index(line, " #"); i != -1 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flushSub()
			sec := strings.TrimSpace(strings.Trim(line, "[]"))
			inDepSection = isDepTable(sec)
			if !inDepSection {
				if i := strings.LastIndex(sec, "."); i != -1 && isDepTable(sec[:i]) {
					subName = sec[i+1:]
				}
			}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if subName != "" {
			switch key {
			case "version":
				subVersion = strings.Trim(val, `"' `)
			case "package":
				subPackage = strings.Trim(val, `"' `)
			case "path", "git", "workspace":
				subLocal = true
			}
			continue
		}
		if !inDepSection {
			continue
		}
		if strings.HasPrefix(val, "{") {
			var version, packageName string
			local := false
			for _, sub := range strings.Split(strings.Trim(val, "{}"), ",") {
				subParts := strings.SplitN(strings.TrimSpace(sub), "=", 2)
				if len(subParts) != 2 {
					continue
				}
				v := strings.Trim(strings.TrimSpace(subParts[1]), `"' `)
				switch strings.TrimSpace(subParts[0]) {
				case "version":
					version = v
				case "package":
					packageName = v
				case "path", "git", "workspace":
					local = true
				}
			}
			add(key, version, packageName, local)
		} else {
			add(key, strings.Trim(val, `"' `), "", false)
		}
	}
	flushSub()
	return pkgs, scanner.Err()
}

// ── PHP (composer.json) ───────────────────────────────────────────────────────

func parseComposer(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("invalid composer.json: %w", err)
	}
	var pkgs []Package
	addDep := func(name, version string) {
		name = strings.TrimSpace(name)
		if name == "php" || strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-") {
			return
		}
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: "Packagist",
		})
	}
	for name, version := range manifest.Require {
		addDep(name, version)
	}
	for name, version := range manifest.RequireDev {
		addDep(name, version)
	}
	return pkgs, nil
}

// ── Ruby (Gemfile.lock) ──────────────────────────────────────────────────────

func parseRubyGem(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	scanner := bufio.NewScanner(f)
	inSpecs := false

	for scanner.Scan() {
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs && (trimmed == "" || (!strings.HasPrefix(rawLine, " ") && !strings.HasPrefix(rawLine, "\t"))) {
			inSpecs = false
			continue
		}
		if inSpecs {
			if strings.HasPrefix(rawLine, "    ") && !strings.HasPrefix(rawLine, "      ") {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 && strings.HasPrefix(fields[1], "(") && strings.HasSuffix(fields[1], ")") {
					version := strings.Trim(fields[1], "()")
					// Platform gems are listed as "1.10.0-x86_64-linux". RubyGems
					// versions never contain "-", so the rest is the platform.
					version = strings.SplitN(version, "-", 2)[0]
					pkgs = append(pkgs, Package{
						Name:      fields[0],
						Version:   version,
						Ecosystem: "RubyGems",
					})
				}
			}
		}
	}
	return pkgs, scanner.Err()
}

// ── npm lockfile (package-lock.json v1, v2, v3) ──────────────────────────────

func parseNPMLock(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var lockfile struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("invalid package-lock.json: %w", err)
	}

	seen := make(map[string]bool)
	var pkgs []Package

	// v2/v3 packages map: "node_modules/foo": { "version": "1.0.0" }
	if len(lockfile.Packages) > 0 {
		for key, val := range lockfile.Packages {
			if key == "" || val.Version == "" {
				continue
			}
			idx := strings.LastIndex(key, "node_modules/")
			if idx == -1 {
				continue
			}
			pkgName := key[idx+len("node_modules/"):]
			if pkgName == "" {
				continue
			}
			// An aliased install ("alias": "npm:real@1.0.0") records the real
			// package name; the directory only carries the alias.
			if val.Name != "" {
				pkgName = val.Name
			}
			uniqueKey := pkgName + "@" + val.Version
			if !seen[uniqueKey] {
				seen[uniqueKey] = true
				pkgs = append(pkgs, Package{
					Name:      pkgName,
					Version:   val.Version,
					Ecosystem: "npm",
				})
			}
		}
		if len(pkgs) > 0 {
			return pkgs, nil
		}
	}

	// v1 fallback: recursive dependencies map
	var parseV1Deps func(deps map[string]json.RawMessage)
	parseV1Deps = func(deps map[string]json.RawMessage) {
		for name, raw := range deps {
			var dep struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if err := json.Unmarshal(raw, &dep); err == nil {
				if dep.Version != "" {
					name := name
					// v1 records an alias as "version": "npm:real@1.0.0".
					if real, version := splitNPMSpec(strings.TrimPrefix(dep.Version, "npm:")); strings.HasPrefix(dep.Version, "npm:") && version != "" {
						name, dep.Version = real, version
					}
					uniqueKey := name + "@" + dep.Version
					if !seen[uniqueKey] {
						seen[uniqueKey] = true
						pkgs = append(pkgs, Package{
							Name:      name,
							Version:   dep.Version,
							Ecosystem: "npm",
						})
					}
				}
				if len(dep.Dependencies) > 0 {
					parseV1Deps(dep.Dependencies)
				}
			}
		}
	}

	var root struct {
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &root); err == nil && len(root.Dependencies) > 0 {
		parseV1Deps(root.Dependencies)
	}

	return pkgs, nil
}

// splitNPMSpec splits "name@rest" into its parts, keeping the leading @ of a
// scoped name. Without a separating @ the whole spec is the name.
func splitNPMSpec(spec string) (string, string) {
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}
	i := strings.Index(spec[start:], "@")
	if i < 0 {
		return spec, ""
	}
	return spec[:start+i], spec[start+i+1:]
}

// ── Yarn lockfile (yarn.lock) ────────────────────────────────────────────────

func parseYarnLock(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	var currentPkgName string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			if strings.Contains(trimmed, "@workspace:") || trimmed == "__metadata:" {
				currentPkgName = ""
				continue
			}
			entry := strings.TrimSuffix(trimmed, ":")
			firstPart := strings.Trim(strings.Split(entry, ",")[0], `" `)
			name, descriptor := splitNPMSpec(firstPart)
			// "alias@npm:real-package@^1.0.0" installs real-package.
			if real, version := splitNPMSpec(strings.TrimPrefix(descriptor, "npm:")); strings.HasPrefix(descriptor, "npm:") && version != "" {
				name = real
			}
			currentPkgName = name
			continue
		}

		if currentPkgName != "" && (strings.HasPrefix(trimmed, "version ") || strings.HasPrefix(trimmed, "version:")) {
			version := strings.Trim(strings.TrimPrefix(strings.TrimPrefix(trimmed, "version "), "version:"), `" `)
			if version != "" {
				uniqueKey := currentPkgName + "@" + version
				if !seen[uniqueKey] {
					seen[uniqueKey] = true
					pkgs = append(pkgs, Package{
						Name:      currentPkgName,
						Version:   version,
						Ecosystem: "npm",
					})
				}
			}
			currentPkgName = ""
		}
	}

	return pkgs, scanner.Err()
}

// ── pnpm lockfile (pnpm-lock.yaml) ───────────────────────────────────────────

func parsePnpmLock(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	inPackages := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "packages:" {
			inPackages = true
			continue
		}
		if inPackages && (!strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && trimmed != "") {
			inPackages = false
			continue
		}
		if inPackages && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(trimmed, ":") {
			pkgSpec := strings.TrimSuffix(trimmed, ":")
			pkgSpec = strings.Trim(pkgSpec, `"' `)
			pkgSpec = strings.TrimPrefix(pkgSpec, "/")
			pkgSpec = strings.SplitN(pkgSpec, "(", 2)[0]
			lastAt := strings.Index(pkgSpec, "@")
			if strings.HasPrefix(pkgSpec, "@") {
				lastAt = strings.Index(pkgSpec[1:], "@") + 1
			}
			if slash := strings.LastIndex(pkgSpec, "/"); slash > 0 && (!strings.HasPrefix(pkgSpec, "@") || strings.Contains(pkgSpec[:slash], "/")) {
				pkgSpec = pkgSpec[:slash] + "@" + pkgSpec[slash+1:]
				lastAt = slash
			}
			if lastAt > 0 {
				name := pkgSpec[:lastAt]
				version := pkgSpec[lastAt+1:]
				if idx := strings.Index(version, "_"); idx != -1 {
					version = version[:idx]
				}
				name = strings.TrimSpace(name)
				version = strings.TrimSpace(version)
				if name != "" && version != "" {
					uniqueKey := name + "@" + version
					if !seen[uniqueKey] {
						seen[uniqueKey] = true
						pkgs = append(pkgs, Package{
							Name:      name,
							Version:   version,
							Ecosystem: "npm",
						})
					}
				}
			}
		}
	}

	return pkgs, scanner.Err()
}

// ── Python pyproject.toml (PEP 621 & Poetry) ──────────────────────────────────

func parsePEP508Spec(spec string) (string, string) {
	// Strip environment markers (e.g., ; python_version >= "3.11")
	spec = strings.Split(spec, ";")[0]
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ""
	}

	// A direct reference (name @ url) has no registry version to check.
	if at := strings.Index(spec, "@"); at > 0 && !strings.ContainsAny(spec[:at], "=<>!~") {
		name := strings.TrimSpace(strings.Split(spec[:at], "[")[0])
		if name == "" || strings.TrimSpace(spec[at+1:]) == "" {
			return "", ""
		}
		return name, "@ " + strings.TrimSpace(spec[at+1:])
	}

	// Find earliest version comparison operator
	operators := []string{"===", "==", "~=", ">=", "<=", "!=", ">", "<"}
	minIdx := -1
	matchedOp := ""
	for _, op := range operators {
		if idx := strings.Index(spec, op); idx != -1 {
			if minIdx == -1 || idx < minIdx {
				minIdx = idx
				matchedOp = op
			}
		}
	}

	var rawName, rawVer string
	if minIdx != -1 {
		rawName = spec[:minIdx]
		rawVer = spec[minIdx:]
		// PEP 508 allows whitespace around the operator: "urllib3 == 1.26.4".
		if pinned := strings.TrimSpace(rawVer[2:]); matchedOp == "==" && !strings.ContainsAny(pinned, ",* ") {
			rawVer = pinned
		}
	} else {
		rawName = spec
		rawVer = "latest"
	}

	// Strip extras e.g. requests[security] -> requests
	rawName = strings.Split(rawName, "[")[0]
	rawName = strings.TrimSpace(rawName)
	rawVer = strings.TrimSpace(rawVer)

	if rawName == "" || rawVer == "" {
		return "", ""
	}
	return rawName, rawVer
}

// Inline tables in dependency groups ({include-group = "test"}) name other
// groups, not packages.
var inlineTableRe = regexp.MustCompile(`\{[^}]*\}`)

func parsePyProjectToml(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	seen := make(map[string]bool)
	addPkg := func(name, version string) {
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if name == "" || version == "" || strings.EqualFold(name, "python") {
			return
		}
		key := name + "@" + version
		if !seen[key] {
			seen[key] = true
			pkgs = append(pkgs, Package{
				Name:         name,
				Version:      version,
				Ecosystem:    "PyPI",
				ManifestPath: filePath,
			})
		}
	}

	var dependencyQuoteError error
	extractQuotedStrings := func(s string) []string {
		var res []string
		for {
			idx1 := strings.IndexAny(s, `"'`)
			if idx1 == -1 {
				break
			}
			quote := s[idx1]
			rest := s[idx1+1:]
			idx2 := strings.IndexByte(rest, quote)
			if idx2 == -1 {
				dependencyQuoteError = fmt.Errorf("unterminated dependency string in %s", filePath)
				break
			}
			res = append(res, rest[:idx2])
			s = rest[idx2+1:]
		}
		return res
	}

	hasUnquotedBracket := func(s string, bracket byte) bool {
		var quote byte
		for i := 0; i < len(s); i++ {
			c := s[i]
			if quote != 0 {
				if c == quote && (i == 0 || s[i-1] != '\\') {
					quote = 0
				}
				continue
			}
			if c == '"' || c == '\'' {
				quote = c
				continue
			}
			if c == bracket {
				return true
			}
		}
		return false
	}

	isArraySection := func(section, key string) bool {
		switch section {
		case "project":
			return key == "dependencies"
		case "tool.uv":
			return key == "dev-dependencies"
		case "project.optional-dependencies", "dependency-groups", "tool.pdm.dev-dependencies":
			return true
		}
		return false
	}
	isPoetrySection := func(section string) bool {
		return section == "tool.poetry.dependencies" ||
			section == "tool.poetry.dev-dependencies" ||
			(strings.HasPrefix(section, "tool.poetry.group.") && strings.HasSuffix(section, ".dependencies"))
	}

	scanner := bufio.NewScanner(f)
	section := ""
	inArray := false
	poetrySubtable := "" // [tool.poetry.dependencies.name]

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments outside quotes if simple
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && !strings.HasPrefix(line, "[[") && !inArray {
			section = strings.Trim(line, "[] ")
			inArray = false
			poetrySubtable = ""
			if i := strings.LastIndex(section, "."); i != -1 && isPoetrySection(section[:i]) {
				poetrySubtable = strings.Trim(section[i+1:], `"'`)
			}
			continue
		}

		if poetrySubtable != "" {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 && strings.TrimSpace(parts[0]) == "version" {
				addPkg(poetrySubtable, cleanNPMVersion(strings.Trim(strings.TrimSpace(parts[1]), `"' `)))
			}
			continue
		}

		// 1. PEP 621 [project] dependencies, optional dependencies, dependency
		// groups, and the uv and PDM development dependency lists.
		if section == "project" || section == "tool.uv" || isArraySection(section, "") {
			if !inArray {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				if !isArraySection(section, key) {
					continue
				}
				if strings.HasPrefix(val, "[") {
					for _, item := range extractQuotedStrings(inlineTableRe.ReplaceAllString(val, "")) {
						name, ver := parsePEP508Spec(item)
						addPkg(name, ver)
					}
					if !hasUnquotedBracket(val[1:], ']') {
						inArray = true
					}
				}
			} else {
				for _, item := range extractQuotedStrings(inlineTableRe.ReplaceAllString(line, "")) {
					name, ver := parsePEP508Spec(item)
					addPkg(name, ver)
				}
				if hasUnquotedBracket(line, ']') {
					inArray = false
				}
			}
			continue
		}

		// 2. Handle Poetry [tool.poetry.dependencies], [tool.poetry.dev-dependencies], [tool.poetry.group.*.dependencies]
		if isPoetrySection(section) {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			var version string
			if strings.HasPrefix(val, "{") {
				for _, sub := range strings.Split(strings.Trim(val, "{}"), ",") {
					subParts := strings.SplitN(strings.TrimSpace(sub), "=", 2)
					if len(subParts) == 2 && strings.TrimSpace(subParts[0]) == "version" {
						version = strings.Trim(strings.TrimSpace(subParts[1]), `"' `)
						break
					}
				}
			} else {
				version = strings.Trim(val, `"' `)
			}
			version = cleanNPMVersion(version)
			addPkg(name, version)
		}
	}

	return pkgs, errors.Join(scanner.Err(), dependencyQuoteError)
}

// ── Python Poetry lockfile (poetry.lock) ──────────────────────────────────────

func parsePoetryLock(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	var currentName, currentVersion string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if currentName != "" && currentVersion != "" {
				key := currentName + "@" + currentVersion
				if !seen[key] {
					seen[key] = true
					pkgs = append(pkgs, Package{
						Name:      currentName,
						Version:   currentVersion,
						Ecosystem: "PyPI",
					})
				}
			}
			currentName = ""
			currentVersion = ""
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			currentName = strings.Trim(strings.TrimPrefix(line, "name = "), `"' `)
		} else if strings.HasPrefix(line, "version = ") {
			currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), `"' `)
		}
	}
	if currentName != "" && currentVersion != "" {
		key := currentName + "@" + currentVersion
		if !seen[key] {
			seen[key] = true
			pkgs = append(pkgs, Package{
				Name:      currentName,
				Version:   currentVersion,
				Ecosystem: "PyPI",
			})
		}
	}
	return pkgs, scanner.Err()
}

// ── Python Pipenv lockfile (Pipfile.lock) ──────────────────────────────────────

func parsePipfileLock(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var lockfile struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}

	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("invalid Pipfile.lock: %w", err)
	}

	seen := make(map[string]bool)
	var pkgs []Package

	addDep := func(name, ver string) {
		ver = strings.TrimLeft(ver, "=~<>^")
		ver = strings.TrimSpace(ver)
		name = strings.TrimSpace(name)
		if name != "" && ver != "" {
			key := name + "@" + ver
			if !seen[key] {
				seen[key] = true
				pkgs = append(pkgs, Package{
					Name:      name,
					Version:   ver,
					Ecosystem: "PyPI",
				})
			}
		}
	}

	for name, val := range lockfile.Default {
		addDep(name, val.Version)
	}
	for name, val := range lockfile.Develop {
		addDep(name, val.Version)
	}

	return pkgs, nil
}

// ── PHP Composer lockfile (composer.lock) ─────────────────────────────────────

func parseComposerLock(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var lockfile struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}

	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("invalid composer.lock: %w", err)
	}

	seen := make(map[string]bool)
	var pkgs []Package

	addDep := func(name, ver string) {
		name = strings.TrimSpace(name)
		ver = strings.TrimPrefix(strings.TrimSpace(ver), "v")
		if name == "php" || strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-") {
			return
		}
		if name != "" && ver != "" {
			key := name + "@" + ver
			if !seen[key] {
				seen[key] = true
				pkgs = append(pkgs, Package{
					Name:      name,
					Version:   ver,
					Ecosystem: "Packagist",
				})
			}
		}
	}

	for _, p := range lockfile.Packages {
		addDep(p.Name, p.Version)
	}
	for _, p := range lockfile.PackagesDev {
		addDep(p.Name, p.Version)
	}

	return pkgs, nil
}

// ── Go Checksum lockfile (go.sum) ─────────────────────────────────────────────

func parseGoSum(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			module := parts[0]
			version := parts[1]
			if strings.HasSuffix(version, "/go.mod") {
				continue
			}
			version = strings.TrimSpace(version)
			key := module + "@" + version
			if !seen[key] {
				seen[key] = true
				pkgs = append(pkgs, Package{
					Name:      module,
					Version:   version,
					Ecosystem: "Go",
				})
			}
		}
	}

	return pkgs, scanner.Err()
}

// ── .NET NuGet lockfile (packages.lock.json) ──────────────────────────────────

func parseNuGetLock(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var lockfile struct {
		Dependencies map[string]map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("invalid packages.lock.json: %w", err)
	}

	seen := make(map[string]bool)
	var pkgs []Package

	for _, fwDeps := range lockfile.Dependencies {
		for name, dep := range fwDeps {
			if dep.Resolved != "" {
				key := name + "@" + dep.Resolved
				if !seen[key] {
					seen[key] = true
					pkgs = append(pkgs, Package{
						Name:      name,
						Version:   dep.Resolved,
						Ecosystem: "NuGet",
					})
				}
			}
		}
	}

	return pkgs, nil
}

// ── C / C++ (Conan & vcpkg) ──────────────────────────────────────────────────

// parseConanFile parses dependencies from conanfile.txt.
func parseConanFile(filePath string) ([]Package, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var pkgs []Package
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	inRequires := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Check for section headers [section]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inRequires = strings.EqualFold(line, "[requires]")
			continue
		}

		if !inRequires {
			continue
		}

		// Remove trailing inline comments if preceded by whitespace
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		} else if idx := strings.Index(line, " ;"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// Conan requirement line: e.g. "openssl/3.1.4", "openssl/3.1.4@user/channel", "openssl/3.1.4#rev"
		line = strings.Split(line, "#")[0]
		line = strings.Split(line, "@")[0]
		line = strings.TrimSpace(line)

		parts := strings.Split(line, "/")
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			version := strings.TrimSpace(parts[1])
			if name != "" && version != "" {
				key := name + "@" + version
				if !seen[key] {
					seen[key] = true
					pkgs = append(pkgs, Package{
						Name:         name,
						Version:      version,
						Ecosystem:    "ConanCenter",
						ManifestPath: filePath,
					})
				}
			}
		}
	}

	return pkgs, scanner.Err()
}

// parseConanLock parses dependencies from conan.lock (supports Conan 1.x and 2.x formats).
func parseConanLock(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	type conanNode struct {
		Ref string `json:"ref"`
	}

	var root struct {
		GraphLock struct {
			Nodes json.RawMessage `json:"nodes"`
		} `json:"graph_lock"`
		Nodes json.RawMessage `json:"nodes"`
		// Conan 2 lockfiles list references directly.
		Requires       []string `json:"requires"`
		BuildRequires  []string `json:"build_requires"`
		PythonRequires []string `json:"python_requires"`
	}

	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("invalid conan.lock: %w", err)
	}

	nodesRaw := root.GraphLock.Nodes
	if len(nodesRaw) == 0 {
		nodesRaw = root.Nodes
	}

	var nodesList []conanNode
	for _, refs := range [][]string{root.Requires, root.BuildRequires, root.PythonRequires} {
		for _, ref := range refs {
			nodesList = append(nodesList, conanNode{Ref: ref})
		}
	}

	// Conan 1 graph lock nodes, as a map keyed by node ID or as a list.
	var nodesMap map[string]conanNode
	if len(nodesRaw) == 0 {
		nodesRaw = []byte("null")
	}
	if err := json.Unmarshal(nodesRaw, &nodesMap); err == nil {
		for key, node := range nodesMap {
			// In Conan, node "0" is always the root consumer project
			if key == "0" {
				continue
			}
			nodesList = append(nodesList, node)
		}
	} else {
		// Try unmarshaling as slice []conanNode
		var slice []conanNode
		if err := json.Unmarshal(nodesRaw, &slice); err == nil {
			if len(slice) > 1 {
				slice = slice[1:] // Skip root consumer node 0
			}
			nodesList = append(nodesList, slice...)
		}
	}

	var pkgs []Package
	seen := make(map[string]bool)

	for _, n := range nodesList {
		ref := strings.TrimSpace(n.Ref)
		if ref == "" || ref == "null" {
			continue
		}

		// ref format: "openssl/3.1.4#rev..." or "openssl/3.1.4@user/channel#rev"
		ref = strings.Split(ref, "#")[0]
		ref = strings.Split(ref, "@")[0]
		ref = strings.TrimSpace(ref)

		parts := strings.Split(ref, "/")
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			version := strings.TrimSpace(parts[1])
			if name != "" && version != "" {
				key := name + "@" + version
				if !seen[key] {
					seen[key] = true
					pkgs = append(pkgs, Package{
						Name:         name,
						Version:      version,
						Ecosystem:    "ConanCenter",
						ManifestPath: filePath,
					})
				}
			}
		}
	}

	return pkgs, nil
}

// parseVcpkg parses dependencies from Microsoft vcpkg (vcpkg.json).
func parseVcpkg(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var manifest struct {
		Dependencies []json.RawMessage `json:"dependencies"`
		Overrides    []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"overrides"`
	}

	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("invalid vcpkg.json: %w", err)
	}

	overrides := make(map[string]string)
	for _, o := range manifest.Overrides {
		if o.Name != "" && o.Version != "" {
			overrides[o.Name] = o.Version
		}
	}

	var pkgs []Package
	seen := make(map[string]bool)

	for _, depRaw := range manifest.Dependencies {
		var name, version string

		// Try parsing as simple string "zlib"
		var simple string
		if err := json.Unmarshal(depRaw, &simple); err == nil && simple != "" {
			name = simple
		} else {
			// Try parsing as dependency object
			var depObj struct {
				Name          string `json:"name"`
				Version       string `json:"version"`
				VersionGE     string `json:"version>="`
				VersionString string `json:"version-string"`
				VersionDate   string `json:"version-date"`
			}
			if err := json.Unmarshal(depRaw, &depObj); err == nil {
				name = depObj.Name
				switch {
				case depObj.Version != "":
					version = depObj.Version
				case depObj.VersionGE != "":
					version = ">=" + depObj.VersionGE
				case depObj.VersionString != "":
					version = depObj.VersionString
				case depObj.VersionDate != "":
					version = depObj.VersionDate
				}
			}
		}

		if name == "" {
			continue
		}

		// Overrides take precedence
		if ov, ok := overrides[name]; ok {
			version = ov
		}

		if version == "" {
			version = "latest"
		}

		key := name + "@" + version
		if !seen[key] {
			seen[key] = true
			pkgs = append(pkgs, Package{
				Name:         name,
				Version:      version,
				Ecosystem:    "ConanCenter",
				ManifestPath: filePath,
			})
		}
	}

	return pkgs, nil
}

// candidateConfigExts are file extensions inspected by content when scanning a directory.
var candidateConfigExts = map[string]bool{
	".json":    true,
	".toml":    true,
	".lock":    true,
	".xml":     true,
	".csproj":  true,
	".fsproj":  true,
	".vbproj":  true,
	".props":   true,
	".config":  true,
	".gradle":  true,
	".kts":     true,
	".yaml":    true,
	".yml":     true,
	".cfg":     true,
	".in":      true,
	".gemspec": true,
	".exs":     true,
}

func isCandidateDependencyFile(fileName string) bool {
	if IsManifestFile(fileName) {
		return true
	}
	base := filepath.Base(fileName)
	lower := strings.ToLower(base)

	switch lower {
	case "pipfile", "gemfile", "podfile", "podfile.lock", "gradle.lockfile",
		"setup.py", "setup.cfg", "conanfile.py", "package.resolved", "mix.exs", "mix.lock",
		"cmakelists.txt":
		return true
	}

	if strings.HasSuffix(lower, ".txt") &&
		(strings.Contains(lower, "req") || strings.Contains(lower, "constraint") || strings.Contains(lower, "conan")) {
		return true
	}

	ext := strings.ToLower(filepath.Ext(base))
	return candidateConfigExts[ext]
}

// DiscoverDependencies walks rootDir to discover dependencies across manifests, lockfiles,
// installed environments (venv, node_modules, vendor, obj/project.assets.json, vcpkg_installed, .dart_tool),
// and source-code imports across all supported languages.
func DiscoverDependencies(rootDir string) ([]Package, []string, error) {
	var discoveryIssues []error
	dirFiles := make(map[string][]string)
	var venvDirs []string
	var nodeModulesDirs []string
	var vendorDirs []string
	var dotNetAssetFiles []string
	var vcpkgStatusFiles []string
	var dartPackageConfigs []string
	localModuleNames := make(map[string]bool)

	rootErr := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// The root must be readable; below it, an unreadable directory or
			// file makes the scan incomplete without discarding what was read.
			if filepath.Clean(path) == filepath.Clean(rootDir) {
				return err
			}
			discoveryIssues = append(discoveryIssues, fmt.Errorf("read %s: %w", path, err))
			return continueAfterWalkError(d)
		}
		if d.IsDir() {
			name := d.Name()
			isRoot := filepath.Clean(path) == filepath.Clean(rootDir)
			// A virtual environment is recognised by pyvenv.cfg whatever its
			// name; venv and .venv are also accepted by name.
			if !isRoot && (name == "venv" || name == ".venv" || isVirtualEnv(path)) {
				venvDirs = append(venvDirs, path)
				return filepath.SkipDir
			}
			if name == "node_modules" {
				nodeModulesDirs = append(nodeModulesDirs, path)
				return filepath.SkipDir
			}
			if name == "vendor" {
				vendorDirs = append(vendorDirs, path)
				return filepath.SkipDir
			}
			if name == "obj" {
				assets := filepath.Join(path, "project.assets.json")
				if _, statErr := os.Stat(assets); statErr == nil {
					dotNetAssetFiles = append(dotNetAssetFiles, assets)
				} else if !os.IsNotExist(statErr) {
					discoveryIssues = append(discoveryIssues, fmt.Errorf("stat %s: %w", assets, statErr))
				}
				return filepath.SkipDir
			}
			if name == "vcpkg_installed" {
				statusFile := filepath.Join(path, "vcpkg", "status")
				if _, statErr := os.Stat(statusFile); statErr == nil {
					vcpkgStatusFiles = append(vcpkgStatusFiles, statusFile)
				} else if !os.IsNotExist(statErr) {
					discoveryIssues = append(discoveryIssues, fmt.Errorf("stat %s: %w", statusFile, statErr))
				}
				return filepath.SkipDir
			}
			if name == ".dart_tool" {
				pkgCfg := filepath.Join(path, "package_config.json")
				if _, statErr := os.Stat(pkgCfg); statErr == nil {
					dartPackageConfigs = append(dartPackageConfigs, pkgCfg)
				} else if !os.IsNotExist(statErr) {
					discoveryIssues = append(discoveryIssues, fmt.Errorf("stat %s: %w", pkgCfg, statErr))
				}
				return filepath.SkipDir
			}
			if skipSourceDir(path, rootDir) {
				return filepath.SkipDir
			}
			if _, statErr := os.Stat(filepath.Join(path, "__init__.py")); statErr == nil {
				localModuleNames[strings.ToLower(name)] = true
			}
			return nil
		}

		fileName := d.Name()
		if fileName == "project.assets.json" {
			dotNetAssetFiles = append(dotNetAssetFiles, path)
			return nil
		}

		if isCandidateDependencyFile(fileName) {
			dir := filepath.Dir(path)
			dirFiles[dir] = append(dirFiles[dir], path)
		}
		return nil
	})
	if rootErr != nil {
		return nil, nil, &DiscoveryError{Issues: []error{rootErr}}
	}

	var discoveredSources []string
	var manifestPkgs []Package
	lockDirs := make(map[string]map[string]bool)
	hasLock := func(dir, eco string) bool { return lockDirs[filepath.Clean(dir)][eco] }
	coveredEcosystems := make(map[string]map[string]bool)
	cover := func(dir, eco string) {
		dir = filepath.Clean(dir)
		if coveredEcosystems[dir] == nil {
			coveredEcosystems[dir] = make(map[string]bool)
		}
		coveredEcosystems[dir][eco] = true
	}
	appendEnv := func(pkgs []Package, projectDir string) []Package {
		for i := range pkgs {
			pkgs[i].ProjectPath = filepath.Clean(projectDir)
			pkgs[i].VersionSource = "installed"
		}
		return pkgs
	}

	var dirs []string
	for dir := range dirFiles {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		selected := filterDirManifests(dirFiles[dir])
		for _, file := range selected {
			pkgs, parseErr := ParseManifest(file)
			if parseErr != nil {
				if isNamedDependencyFile(filepath.Base(file)) {
					// Keep scanning: other manifests are still checked, and the
					// scan is reported as incomplete.
					discoveryIssues = append(discoveryIssues, fmt.Errorf("parse %s: %w", file, parseErr))
					discoveredSources = append(discoveredSources, file)
					cover(dir, dependencyFileEcosystem(file))
				}
				continue
			}
			if len(pkgs) == 0 && !IsManifestFile(file) {
				continue
			}
			discoveredSources = append(discoveredSources, file)
			cover(dir, dependencyFileEcosystem(file))
			base := strings.ToLower(filepath.Base(file))
			if lockDirs[dir] == nil {
				lockDirs[dir] = make(map[string]bool)
			}
			switch {
			case strings.HasSuffix(base, "poetry.lock"), strings.HasSuffix(base, "pipfile.lock"), strings.HasSuffix(base, "uv.lock"), strings.HasSuffix(base, "pdm.lock"):
				lockDirs[dir]["PyPI"] = true
			case strings.HasSuffix(base, "package-lock.json"), strings.HasSuffix(base, "yarn.lock"), strings.HasSuffix(base, "pnpm-lock.yaml"):
				lockDirs[dir]["npm"] = true
			case strings.HasSuffix(base, "go.mod"):
				lockDirs[dir]["Go"] = true
			case strings.HasSuffix(base, "composer.lock"):
				lockDirs[dir]["Packagist"] = true
			case strings.HasSuffix(base, "gemfile.lock"):
				lockDirs[dir]["RubyGems"] = true
			case strings.HasSuffix(base, "packages.lock.json"):
				lockDirs[dir]["NuGet"] = true
			case strings.HasSuffix(base, "conan.lock"):
				lockDirs[dir]["ConanCenter"] = true
			case strings.HasSuffix(base, "pubspec.lock"):
				lockDirs[dir]["Pub"] = true
			}
			manifestPkgs = append(manifestPkgs, pkgs...)
		}
	}

	type environment struct {
		path, project, eco string
		read               func() ([]Package, error)
	}
	var environments []environment
	for _, dir := range venvDirs {
		environments = append(environments, environment{dir, filepath.Dir(dir), "PyPI", func() ([]Package, error) { return inspectPythonVenv(dir, localModuleNames) }})
	}
	for _, dir := range nodeModulesDirs {
		environments = append(environments, environment{dir, filepath.Dir(dir), "npm", func() ([]Package, error) { return inspectNodeModules(dir) }})
	}
	for _, dir := range vendorDirs {
		environments = append(environments,
			environment{filepath.Join(dir, "modules.txt"), filepath.Dir(dir), "Go", func() ([]Package, error) { return inspectGoVendorModules(filepath.Join(dir, "modules.txt")) }},
			environment{filepath.Join(dir, "composer", "installed.json"), filepath.Dir(dir), "Packagist", func() ([]Package, error) {
				return inspectComposerInstalled(filepath.Join(dir, "composer", "installed.json"))
			}},
			environment{filepath.Join(dir, "bundle"), filepath.Dir(dir), "RubyGems", func() ([]Package, error) { return inspectRubyVendorBundle(dir) }})
	}
	for _, path := range dotNetAssetFiles {
		environments = append(environments, environment{path, filepath.Dir(filepath.Dir(path)), "NuGet", func() ([]Package, error) { return inspectDotNetAssets(path) }})
	}
	for _, path := range vcpkgStatusFiles {
		environments = append(environments, environment{path, filepath.Dir(filepath.Dir(filepath.Dir(path))), "ConanCenter", func() ([]Package, error) { return inspectVcpkgStatus(path) }})
	}
	for _, path := range dartPackageConfigs {
		environments = append(environments, environment{path, filepath.Dir(filepath.Dir(path)), "Pub", func() ([]Package, error) { return inspectDartPackageConfig(path) }})
	}
	var envPkgs []Package
	for _, env := range environments {
		if hasLock(env.project, env.eco) {
			continue
		}
		pkgs, err := env.read()
		if err != nil {
			discoveryIssues = append(discoveryIssues, fmt.Errorf("inspect %s: %w", env.path, err))
		}
		if len(pkgs) > 0 || err != nil {
			discoveredSources = append(discoveredSources, env.path)
			cover(env.project, env.eco)
		}
		envPkgs = append(envPkgs, appendEnv(pkgs, env.project)...)
	}

	finalPkgs := mergeManifestAndEnvPackages(manifestPkgs, envPkgs)

	// A dependency source covers imports of its own ecosystem in its directory
	// and below. A package.json says nothing about the Python imports beside it.
	for _, pkg := range finalPkgs {
		cover(pkg.ProjectPath, pkg.Ecosystem)
	}
	covered := func(p Package) bool {
		for dir := filepath.Dir(p.ManifestPath); ; dir = filepath.Dir(dir) {
			if coveredEcosystems[filepath.Clean(dir)][p.Ecosystem] {
				return true
			}
			parent := filepath.Dir(dir)
			if parent == dir || dir == filepath.Clean(rootDir) {
				return false
			}
		}
	}
	srcPkgs, _, srcErr := scanSourceCodeImports(rootDir)
	if srcErr != nil {
		discoveryIssues = append(discoveryIssues, srcErr)
	}
	seenSource := make(map[string]bool)
	for _, p := range srcPkgs {
		if covered(p) {
			continue
		}
		finalPkgs = append(finalPkgs, p)
		if !seenSource[p.ManifestPath] {
			discoveredSources = append(discoveredSources, p.ManifestPath)
			seenSource[p.ManifestPath] = true
		}
	}

	if len(discoveryIssues) > 0 {
		return finalPkgs, discoveredSources, &DiscoveryError{Issues: discoveryIssues}
	}
	return finalPkgs, discoveredSources, nil
}

// dependencyFileEcosystem names the ecosystem a dependency file declares, so
// that a manifest without dependencies still covers its own imports.
func dependencyFileEcosystem(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
		return "npm"
	case "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock", "uv.lock", "pdm.lock", "setup.py", "setup.cfg", "environment.yml", "environment.yaml":
		return "PyPI"
	case "go.mod", "go.sum":
		return "Go"
	case "cargo.toml", "cargo.lock":
		return "crates.io"
	case "composer.json", "composer.lock":
		return "Packagist"
	case "gemfile", "gemfile.lock":
		return "RubyGems"
	case "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "libs.versions.toml":
		return "Maven"
	case "packages.config", "packages.lock.json", "directory.packages.props", "paket.lock", "paket.dependencies":
		return "NuGet"
	case "conanfile.txt", "conanfile.py", "conan.lock", "vcpkg.json", "cmakelists.txt":
		return "ConanCenter"
	case "pubspec.yaml", "pubspec.lock":
		return "Pub"
	case "mix.exs", "mix.lock":
		return "Hex"
	case "package.swift", "package.resolved":
		return "SwiftURL"
	}
	switch {
	case strings.HasSuffix(base, "requirements.txt"):
		return "PyPI"
	case strings.HasSuffix(base, ".gemspec"):
		return "RubyGems"
	case strings.HasSuffix(base, ".csproj"), strings.HasSuffix(base, ".fsproj"), strings.HasSuffix(base, ".vbproj"):
		return "NuGet"
	}
	return ""
}

func mergeManifestAndEnvPackages(manifestPkgs, envPkgs []Package) []Package {
	if len(envPkgs) == 0 {
		var result []Package
		seen := make(map[string]bool)
		for _, p := range manifestPkgs {
			k := p.Key()
			if !seen[k] {
				seen[k] = true
				result = append(result, p)
			}
		}
		return result
	}

	manifestPathByPkg := make(map[string]string)
	envHasPkg := make(map[string]bool)

	normKey := func(name, eco string) string {
		if eco == "PyPI" {
			name = strings.ReplaceAll(strings.ToLower(name), "_", "-")
		}
		return strings.ToLower(name) + "@" + eco
	}

	for _, mp := range manifestPkgs {
		nk := normKey(mp.Name, mp.Ecosystem) + "@" + mp.ProjectPath
		if manifestPathByPkg[nk] == "" {
			manifestPathByPkg[nk] = mp.ManifestPath
		}
	}

	var merged []Package
	seen := make(map[string]bool)

	for _, ep := range envPkgs {
		nk := normKey(ep.Name, ep.Ecosystem) + "@" + ep.ProjectPath
		envHasPkg[nk] = true
		if mPath, ok := manifestPathByPkg[nk]; ok && mPath != "" {
			ep.ManifestPath = mPath
		}
		k := ep.Key()
		if !seen[k] {
			seen[k] = true
			merged = append(merged, ep)
		}
	}

	// The installed version is what actually runs, so it replaces the declared
	// one, including an exact pin that the environment does not match. An
	// environment serves manifests in its project directory and below
	// (requirements/base.txt beside a root .venv).
	installed := func(mp Package) bool {
		for dir := filepath.Clean(mp.ProjectPath); ; dir = filepath.Dir(dir) {
			if envHasPkg[normKey(mp.Name, mp.Ecosystem)+"@"+dir] {
				return true
			}
			if filepath.Dir(dir) == dir {
				return false
			}
		}
	}
	for _, mp := range manifestPkgs {
		if !installed(mp) {
			k := mp.Key()
			if !seen[k] {
				seen[k] = true
				merged = append(merged, mp)
			}
		}
	}

	return merged
}

var defaultVenvSkipPkgs = map[string]bool{
	"pip":        true,
	"setuptools": true,
	"wheel":      true,
	"distribute": true,
}

var gemspecFileRe = regexp.MustCompile(`^(.+)-([0-9]+\.[0-9]+(?:\.[0-9a-zA-Z._-]+)?)\.gemspec$`)

func parseByContent(filePath string) ([]Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	base := filepath.Base(filePath)
	lowerBase := strings.ToLower(base)
	ext := strings.ToLower(filepath.Ext(base))

	if trimmed[0] == '{' {
		if pkgs, ok := tryParseGenericJSON(filePath, trimmed); ok {
			return pkgs, nil
		}
	}

	if trimmed[0] == '<' {
		if pkgs, ok := tryParseGenericXML(filePath, trimmed); ok {
			return pkgs, nil
		}
	}

	if ext == ".gradle" || strings.HasSuffix(lowerBase, ".gradle.kts") || lowerBase == "gradle.lockfile" {
		return parseGradleFile(filePath, string(data))
	}

	if lowerBase == "setup.py" {
		return parseSetupPy(filePath, string(data))
	}
	if lowerBase == "conanfile.py" {
		return parseConanPy(filePath, string(data))
	}
	if lowerBase == "cmakelists.txt" {
		return parseCMakeLists(filePath, string(data))
	}

	if lowerBase == "gemfile" || ext == ".gemspec" {
		return parseGemfile(filePath, string(data))
	}

	if lowerBase == "pubspec.lock" {
		return parsePubspecLock(filePath, string(data))
	}
	if lowerBase == "mix.lock" {
		return parseMixLock(filePath, string(data))
	}
	if lowerBase == "mix.exs" {
		return parseElixirMix(filePath, string(data))
	}

	if ext == ".toml" || ext == ".cfg" || lowerBase == "pipfile" || ext == ".lock" {
		if pkgs, ok := tryParseGenericTOMLOrINI(filePath, string(data)); ok {
			return pkgs, nil
		}
	}

	if ext == ".yaml" || ext == ".yml" || lowerBase == "pubspec.lock" {
		if pkgs, ok := tryParseGenericYAML(filePath, string(data)); ok {
			return pkgs, nil
		}
	}

	if ext == ".txt" || ext == ".in" {
		if pkgs, err := parsePyPI(filePath); err == nil && len(pkgs) > 0 {
			return pkgs, nil
		}
	}

	return nil, fmt.Errorf("unsupported manifest: %s", filePath)
}

func tryParseGenericJSON(filePath string, data []byte) ([]Package, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false
	}

	if _, ok := raw["graph_lock"]; ok {
		if pkgs, err := parseConanLock(filePath); err == nil {
			return pkgs, true
		}
	}
	if _, ok := raw["default"]; ok {
		if _, ok2 := raw["develop"]; ok2 {
			if pkgs, err := parsePipfileLock(filePath); err == nil {
				return pkgs, true
			}
		}
	}
	if _, ok := raw["packages-dev"]; ok {
		if pkgs, err := parseComposerLock(filePath); err == nil {
			return pkgs, true
		}
	}
	if _, ok := raw["require"]; ok {
		if pkgs, err := parseComposer(filePath); err == nil {
			return pkgs, true
		}
	}
	if _, ok := raw["lockfileVersion"]; ok {
		if pkgs, err := parseNPMLock(filePath); err == nil {
			return pkgs, true
		}
	}
	if _, ok := raw["pins"]; ok {
		if pkgs := parseSwiftPackageResolved(filePath, data); len(pkgs) > 0 {
			return pkgs, true
		}
	}
	// vcpkg.json, project.assets.json, package_config.json, installed.json, or package.json
	if _, ok := raw["libraries"]; ok {
		if pkgs, err := inspectDotNetAssets(filePath); err == nil && len(pkgs) > 0 {
			return pkgs, true
		}
	}
	if _, ok := raw["configVersion"]; ok {
		if pkgs, err := inspectDartPackageConfig(filePath); err == nil && len(pkgs) > 0 {
			return pkgs, true
		}
	}
	if depsRaw, ok := raw["dependencies"]; ok {
		trimDeps := bytes.TrimSpace(depsRaw)
		if len(trimDeps) > 0 && trimDeps[0] == '[' {
			if pkgs, err := parseVcpkg(filePath); err == nil {
				return pkgs, true
			}
		}
		if len(trimDeps) > 0 && trimDeps[0] == '{' {
			if pkgs, err := parseNuGetLock(filePath); err == nil && len(pkgs) > 0 {
				return pkgs, true
			}
			if pkgs, err := parseNPM(filePath); err == nil {
				return pkgs, true
			}
		}
	}
	if _, ok := raw["devDependencies"]; ok {
		if pkgs, err := parseNPM(filePath); err == nil {
			return pkgs, true
		}
	}

	return nil, false
}

func parseSwiftPackageResolved(filePath string, data []byte) []Package {
	var resolved struct {
		Pins []struct {
			Identity string `json:"identity"`
			Package  string `json:"package"`
			Location string `json:"location"`
			State    struct {
				Version string `json:"version"`
			} `json:"state"`
		} `json:"pins"`
	}
	if err := json.Unmarshal(data, &resolved); err != nil {
		return nil
	}
	var pkgs []Package
	for _, pin := range resolved.Pins {
		name := pin.Identity
		if name == "" {
			name = pin.Package
		}
		if name != "" && pin.State.Version != "" {
			pkgs = append(pkgs, Package{
				Name:         name,
				Version:      pin.State.Version,
				Ecosystem:    "SwiftURL",
				ManifestPath: filePath,
			})
		}
	}
	return pkgs
}
func tryParseGenericXML(filePath string, data []byte) ([]Package, bool) {
	content := string(data)
	if strings.Contains(content, "<groupId>") && strings.Contains(content, "<artifactId>") {
		pkgs, err := parseMavenWithProperties(filePath, data)
		if err == nil && len(pkgs) > 0 {
			return pkgs, true
		}
	}
	if strings.Contains(content, "PackageReference") || strings.Contains(content, "PackageVersion") || strings.Contains(content, "<packages>") {
		pkgs, err := parseDotNetXML(filePath, data)
		if err == nil && len(pkgs) > 0 {
			return pkgs, true
		}
	}
	return nil, false
}

func parseMavenWithProperties(filePath string, data []byte) ([]Package, error) {
	type rawProp struct {
		XMLName xml.Name
		Value   string `xml:",chardata"`
	}
	var pom struct {
		Version string `xml:"version"`
		Parent  struct {
			Version string `xml:"version"`
		} `xml:"parent"`
		Properties struct {
			Entries []rawProp `xml:",any"`
		} `xml:"properties"`
		Dependencies []mavenDep `xml:"dependencies>dependency"`
		DepMgmt      []mavenDep `xml:"dependencyManagement>dependencies>dependency"`
	}
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, err
	}

	props := make(map[string]string)
	if pom.Version != "" {
		props["project.version"] = strings.TrimSpace(pom.Version)
		props["pom.version"] = strings.TrimSpace(pom.Version)
	} else if pom.Parent.Version != "" {
		props["project.version"] = strings.TrimSpace(pom.Parent.Version)
		props["project.parent.version"] = strings.TrimSpace(pom.Parent.Version)
	}
	for _, entry := range pom.Properties.Entries {
		props[entry.XMLName.Local] = strings.TrimSpace(entry.Value)
	}

	// Properties may refer to other properties and be embedded in text
	// ("${major}.${minor}"). Unknown or cyclic references stay unresolved.
	resolveProp := func(val string) string {
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

	// dependencyManagement supplies versions for dependencies declared without
	// one, and pins the versions of child-module and transitive dependencies,
	// so its entries are reported. An imported BOM (scope import) is only a
	// list of versions, not a dependency.
	managed := make(map[string]string)
	var allDeps []mavenDep
	for _, dep := range pom.DepMgmt {
		managed[resolveProp(dep.GroupID)+":"+resolveProp(dep.ArtifactID)] = dep.Version
		if strings.TrimSpace(dep.Scope) != "import" {
			allDeps = append(allDeps, dep)
		}
	}
	for _, dep := range pom.Dependencies {
		if strings.TrimSpace(dep.Version) == "" {
			dep.Version = managed[resolveProp(dep.GroupID)+":"+resolveProp(dep.ArtifactID)]
		}
		allDeps = append(allDeps, dep)
	}
	var pkgs []Package
	seen := make(map[string]bool)
	for _, dep := range allDeps {
		ver := resolveProp(dep.Version)
		group := resolveProp(dep.GroupID)
		artifact := resolveProp(dep.ArtifactID)
		if group == "" || artifact == "" || ver == "" || strings.Contains(ver, "${") {
			continue
		}
		p := Package{
			Name:         group + ":" + artifact,
			Version:      ver,
			Ecosystem:    "Maven",
			ManifestPath: filePath,
		}
		if !seen[p.Key()] {
			seen[p.Key()] = true
			pkgs = append(pkgs, p)
		}
	}
	return pkgs, nil
}

func parseDotNetXML(filePath string, data []byte) ([]Package, error) {
	type rawProp struct {
		XMLName xml.Name
		Value   string `xml:",chardata"`
	}
	var proj struct {
		PropertyGroups []struct {
			Entries []rawProp `xml:",any"`
		} `xml:"PropertyGroup"`
		ItemGroups []struct {
			PackageRefs []struct {
				Include         string `xml:"Include,attr"`
				Update          string `xml:"Update,attr"`
				VersionAttr     string `xml:"Version,attr"`
				VersionElem     string `xml:"Version"`
				VersionOverride string `xml:"VersionOverride,attr"`
			} `xml:"PackageReference"`
			PackageVersions []struct {
				Include     string `xml:"Include,attr"`
				VersionAttr string `xml:"Version,attr"`
				VersionElem string `xml:"Version"`
			} `xml:"PackageVersion"`
		} `xml:"ItemGroup"`
		Packages []struct {
			ID      string `xml:"id,attr"`
			Version string `xml:"version,attr"`
		} `xml:"package"`
	}
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, err
	}

	// MSBuild properties ($(Name)) defined in the same file are substituted;
	// a version that still refers to an unknown property stays unresolved.
	props := make(map[string]string)
	for _, group := range proj.PropertyGroups {
		for _, entry := range group.Entries {
			props[strings.ToLower(entry.XMLName.Local)] = strings.TrimSpace(entry.Value)
		}
	}
	resolve := func(val string) string {
		for depth := 0; depth < 10 && strings.Contains(val, "$("); depth++ {
			start := strings.Index(val, "$(")
			end := strings.Index(val[start:], ")")
			if end == -1 {
				break
			}
			resolved, ok := props[strings.ToLower(val[start+2:start+end])]
			if !ok {
				break
			}
			val = val[:start] + resolved + val[start+end+1:]
		}
		return val
	}

	var pkgs []Package
	seen := make(map[string]bool)
	add := func(name, ver string) {
		name = strings.TrimSpace(name)
		ver = resolve(strings.TrimSpace(ver))
		if name == "" || ver == "" {
			return
		}
		p := Package{
			Name:         name,
			Version:      ver,
			Ecosystem:    "NuGet",
			ManifestPath: filePath,
		}
		if !seen[p.Key()] {
			seen[p.Key()] = true
			pkgs = append(pkgs, p)
		}
	}

	for _, ig := range proj.ItemGroups {
		for _, ref := range ig.PackageRefs {
			name := ref.Include
			if name == "" {
				name = ref.Update
			}
			ver := ref.VersionAttr
			if ver == "" {
				ver = ref.VersionElem
			}
			// Central package management: a project-level override wins over
			// the version in Directory.Packages.props.
			if ref.VersionOverride != "" {
				ver = ref.VersionOverride
			}
			add(name, ver)
		}
		for _, pv := range ig.PackageVersions {
			ver := pv.VersionAttr
			if ver == "" {
				ver = pv.VersionElem
			}
			add(pv.Include, ver)
		}
	}
	for _, p := range proj.Packages {
		add(p.ID, p.Version)
	}
	return pkgs, nil
}

var gradleCoordRe = regexp.MustCompile(`['"]([a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+:[0-9a-zA-Z._+-]+)['"]`)

func parseGradleFile(filePath, content string) ([]Package, error) {
	var pkgs []Package
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasSuffix(filepath.Base(filePath), "gradle.lockfile") {
			if idx := strings.Index(line, "="); idx != -1 {
				coord := line[:idx]
				parts := strings.Split(coord, ":")
				if len(parts) == 3 {
					p := Package{
						Name:         parts[0] + ":" + parts[1],
						Version:      parts[2],
						Ecosystem:    "Maven",
						ManifestPath: filePath,
					}
					if !seen[p.Key()] {
						seen[p.Key()] = true
						pkgs = append(pkgs, p)
					}
				}
			}
			continue
		}

		matches := gradleCoordRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			parts := strings.Split(m[1], ":")
			if len(parts) == 3 && !strings.HasPrefix(parts[2], "$") {
				p := Package{
					Name:         parts[0] + ":" + parts[1],
					Version:      parts[2],
					Ecosystem:    "Maven",
					ManifestPath: filePath,
				}
				if !seen[p.Key()] {
					seen[p.Key()] = true
					pkgs = append(pkgs, p)
				}
			}
		}
	}
	return pkgs, nil
}

var quotedStrRe = regexp.MustCompile(`['"]([^'"]+)['"]`)

func parseSetupPy(filePath, content string) ([]Package, error) {
	var pkgs []Package
	seen := make(map[string]bool)

	inRequires := false
	depth := 0
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if at := strings.Index(line, "install_requires"); at >= 0 {
			line = line[at+len("install_requires"):]
			inRequires = strings.Contains(line, "[")
			depth = 0
		}
		if inRequires {
			for _, m := range quotedStrRe.FindAllStringSubmatch(line, -1) {
				spec := m[1]
				name, ver := parsePEP508Spec(spec)
				if name != "" && ver != "" && !strings.ContainsAny(name, " /\\:") {
					p := Package{
						Name:         name,
						Version:      ver,
						Ecosystem:    "PyPI",
						ManifestPath: filePath,
					}
					if !seen[p.Key()] {
						seen[p.Key()] = true
						pkgs = append(pkgs, p)
					}
				}
			}
			depth += unquotedBracketDelta(line)
			if depth <= 0 {
				inRequires = false
			}
		}
	}
	return pkgs, nil
}

func parseConanPy(filePath, content string) ([]Package, error) {
	var pkgs []Package
	seen := make(map[string]bool)
	for _, m := range quotedStrRe.FindAllStringSubmatch(content, -1) {
		val := strings.Split(strings.Split(m[1], "#")[0], "@")[0]
		parts := strings.Split(val, "/")
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" && !strings.ContainsAny(parts[0], " \t") {
			if parts[1][0] >= '0' && parts[1][0] <= '9' {
				p := Package{
					Name:         parts[0],
					Version:      parts[1],
					Ecosystem:    "ConanCenter",
					ManifestPath: filePath,
				}
				if !seen[p.Key()] {
					seen[p.Key()] = true
					pkgs = append(pkgs, p)
				}
			}
		}
	}
	return pkgs, nil
}

var (
	cmakeFindPkgRe      = regexp.MustCompile(`(?i)find_package\s*\(\s*([a-zA-Z0-9_+-]+)(?:\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?))?`)
	cmakeFetchContentRe = regexp.MustCompile(`(?is)FetchContent_Declare\s*\(\s*([a-zA-Z0-9_+-]+).*?GIT_TAG\s+([^\s\)]+)`)
)

var cmakeBuiltinModules = map[string]bool{
	"threads": true, "pkgconfig": true, "python": true, "python3": true, "pythoninterp": true,
	"pythonlibs": true, "openmp": true, "mpi": true, "git": true, "doxygen": true,
	"latx": true, "perl": true, "java": true, "jni": true, "cudatoolkit": true,
	"opengl": true, "x11": true, "curses": true, "backtrace": true, "iconv": true,
	"intl": true,
}

func parseCMakeLists(filePath, content string) ([]Package, error) {
	var pkgs []Package
	seen := make(map[string]bool)

	add := func(rawName, rawVer string) {
		name := strings.ToLower(strings.TrimSpace(rawName))
		if name == "" || cmakeBuiltinModules[name] {
			return
		}
		ver := strings.TrimPrefix(strings.Trim(strings.TrimSpace(rawVer), `"'`), "v")
		if ver == "" {
			ver = "latest"
		}
		p := Package{
			Name:         name,
			Version:      ver,
			Ecosystem:    "ConanCenter",
			ManifestPath: filePath,
		}
		if !seen[p.Key()] {
			seen[p.Key()] = true
			pkgs = append(pkgs, p)
		}
	}

	for _, m := range cmakeFetchContentRe.FindAllStringSubmatch(content, -1) {
		add(m[1], m[2])
	}
	for _, m := range cmakeFindPkgRe.FindAllStringSubmatch(content, -1) {
		add(m[1], m[2])
	}
	return pkgs, nil
}

func parseGemfile(filePath, content string) ([]Package, error) {
	var pkgs []Package
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "gem ") && !strings.Contains(line, ".add_dependency") && !strings.Contains(line, ".add_runtime_dependency") {
			continue
		}
		matches := quotedStrRe.FindAllStringSubmatch(line, -1)
		if len(matches) >= 1 {
			name := matches[0][1]
			ver := "latest"
			if len(matches) >= 2 {
				ver = strings.TrimSpace(matches[1][1])
			}
			if name != "" && ver != "" {
				p := Package{
					Name:         name,
					Version:      ver,
					Ecosystem:    "RubyGems",
					ManifestPath: filePath,
				}
				if !seen[p.Key()] {
					seen[p.Key()] = true
					pkgs = append(pkgs, p)
				}
			}
		}
	}
	return pkgs, nil
}

var elixirDepRe = regexp.MustCompile(`\{\s*:([a-zA-Z0-9_]+)\s*,\s*"([^"]+)"`)

func parseElixirMix(filePath, content string) ([]Package, error) {
	var pkgs []Package
	seen := make(map[string]bool)
	for _, m := range elixirDepRe.FindAllStringSubmatch(content, -1) {
		name := m[1]
		ver := strings.TrimSpace(m[2])
		if name != "" && ver != "" {
			p := Package{
				Name:         name,
				Version:      ver,
				Ecosystem:    "Hex",
				ManifestPath: filePath,
			}
			if !seen[p.Key()] {
				seen[p.Key()] = true
				pkgs = append(pkgs, p)
			}
		}
	}
	return pkgs, nil
}

func tryParseGenericTOMLOrINI(filePath, content string) ([]Package, bool) {
	if strings.Contains(content, "[project]") || strings.Contains(content, "[tool.poetry") || strings.Contains(content, "[dependency-groups]") {
		if pkgs, err := parsePyProjectToml(filePath); err == nil && len(pkgs) > 0 {
			return pkgs, true
		}
	}
	if strings.Contains(content, "[dependencies]") || strings.Contains(content, "[dev-dependencies]") {
		if pkgs, err := parseCargoToml(filePath); err == nil && len(pkgs) > 0 {
			return pkgs, true
		}
	}
	if strings.Contains(content, "[packages]") || strings.Contains(content, "[dev-packages]") {
		if pkgs := parsePipfileToml(filePath, content); len(pkgs) > 0 {
			return pkgs, true
		}
	}
	if strings.Contains(content, "install_requires") {
		if pkgs := parseSetupCfg(filePath, content); len(pkgs) > 0 {
			return pkgs, true
		}
	}
	if strings.Contains(content, "[libraries]") {
		if pkgs := parseGradleVersionCatalog(filePath, content); len(pkgs) > 0 {
			return pkgs, true
		}
	}
	return nil, false
}

func parsePipfileToml(filePath, content string) []Package {
	var pkgs []Package
	seen := make(map[string]bool)
	inPkgSec := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := strings.Trim(line, "[] ")
			inPkgSec = (sec == "packages" || sec == "dev-packages")
			continue
		}
		if !inPkgSec {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"' `)
		ver := strings.TrimSpace(val)
		if ver == "" {
			ver = "latest"
		}
		p := Package{Name: name, Version: ver, Ecosystem: "PyPI", ManifestPath: filePath}
		if !seen[p.Key()] {
			seen[p.Key()] = true
			pkgs = append(pkgs, p)
		}
	}
	return pkgs
}
func parseSetupCfg(filePath, content string) []Package {
	var pkgs []Package
	seen := make(map[string]bool)
	inInstallReq := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "install_requires") {
			inInstallReq = true
			continue
		}
		if inInstallReq {
			if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") {
				inInstallReq = false
				continue
			}
			name, ver := parsePEP508Spec(line)
			if name != "" && ver != "" {
				p := Package{Name: name, Version: ver, Ecosystem: "PyPI", ManifestPath: filePath}
				if !seen[p.Key()] {
					seen[p.Key()] = true
					pkgs = append(pkgs, p)
				}
			}
		}
	}
	return pkgs
}
func parseGradleVersionCatalog(filePath, content string) []Package {
	versions := make(map[string]string)
	var pkgs []Package
	seen := make(map[string]bool)

	section := ""
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[] ")
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if section == "versions" {
			versions[key] = strings.Trim(val, `"' `)
		} else if section == "libraries" {
			if !strings.HasPrefix(val, "{") {
				coord := strings.Trim(val, `"' `)
				cParts := strings.Split(coord, ":")
				if len(cParts) == 3 {
					p := Package{Name: cParts[0] + ":" + cParts[1], Version: cParts[2], Ecosystem: "Maven", ManifestPath: filePath}
					if !seen[p.Key()] {
						seen[p.Key()] = true
						pkgs = append(pkgs, p)
					}
				}
			} else {
				var mod, group, name, ver, verRef string
				for _, field := range strings.Split(strings.Trim(val, "{}"), ",") {
					kv := strings.SplitN(strings.TrimSpace(field), "=", 2)
					if len(kv) != 2 {
						continue
					}
					fk := strings.TrimSpace(kv[0])
					fv := strings.Trim(strings.TrimSpace(kv[1]), `"' `)
					switch fk {
					case "module":
						mod = fv
					case "group":
						group = fv
					case "name":
						name = fv
					case "version":
						ver = fv
					case "version.ref":
						verRef = fv
					}
				}
				if mod == "" && group != "" && name != "" {
					mod = group + ":" + name
				}
				if ver == "" && verRef != "" {
					ver = versions[verRef]
				}
				if mod != "" && ver != "" {
					p := Package{Name: mod, Version: ver, Ecosystem: "Maven", ManifestPath: filePath}
					if !seen[p.Key()] {
						seen[p.Key()] = true
						pkgs = append(pkgs, p)
					}
				}
			}
		}
	}
	return pkgs
}
func tryParseGenericYAML(filePath, content string) ([]Package, bool) {
	base := strings.ToLower(filepath.Base(filePath))
	if base == "pnpm-lock.yaml" {
		if pkgs, err := parsePnpmLock(filePath); err == nil && len(pkgs) > 0 {
			return pkgs, true
		}
	}
	if strings.HasPrefix(base, "pubspec.") {
		if pkgs := parsePubspecYAML(filePath, content); len(pkgs) > 0 {
			return pkgs, true
		}
	}
	if strings.Contains(content, "channels:") && strings.Contains(content, "dependencies:") {
		if pkgs := parseCondaEnvironmentYAML(filePath, content); len(pkgs) > 0 {
			return pkgs, true
		}
	}
	return nil, false
}

func parsePubspecYAML(filePath, content string) []Package {
	var pkgs []Package
	seen := make(map[string]bool)
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") && strings.HasSuffix(trimmed, ":") {
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if section == "dependencies" || section == "dev_dependencies" {
			if strings.HasPrefix(raw, "  ") && !strings.HasPrefix(raw, "    ") && strings.Contains(trimmed, ":") {
				parts := strings.SplitN(trimmed, ":", 2)
				name := strings.TrimSpace(parts[0])
				ver := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				if name != "flutter" && name != "flutter_test" && name != "" && ver != "" {
					p := Package{Name: name, Version: ver, Ecosystem: "Pub", ManifestPath: filePath}
					if !seen[p.Key()] {
						seen[p.Key()] = true
						pkgs = append(pkgs, p)
					}
				}
			}
		}
	}
	return pkgs
}
func parseCondaEnvironmentYAML(filePath, content string) []Package {
	var pkgs []Package
	seen := make(map[string]bool)
	inDeps := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "dependencies:" {
			inDeps = true
			continue
		}
		if inDeps && !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") && strings.HasSuffix(trimmed, ":") {
			inDeps = false
			continue
		}
		if inDeps && strings.HasPrefix(trimmed, "- ") {
			spec := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if spec == "pip:" || strings.HasPrefix(spec, "python=") || strings.HasPrefix(spec, "python>") {
				continue
			}
			if at := strings.IndexByte(spec, '='); at > 0 && !strings.ContainsAny(spec[at-1:at], ">!<~=") && (at+1 == len(spec) || spec[at+1] != '=') {
				spec = spec[:at] + "==" + spec[at+1:]
			}
			name, ver := parsePEP508Spec(spec)
			if name != "" && ver != "" {
				p := Package{Name: name, Version: ver, Ecosystem: "PyPI", ManifestPath: filePath}
				if !seen[p.Key()] {
					seen[p.Key()] = true
					pkgs = append(pkgs, p)
				}
			}
		}
	}
	return pkgs
}

// pythonStdlib lists the standard library (sys.stdlib_module_names of CPython
// 3.12, plus modules removed in 3.12). typing_extensions is a PyPI package.
var pythonStdlib = map[string]bool{
	"ConfigParser": true, "__future__": true, "abc": true, "aifc": true, "antigravity": true,
	"argparse": true, "array": true, "ast": true, "asynchat": true, "asyncio": true,
	"asyncore": true, "atexit": true, "audioop": true, "base64": true, "bdb": true,
	"binascii": true, "bisect": true, "builtins": true, "bz2": true, "cProfile": true,
	"calendar": true, "cgi": true, "cgitb": true, "chunk": true, "cmath": true, "cmd": true,
	"code": true, "codecs": true, "codeop": true, "collections": true, "colorsys": true,
	"compileall": true, "concurrent": true, "configparser": true, "contextlib": true,
	"contextvars": true, "copy": true, "copyreg": true, "crypt": true, "csv": true,
	"ctypes": true, "curses": true, "dataclasses": true, "datetime": true, "dbm": true,
	"decimal": true, "difflib": true, "dis": true, "distutils": true, "doctest": true,
	"email": true, "encodings": true, "ensurepip": true, "enum": true, "errno": true,
	"faulthandler": true, "fcntl": true, "filecmp": true, "fileinput": true, "fnmatch": true,
	"fractions": true, "ftplib": true, "functools": true, "gc": true, "genericpath": true,
	"getopt": true, "getpass": true, "gettext": true, "glob": true, "graphlib": true, "grp": true,
	"gzip": true, "hashlib": true, "heapq": true, "hmac": true, "html": true, "http": true,
	"idlelib": true, "imaplib": true, "imghdr": true, "imp": true, "importlib": true,
	"inspect": true, "io": true, "ipaddress": true, "itertools": true, "json": true,
	"keyword": true, "lib2to3": true, "linecache": true, "locale": true, "logging": true,
	"lzma": true, "mailbox": true, "mailcap": true, "marshal": true, "math": true,
	"mimetypes": true, "mmap": true, "modulefinder": true, "msilib": true, "msvcrt": true,
	"multiprocessing": true, "netrc": true, "nis": true, "nntplib": true, "nt": true,
	"ntpath": true, "nturl2path": true, "numbers": true, "opcode": true, "operator": true,
	"optparse": true, "os": true, "ossaudiodev": true, "pathlib": true, "pdb": true,
	"pickle": true, "pickletools": true, "pipes": true, "pkgutil": true, "platform": true,
	"plistlib": true, "poplib": true, "posix": true, "posixpath": true, "pprint": true,
	"profile": true, "pstats": true, "pty": true, "pwd": true, "py_compile": true, "pyclbr": true,
	"pydoc": true, "pydoc_data": true, "pyexpat": true, "queue": true, "quopri": true,
	"random": true, "re": true, "readline": true, "reprlib": true, "resource": true,
	"rlcompleter": true, "runpy": true, "sched": true, "secrets": true, "select": true,
	"selectors": true, "shelve": true, "shlex": true, "shutil": true, "signal": true,
	"site": true, "smtpd": true, "smtplib": true, "sndhdr": true, "socket": true,
	"socketserver": true, "spwd": true, "sqlite3": true, "sre_compile": true,
	"sre_constants": true, "sre_parse": true, "ssl": true, "stat": true, "statistics": true,
	"string": true, "stringprep": true, "struct": true, "subprocess": true, "sunau": true,
	"symtable": true, "sys": true, "sysconfig": true, "syslog": true, "tabnanny": true,
	"tarfile": true, "telnetlib": true, "tempfile": true, "termios": true, "textwrap": true,
	"this": true, "threading": true, "time": true, "timeit": true, "tkinter": true, "token": true,
	"tokenize": true, "tomllib": true, "trace": true, "traceback": true, "tracemalloc": true,
	"tty": true, "turtle": true, "turtledemo": true, "types": true, "typing": true,
	"unicodedata": true, "unittest": true, "urllib": true, "uu": true, "uuid": true, "venv": true,
	"warnings": true, "wave": true, "weakref": true, "webbrowser": true, "winreg": true,
	"winsound": true, "wsgiref": true, "xdrlib": true, "xml": true, "xmlrpc": true,
	"zipapp": true, "zipfile": true, "zipimport": true, "zlib": true, "zoneinfo": true,
}

var pythonImportAliases = map[string]string{
	"cv2":           "opencv-python",
	"bs4":           "beautifulsoup4",
	"sklearn":       "scikit-learn",
	"yaml":          "PyYAML",
	"pil":           "Pillow",
	"dotenv":        "python-dotenv",
	"jwt":           "PyJWT",
	"serial":        "pyserial",
	"usb":           "pyusb",
	"crypto":        "pycryptodome",
	"cryptodome":    "pycryptodomex",
	"dateutil":      "python-dateutil",
	"attr":          "attrs",
	"jose":          "python-jose",
	"openssl":       "pyOpenSSL",
	"nacl":          "PyNaCl",
	"magic":         "python-magic",
	"docx":          "python-docx",
	"pptx":          "python-pptx",
	"git":           "GitPython",
	"zmq":           "pyzmq",
	"mysqldb":       "mysqlclient",
	"skimage":       "scikit-image",
	"fitz":          "PyMuPDF",
	"slugify":       "python-slugify",
	"multipart":     "python-multipart",
	"socketio":      "python-socketio",
	"engineio":      "python-engineio",
	"ldap":          "python-ldap",
	"kafka":         "kafka-python",
	"telegram":      "python-telegram-bot",
	"jinja2":        "Jinja2",
	"markupsafe":    "MarkupSafe",
	"pkg_resources": "setuptools",
}

var nodeBuiltinModules = map[string]bool{
	"assert": true, "async_hooks": true, "buffer": true, "child_process": true,
	"cluster": true, "console": true, "constants": true, "crypto": true,
	"dgram": true, "diagnostics_channel": true, "dns": true, "domain": true,
	"events": true, "fs": true, "http": true, "http2": true, "https": true,
	"inspector": true, "module": true, "net": true, "os": true, "path": true,
	"perf_hooks": true, "process": true, "punycode": true, "querystring": true,
	"readline": true, "repl": true, "stream": true, "string_decoder": true,
	"timers": true, "tls": true, "trace_events": true, "tty": true, "url": true,
	"util": true, "v8": true, "vm": true, "wasi": true, "worker_threads": true,
	"zlib": true,
}

var (
	pyFromRe       = regexp.MustCompile(`^\s*from\s+([a-zA-Z0-9_][a-zA-Z0-9_.]*)\s+import\b`)
	pyImportListRe = regexp.MustCompile(`^\s*import\s+([a-zA-Z0-9_][a-zA-Z0-9_., \t]*?)\s*(?:#.*)?$`)
	jsImportRe     = regexp.MustCompile(`(?:from\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\))`)
	rustUseRe      = regexp.MustCompile(`^\s*(?:pub\s+)?(?:use|extern\s+crate)\s+([a-zA-Z0-9_]+)`)
	cIncludeRe     = regexp.MustCompile(`^\s*#\s*include\s*<([^>]+)>`)
	javaImportRe   = regexp.MustCompile(`^\s*import\s+(?:static\s+)?([a-zA-Z0-9_.]+)`)
	csUsingRe      = regexp.MustCompile(`^\s*using\s+(?:static\s+)?([a-zA-Z0-9_.]+)\s*;`)
	phpUseRe       = regexp.MustCompile(`^\s*use\s+([a-zA-Z0-9_]+)\\([a-zA-Z0-9_]+)(?:\\([a-zA-Z0-9_]+))?`)
	rubyReqRe      = regexp.MustCompile(`^\s*require\s+['"]([^'"]+)['"]`)
	dartImportRe   = regexp.MustCompile(`^\s*import\s+['"]package:([a-zA-Z0-9_]+)/`)
)

// localModuleIndex records the module names a project defines itself, per
// directory, so that an import of a project's own module is not reported as a
// third-party package. Names are visible from the directory that defines
// them and every directory below it, and from the lib/ and src/ source roots
// beside it. Sibling projects do not see each other's names.
type localModuleIndex struct {
	// python holds name.py modules and directories with __init__.py.
	python map[string]map[string]bool
	// other holds directories containing source files, and .rs/.rb modules.
	other map[string]map[string]bool
	cache map[string]map[string]bool
}

var sourceExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true, ".mjs": true, ".cjs": true,
	".go": true, ".rs": true, ".c": true, ".cc": true, ".cpp": true, ".cxx": true, ".h": true,
	".hpp": true, ".hxx": true, ".java": true, ".kt": true, ".scala": true, ".cs": true,
	".fs": true, ".php": true, ".rb": true, ".dart": true,
}

func buildLocalModuleIndex(rootDir string) *localModuleIndex {
	idx := &localModuleIndex{
		python: make(map[string]map[string]bool),
		other:  make(map[string]map[string]bool),
		cache:  make(map[string]map[string]bool),
	}
	add := func(set map[string]map[string]bool, dir, name string) {
		dir = filepath.Clean(dir)
		if set[dir] == nil {
			set[dir] = make(map[string]bool)
		}
		set[dir][strings.ToLower(name)] = true
	}
	hasSource := make(map[string]bool)
	// Read errors are reported by the import walk; this walk only collects names.
	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipSourceDir(path, rootDir) {
				return filepath.SkipDir
			}
			if filepath.Clean(path) != filepath.Clean(rootDir) {
				if _, statErr := os.Stat(filepath.Join(path, "__init__.py")); statErr == nil {
					add(idx.python, filepath.Dir(path), d.Name())
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !sourceExtensions[ext] {
			return nil
		}
		stem := strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
		dir := filepath.Dir(path)
		if ext == ".py" {
			add(idx.python, dir, stem)
		}
		if ext == ".rs" || ext == ".rb" {
			add(idx.other, dir, stem)
		}
		// Every directory above a source file, up to the root, holds source.
		for d := dir; !hasSource[d] && d != filepath.Clean(rootDir); d = filepath.Dir(d) {
			hasSource[d] = true
			add(idx.other, filepath.Dir(d), filepath.Base(d))
		}
		return nil
	})
	return idx
}

// namesFor returns the local module names visible to the source file at path.
// A Python module never hides the package it is named after from itself:
// celery.py may import celery.
func (idx *localModuleIndex) namesFor(path string, python bool) map[string]bool {
	dir := filepath.Clean(filepath.Dir(path))
	key := dir
	set := idx.other
	if python {
		key, set = "py:"+dir, idx.python
	}
	names, ok := idx.cache[key]
	if !ok {
		names = make(map[string]bool)
		for d := dir; ; d = filepath.Dir(d) {
			for _, root := range []string{d, filepath.Join(d, "lib"), filepath.Join(d, "src")} {
				for n := range set[root] {
					names[n] = true
				}
			}
			if filepath.Dir(d) == d {
				break
			}
		}
		idx.cache[key] = names
	}
	if python {
		stem := strings.ToLower(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
		if names[stem] {
			own := make(map[string]bool, len(names))
			for n := range names {
				own[n] = true
			}
			delete(own, stem)
			return own
		}
	}
	return names
}

// maxSourceScanBytes bounds how much of each source file is read for imports.
const maxSourceScanBytes = 256 * 1024

// scanSourceCodeImports returns third-party imports and the files they came
// from. Unreadable directories and files are returned as errors, alongside the
// imports that could be read, so that skipped sources never look clean.
func scanSourceCodeImports(rootDir string) ([]Package, []string, error) {
	var pkgs []Package
	var sourceFiles []string
	seenPkg := make(map[string]bool)
	seenFile := make(map[string]bool)
	var readErrors []error
	locals := buildLocalModuleIndex(rootDir)

	record := func(path, name, ecosystem string) {
		if name == "" {
			return
		}
		p := Package{Name: name, Version: "latest", Ecosystem: ecosystem, ManifestPath: path, ProjectPath: filepath.Dir(path), VersionSource: "import"}
		if !seenPkg[p.Key()] {
			seenPkg[p.Key()] = true
			pkgs = append(pkgs, p)
			if !seenFile[path] {
				seenFile[path] = true
				sourceFiles = append(sourceFiles, path)
			}
		}
	}

	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			readErrors = append(readErrors, fmt.Errorf("scan source imports in %s: %w", path, err))
			return continueAfterWalkError(d)
		}
		if d.IsDir() {
			if skipSourceDir(path, rootDir) {
				return filepath.SkipDir
			}
			return nil
		}

		var names []string
		var ecosystem string
		var readErr error
		ext := strings.ToLower(filepath.Ext(d.Name()))
		localModules := locals.namesFor(path, ext == ".py")
		switch ext {
		case ".py":
			names, readErr = extractPythonImports(path, localModules)
			ecosystem = "PyPI"
		case ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs":
			names, readErr = extractJSImports(path)
			ecosystem = "npm"
		case ".go":
			names, readErr = extractGoImports(path, localModules)
			ecosystem = "Go"
		case ".rs":
			names, readErr = extractRustImports(path, localModules)
			ecosystem = "crates.io"
		case ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx":
			names, readErr = extractCPPIncludes(path, localModules)
			ecosystem = "ConanCenter"
		case ".java", ".kt", ".scala":
			names, readErr = extractJVMImports(path)
			ecosystem = "Maven"
		case ".cs", ".fs":
			names, readErr = extractDotNetUsings(path, localModules)
			ecosystem = "NuGet"
		case ".php":
			names, readErr = extractPHPUses(path, localModules)
			ecosystem = "Packagist"
		case ".rb":
			names, readErr = extractRubyRequires(path, localModules)
			ecosystem = "RubyGems"
		case ".dart":
			names, readErr = extractDartImports(path, localModules)
			ecosystem = "Pub"
		}
		if readErr != nil {
			readErrors = append(readErrors, fmt.Errorf("scan source imports in %s: %w", path, readErr))
		}
		for _, name := range names {
			record(path, name, ecosystem)
		}
		return nil
	})

	return pkgs, sourceFiles, errors.Join(readErrors...)
}

func extractPythonImports(filePath string, localModules map[string]bool) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var imports []string
	scanner := bufio.NewScanner(io.LimitReader(f, maxSourceScanBytes))
	// A line may fill the whole read window, so it can never exceed the token limit.
	scanner.Buffer(make([]byte, 0, 64*1024), maxSourceScanBytes+1)
	var docQuote string // inside a triple-quoted string
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if docQuote != "" {
			if strings.Contains(trimmed, docQuote) {
				docQuote = ""
			}
			continue
		}
		for _, q := range []string{`"""`, "'''"} {
			if strings.HasPrefix(trimmed, q) && strings.Count(trimmed, q)%2 == 1 {
				docQuote = q
			}
		}
		if docQuote != "" {
			continue
		}
		var modules []string
		if m := pyFromRe.FindStringSubmatch(line); m != nil {
			modules = []string{m[1]}
		} else if m := pyImportListRe.FindStringSubmatch(line); m != nil {
			// import a, b.c as d
			for _, part := range strings.Split(m[1], ",") {
				if fields := strings.Fields(part); len(fields) > 0 {
					modules = append(modules, fields[0])
				}
			}
		}
		for _, module := range modules {
			if name := pythonDistributionName(module, localModules); name != "" {
				imports = append(imports, name)
			}
		}
	}
	return imports, scanner.Err()
}

// pythonDistributionName maps an imported module path to the PyPI project
// that provides it, or "" for the standard library and local modules.
func pythonDistributionName(module string, localModules map[string]bool) string {
	parts := strings.Split(module, ".")
	top := parts[0]
	if top == "" || pythonStdlib[top] || localModules[strings.ToLower(top)] || (strings.HasPrefix(top, "_") && top != "__future__") || top == "__future__" {
		return ""
	}
	if top == "google" && len(parts) > 1 {
		switch parts[1] {
		case "protobuf":
			return "protobuf"
		case "cloud":
			if len(parts) > 2 {
				return "google-cloud-" + strings.ReplaceAll(parts[2], "_", "-")
			}
			return ""
		}
		return "google-" + strings.ReplaceAll(parts[1], "_", "-")
	}
	if mapped, ok := pythonImportAliases[strings.ToLower(top)]; ok {
		return mapped
	}
	return top
}

func extractJSImports(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var imports []string
	for _, m := range jsImportRe.FindAllStringSubmatch(string(data), -1) {
		spec := m[1]
		if spec == "" {
			spec = m[2]
		}
		if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "node:") || strings.HasPrefix(spec, "http:") || strings.HasPrefix(spec, "https:") {
			continue
		}
		var pkgName string
		if strings.HasPrefix(spec, "@") {
			parts := strings.SplitN(spec, "/", 3)
			if len(parts) >= 2 {
				pkgName = parts[0] + "/" + parts[1]
			}
		} else {
			pkgName = strings.SplitN(spec, "/", 2)[0]
		}
		if pkgName != "" && !nodeBuiltinModules[pkgName] {
			imports = append(imports, pkgName)
		}
	}
	return imports, nil
}

func extractGoImports(filePath string, localModules map[string]bool) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var imports []string
	inBlock := false
	scanner := bufio.NewScanner(io.LimitReader(f, maxSourceScanBytes))
	// A line may fill the whole read window, so it can never exceed the token limit.
	scanner.Buffer(make([]byte, 0, 64*1024), maxSourceScanBytes+1)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "import (") || line == "import(" {
			inBlock = true
			continue
		}
		if inBlock {
			if strings.HasPrefix(line, ")") {
				inBlock = false
				continue
			}
			if m := quotedStrRe.FindStringSubmatch(line); len(m) == 2 {
				if mod := normalizeGoModuleRoot(m[1], localModules); mod != "" {
					imports = append(imports, mod)
				}
			}
			continue
		}
		if strings.HasPrefix(line, "import ") {
			if m := quotedStrRe.FindStringSubmatch(line); len(m) == 2 {
				if mod := normalizeGoModuleRoot(m[1], localModules); mod != "" {
					imports = append(imports, mod)
				}
			}
		}
	}
	return imports, scanner.Err()
}

func normalizeGoModuleRoot(importPath string, localModules map[string]bool) string {
	parts := strings.Split(importPath, "/")
	if len(parts) < 2 || !strings.Contains(parts[0], ".") || localModules[strings.ToLower(parts[0])] {
		return "" // Go standard library or local package
	}
	// gopkg.in/yaml.v3 or gopkg.in/user/pkg.v2
	if parts[0] == "gopkg.in" {
		if len(parts) >= 3 && !strings.Contains(parts[1], ".") {
			return strings.Join(parts[:3], "/")
		}
		return strings.Join(parts[:2], "/")
	}
	// Code hosts and golang.org/x use host/owner/repo
	// (github.com/owner/repo/subpkg -> github.com/owner/repo). Vanity hosts
	// mostly use host/name (google.golang.org/grpc, go.uber.org/zap,
	// k8s.io/client-go). Without go.mod the module boundary is a best guess.
	n := 2
	switch parts[0] {
	case "github.com", "gitlab.com", "bitbucket.org", "golang.org", "cloud.google.com":
		n = 3
	}
	if len(parts) < n {
		return importPath
	}
	// A major version suffix is part of the module path: github.com/go-chi/chi/v5.
	if len(parts) > n && goMajorVersionRe.MatchString(parts[n]) {
		n++
	}
	return strings.Join(parts[:n], "/")
}

var goMajorVersionRe = regexp.MustCompile(`^v[2-9][0-9]*$`)

var rustBuiltinCrates = map[string]bool{
	"std": true, "core": true, "alloc": true, "proc_macro": true,
	"test": true, "crate": true, "self": true, "super": true,
}

func extractRustImports(filePath string, localModules map[string]bool) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var imports []string
	scanner := bufio.NewScanner(io.LimitReader(f, maxSourceScanBytes))
	// A line may fill the whole read window, so it can never exceed the token limit.
	scanner.Buffer(make([]byte, 0, 64*1024), maxSourceScanBytes+1)
	for scanner.Scan() {
		line := scanner.Text()
		m := rustUseRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		crateName := m[1]
		if rustBuiltinCrates[crateName] || localModules[strings.ToLower(crateName)] {
			continue
		}
		imports = append(imports, crateName)
	}
	return imports, scanner.Err()
}

var cppStdHeaders = map[string]bool{
	"algorithm": true, "any": true, "array": true, "atomic": true, "barrier": true,
	"bit": true, "bitset": true, "cassert": true, "cctype": true, "cerrno": true,
	"cfenv": true, "cfloat": true, "charconv": true, "chrono": true, "cinttypes": true,
	"climits": true, "clocale": true, "cmath": true, "codecvt": true, "compare": true,
	"complex": true, "concepts": true, "condition_variable": true, "coroutine": true,
	"csetjmp": true, "csignal": true, "cstdarg": true, "cstddef": true, "cstdint": true,
	"cstdio": true, "cstdlib": true, "cstring": true, "ctime": true, "cuchar": true,
	"cwchar": true, "cwctype": true, "deque": true, "exception": true, "execution": true,
	"expected": true, "filesystem": true, "format": true, "forward_list": true,
	"fstream": true, "functional": true, "future": true, "initializer_list": true,
	"iomanip": true, "ios": true, "iosfwd": true, "iostream": true, "istream": true,
	"iterator": true, "latch": true, "limits": true, "list": true, "locale": true,
	"map": true, "memory": true, "memory_resource": true, "mutex": true, "new": true,
	"numbers": true, "numeric": true, "optional": true, "ostream": true, "print": true,
	"queue": true, "random": true, "ranges": true, "ratio": true, "regex": true,
	"scoped_allocator": true, "semaphore": true, "set": true, "shared_mutex": true,
	"source_location": true, "span": true, "spanstream": true, "sstream": true,
	"stack": true, "stacktrace": true, "stdexcept": true, "stdfloat": true,
	"stop_token": true, "streambuf": true, "string": true, "string_view": true,
	"strstream": true, "syncstream": true, "system_error": true, "thread": true,
	"tuple": true, "type_traits": true, "typeindex": true, "typeinfo": true,
	"unordered_map": true, "unordered_set": true, "utility": true, "valarray": true,
	"variant": true, "vector": true, "version": true,
	// C & POSIX standard headers
	"assert.h": true, "ctype.h": true, "errno.h": true, "fenv.h": true, "float.h": true,
	"inttypes.h": true, "limits.h": true, "locale.h": true, "math.h": true, "setjmp.h": true,
	"signal.h": true, "stdarg.h": true, "stdbool.h": true, "stddef.h": true, "stdint.h": true,
	"stdio.h": true, "stdlib.h": true, "string.h": true, "time.h": true, "uchar.h": true,
	"wchar.h": true, "wctype.h": true, "unistd.h": true, "fcntl.h": true, "pthread.h": true,
	"dlfcn.h": true, "dirent.h": true, "netdb.h": true, "poll.h": true, "syslog.h": true,
	"termios.h": true, "Windows.h": true, "windows.h": true, "winsock2.h": true,
	"sys": true, "arpa": true, "netinet": true, "linux": true, "asm": true,
}

var cppHeaderToConan = map[string]string{
	"openssl":    "openssl",
	"zlib.h":     "zlib",
	"fmt":        "fmt",
	"boost":      "boost",
	"curl":       "libcurl",
	"nlohmann":   "nlohmann_json",
	"spdlog":     "spdlog",
	"sqlite3.h":  "sqlite3",
	"gtest":      "gtest",
	"yaml-cpp":   "yaml-cpp",
	"google":     "protobuf",
	"eigen3":     "eigen",
	"eigen":      "eigen",
	"opencv2":    "opencv",
	"uv.h":       "libuv",
	"zstd.h":     "zstd",
	"lz4.h":      "lz4",
	"expat.h":    "expat",
	"libxml":     "libxml2",
	"png.h":      "libpng",
	"jpeglib.h":  "libjpeg",
	"glfw":       "glfw",
	"sdl2":       "sdl",
	"catch2":     "catch2",
	"absl":       "abseil",
	"grpc":       "grpc",
	"grpcpp":     "grpc",
	"rocksdb":    "rocksdb",
	"rapidjson":  "rapidjson",
	"simdjson":   "simdjson",
	"pugixml":    "pugixml",
	"tinyxml2":   "tinyxml2",
	"zmq.h":      "zeromq",
	"sodium.h":   "libsodium",
	"mbedtls":    "mbedtls",
	"libavcodec": "ffmpeg",
	"pybind11":   "pybind11",
}

func extractCPPIncludes(filePath string, localModules map[string]bool) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var includes []string
	scanner := bufio.NewScanner(io.LimitReader(f, maxSourceScanBytes))
	// A line may fill the whole read window, so it can never exceed the token limit.
	scanner.Buffer(make([]byte, 0, 64*1024), maxSourceScanBytes+1)
	for scanner.Scan() {
		line := scanner.Text()
		m := cIncludeRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		hdr := strings.TrimSpace(m[1])
		if cppStdHeaders[hdr] {
			continue
		}
		top := strings.SplitN(hdr, "/", 2)[0]
		if cppStdHeaders[top] || localModules[strings.ToLower(top)] {
			continue
		}
		if mapped, ok := cppHeaderToConan[strings.ToLower(hdr)]; ok {
			includes = append(includes, mapped)
		} else if mapped, ok := cppHeaderToConan[strings.ToLower(top)]; ok {
			includes = append(includes, mapped)
		} else if strings.Contains(hdr, "/") {
			includes = append(includes, strings.ToLower(top))
		}
	}
	return includes, scanner.Err()
}

var jvmPackageToMaven = map[string]string{
	"org.apache.logging.log4j":       "org.apache.logging.log4j:log4j-core",
	"com.fasterxml.jackson.databind": "com.fasterxml.jackson.core:jackson-databind",
	"com.fasterxml.jackson.core":     "com.fasterxml.jackson.core:jackson-core",
	"com.google.common":              "com.google.guava:guava",
	"com.google.gson":                "com.google.code.gson:gson",
	"org.slf4j":                      "org.slf4j:slf4j-api",
	"org.springframework.boot":       "org.springframework.boot:spring-boot",
	"org.springframework.web":        "org.springframework:spring-web",
	"org.springframework.security":   "org.springframework.security:spring-security-core",
	"io.netty":                       "io.netty:netty-all",
	"org.apache.commons.lang3":       "org.apache.commons:commons-lang3",
	"org.apache.commons.io":          "commons-io:commons-io",
	"okhttp3":                        "com.squareup.okhttp3:okhttp",
	"retrofit2":                      "com.squareup.retrofit2:retrofit",
	"org.junit.jupiter":              "org.junit.jupiter:junit-jupiter",
	"org.mockito":                    "org.mockito:mockito-core",
	"org.hibernate":                  "org.hibernate.orm:hibernate-core",
	"org.yaml.snakeyaml":             "org.yaml:snakeyaml",
	"org.jsoup":                      "org.jsoup:jsoup",
	"org.bouncycastle":               "org.bouncycastle:bcprov-jdk18on",
	"lombok":                         "org.projectlombok:lombok",
}

func extractJVMImports(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var imports []string
	scanner := bufio.NewScanner(io.LimitReader(f, maxSourceScanBytes))
	// A line may fill the whole read window, so it can never exceed the token limit.
	scanner.Buffer(make([]byte, 0, 64*1024), maxSourceScanBytes+1)
	for scanner.Scan() {
		line := scanner.Text()
		m := javaImportRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		imp := m[1]
		if strings.HasPrefix(imp, "java.") || strings.HasPrefix(imp, "javax.") ||
			strings.HasPrefix(imp, "jdk.") || strings.HasPrefix(imp, "sun.") ||
			strings.HasPrefix(imp, "kotlin.") || strings.HasPrefix(imp, "scala.") ||
			strings.HasPrefix(imp, "android.") {
			continue
		}
		matched := false
		for prefix, coord := range jvmPackageToMaven {
			if strings.HasPrefix(imp, prefix) {
				imports = append(imports, coord)
				matched = true
				break
			}
		}
		if !matched {
			parts := strings.Split(imp, ".")
			if len(parts) >= 4 {
				group := strings.Join(parts[:3], ".")
				artifact := parts[3]
				imports = append(imports, group+":"+artifact)
			}
		}
	}
	return imports, scanner.Err()
}

func extractDotNetUsings(filePath string, localModules map[string]bool) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var usings []string
	scanner := bufio.NewScanner(io.LimitReader(f, maxSourceScanBytes))
	// A line may fill the whole read window, so it can never exceed the token limit.
	scanner.Buffer(make([]byte, 0, 64*1024), maxSourceScanBytes+1)
	for scanner.Scan() {
		line := scanner.Text()
		m := csUsingRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		ns := m[1]
		if ns == "System" || strings.HasPrefix(ns, "System.") ||
			ns == "Windows" || strings.HasPrefix(ns, "Windows.") ||
			ns == "Microsoft.CSharp" || ns == "Microsoft.VisualBasic" {
			continue
		}
		parts := strings.Split(ns, ".")
		if localModules[strings.ToLower(parts[0])] {
			continue
		}
		if len(parts) >= 2 && (parts[0] == "Newtonsoft" || parts[0] == "Microsoft" || parts[0] == "StackExchange" || parts[0] == "MongoDB") {
			usings = append(usings, strings.Join(parts[:2], "."))
		} else {
			usings = append(usings, parts[0])
		}
	}
	return usings, scanner.Err()
}

func extractPHPUses(filePath string, localModules map[string]bool) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var uses []string
	scanner := bufio.NewScanner(io.LimitReader(f, maxSourceScanBytes))
	// A line may fill the whole read window, so it can never exceed the token limit.
	scanner.Buffer(make([]byte, 0, 64*1024), maxSourceScanBytes+1)
	for scanner.Scan() {
		line := scanner.Text()
		m := phpUseRe.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		vendor := strings.ToLower(m[1])
		if vendor == "app" || vendor == "tests" || localModules[vendor] {
			continue
		}
		if name := phpPackageName(m[1], m[2], m[3]); name != "" {
			uses = append(uses, name)
		}
	}
	return uses, scanner.Err()
}

// phpVendorPackages maps root namespaces whose Composer package name does not
// follow the namespace.
var phpVendorPackages = map[string]string{
	"guzzlehttp":   "guzzlehttp/guzzle",
	"monolog":      "monolog/monolog",
	"illuminate":   "laravel/framework",
	"phpunit":      "phpunit/phpunit",
	"carbon":       "nesbot/carbon",
	"twig":         "twig/twig",
	"predis":       "predis/predis",
	"firebase":     "firebase/php-jwt",
	"phpmailer":    "phpmailer/phpmailer",
	"dompdf":       "dompdf/dompdf",
	"stripe":       "stripe/stripe-php",
	"aws":          "aws/aws-sdk-php",
	"intervention": "intervention/image",
}

// phpPackageName guesses the Composer package for "use Vendor\Second\Third".
// Symfony components are symfony/<component>; otherwise the second segment
// names the package in kebab case (Doctrine\ORM -> doctrine/orm).
func phpPackageName(vendor, second, third string) string {
	kebab := func(s string) string { return strings.ToLower(phpKebabRe.ReplaceAllString(s, "${1}-${2}")) }
	v := strings.ToLower(vendor)
	if v == "symfony" && strings.EqualFold(second, "Component") {
		if third == "" {
			return ""
		}
		return "symfony/" + kebab(third)
	}
	if mapped, ok := phpVendorPackages[v]; ok {
		return mapped
	}
	return v + "/" + kebab(second)
}

var phpKebabRe = regexp.MustCompile(`([a-z0-9])([A-Z])`)

var rubyStdlib = map[string]bool{
	"abbrev": true, "base64": true, "benchmark": true, "bigdecimal": true, "cgi": true,
	"cmath": true, "coverage": true, "csv": true, "date": true, "dbm": true,
	"debug": true, "delegate": true, "digest": true, "drb": true, "english": true,
	"erb": true, "etc": true, "expect": true, "fcntl": true, "fiddle": true,
	"fileutils": true, "find": true, "forwardable": true, "gdbm": true, "getoptlong": true,
	"io": true, "ipaddr": true, "irb": true, "json": true, "logger": true,
	"matrix": true, "monitor": true, "mutex_m": true, "net": true, "nkf": true,
	"objspace": true, "observer": true, "open-uri": true, "open3": true, "openssl": true,
	"optparse": true, "ostruct": true, "pathname": true, "pp": true, "prettyprint": true,
	"prime": true, "pstore": true, "psych": true, "pty": true, "rdoc": true,
	"readline": true, "reline": true, "resolv": true, "ripper": true, "rss": true,
	"rubygems": true, "Scanf": true, "securerandom": true, "set": true, "shellwords": true,
	"singleton": true, "socket": true, "stringio": true, "strscan": true, "syslog": true,
	"tempfile": true, "thread": true, "time": true, "timeout": true, "tmpdir": true,
	"tracer": true, "tsort": true, "un": true, "uri": true, "weakref": true,
	"webrick": true, "yaml": true, "zlib": true,
}

func extractRubyRequires(filePath string, localModules map[string]bool) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var reqs []string
	scanner := bufio.NewScanner(io.LimitReader(f, maxSourceScanBytes))
	// A line may fill the whole read window, so it can never exceed the token limit.
	scanner.Buffer(make([]byte, 0, 64*1024), maxSourceScanBytes+1)
	for scanner.Scan() {
		line := scanner.Text()
		m := rubyReqRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		spec := m[1]
		if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
			continue
		}
		gem := strings.SplitN(spec, "/", 2)[0]
		if rubyStdlib[strings.ToLower(gem)] || localModules[strings.ToLower(gem)] {
			continue
		}
		reqs = append(reqs, gem)
	}
	return reqs, scanner.Err()
}

func extractDartImports(filePath string, localModules map[string]bool) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var imports []string
	scanner := bufio.NewScanner(io.LimitReader(f, maxSourceScanBytes))
	// A line may fill the whole read window, so it can never exceed the token limit.
	scanner.Buffer(make([]byte, 0, 64*1024), maxSourceScanBytes+1)
	for scanner.Scan() {
		line := scanner.Text()
		m := dartImportRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		pkg := m[1]
		if pkg == "flutter" || pkg == "flutter_test" || localModules[strings.ToLower(pkg)] {
			continue
		}
		imports = append(imports, pkg)
	}
	return imports, scanner.Err()
}
