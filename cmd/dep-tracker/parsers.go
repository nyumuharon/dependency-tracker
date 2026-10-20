package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"venv":         true,
	"env":          true,
	"target":       true,
	"bin":          true,
	"obj":          true,
	"dist":         true,
	"build":        true,
	".idea":        true,
	".vscode":      true,
	"testdata":     true,
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

// filterDirManifests selects the best manifests in a directory (prioritizing lockfiles over loose manifests).
func filterDirManifests(paths []string) []string {
	var npmLocks, npmManifests []string
	var pyLocks, pyManifests []string
	var goLocks, goManifests []string
	var rustLocks, rustManifests []string
	var phpLocks, phpManifests []string
	var conanLocks, conanManifests []string
	var vcpkgManifests []string
	var otherManifests []string

	for _, p := range paths {
		base := filepath.Base(p)
		switch {
		case strings.HasSuffix(base, "package-lock.json"),
			strings.HasSuffix(base, "yarn.lock"),
			strings.HasSuffix(base, "pnpm-lock.yaml"):
			npmLocks = append(npmLocks, p)
		case strings.HasSuffix(base, "package.json"):
			npmManifests = append(npmManifests, p)

		case strings.HasSuffix(base, "poetry.lock"),
			strings.HasSuffix(base, "Pipfile.lock"),
			strings.HasSuffix(base, "uv.lock"):
			pyLocks = append(pyLocks, p)
		case strings.HasSuffix(base, "requirements.txt"),
			strings.HasSuffix(base, "pyproject.toml"):
			pyManifests = append(pyManifests, p)

		case strings.HasSuffix(base, "go.sum"):
			goLocks = append(goLocks, p)
		case strings.HasSuffix(base, "go.mod"):
			goManifests = append(goManifests, p)

		case strings.HasSuffix(base, "Cargo.lock"):
			rustLocks = append(rustLocks, p)
		case strings.HasSuffix(base, "Cargo.toml"):
			rustManifests = append(rustManifests, p)

		case strings.HasSuffix(base, "composer.lock"):
			phpLocks = append(phpLocks, p)
		case strings.HasSuffix(base, "composer.json"):
			phpManifests = append(phpManifests, p)

		case strings.HasSuffix(base, "conan.lock"):
			conanLocks = append(conanLocks, p)
		case strings.HasSuffix(base, "conanfile.txt"):
			conanManifests = append(conanManifests, p)

		case strings.HasSuffix(base, "vcpkg.json"):
			vcpkgManifests = append(vcpkgManifests, p)

		default:
			otherManifests = append(otherManifests, p)
		}
	}

	var selected []string

	// If lockfiles exist for an ecosystem in this folder, prefer lockfiles; otherwise take manifests
	if len(npmLocks) > 0 {
		selected = append(selected, npmLocks...)
	} else {
		selected = append(selected, npmManifests...)
	}

	if len(pyLocks) > 0 {
		selected = append(selected, pyLocks...)
	} else {
		selected = append(selected, pyManifests...)
	}

	if len(goLocks) > 0 {
		selected = append(selected, goLocks...)
	} else {
		selected = append(selected, goManifests...)
	}

	if len(rustLocks) > 0 {
		selected = append(selected, rustLocks...)
	} else {
		selected = append(selected, rustManifests...)
	}

	if len(phpLocks) > 0 {
		selected = append(selected, phpLocks...)
	} else {
		selected = append(selected, phpManifests...)
	}

	if len(conanLocks) > 0 {
		selected = append(selected, conanLocks...)
	} else {
		selected = append(selected, conanManifests...)
	}

	selected = append(selected, vcpkgManifests...)
	selected = append(selected, otherManifests...)
	return selected
}

// FindManifests recursively walks rootDir and returns all discovered dependency manifests/lockfiles.
func FindManifests(rootDir string) ([]string, error) {
	dirManifests := make(map[string][]string)

	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if skipDirs[name] || (strings.HasPrefix(name, ".") && name != ".") {
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
		if err != nil {
			return nil, fmt.Errorf("project discovery failed: %w", err)
		}
		if len(sources) == 0 && len(pkgs) == 0 {
			return nil, fmt.Errorf("no dependencies, manifests, environments, or imports found in directory: %s", targetPath)
		}
		fmt.Fprintf(os.Stderr, "Discovered %d dependency source(s):\n", len(sources))
		for _, s := range sources {
			fmt.Fprintf(os.Stderr, "  • %s\n", s)
		}
		fmt.Fprintln(os.Stderr)
		return pkgs, nil
	}

	pkgs, err := ParseManifest(targetPath)
	if err != nil {
		return nil, err
	}
	var allPkgs []Package
	seen := make(map[string]bool)
	for _, p := range pkgs {
		if p.ManifestPath == "" {
			p.ManifestPath = targetPath
		}
		key := p.Key()
		if !seen[key] {
			seen[key] = true
			allPkgs = append(allPkgs, p)
		}
	}
	return allPkgs, nil
}

func ParseManifest(filePath string) ([]Package, error) {
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
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("invalid package.json: %w", err)
	}
	var pkgs []Package
	for name, version := range manifest.Dependencies {
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: "npm",
		})
	}
	for name, version := range manifest.DevDependencies {
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: "npm",
		})
	}
	return pkgs, nil
}

func cleanNPMVersion(v string) string {
	return strings.TrimLeft(v, "^~>=<")
}

// ── PyPI (requirements.txt) ───────────────────────────────────────────────────

func parsePyPI(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		name, ver := parsePEP508Spec(line)
		if name != "" && ver != "" && ver != "latest" {
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   ver,
				Ecosystem: "PyPI",
			})
		}
	}
	return pkgs, scanner.Err()
}

// ── Maven (pom.xml) ───────────────────────────────────────────────────────────

type mavenPOM struct {
	Dependencies []mavenDep `xml:"dependencies>dependency"`
}

type mavenDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
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
	var pkgs []Package

	if strings.HasSuffix(filePath, ".csproj") {
		var proj csproj
		if err := xml.Unmarshal(data, &proj); err != nil {
			return nil, fmt.Errorf("invalid .csproj: %w", err)
		}
		for _, ig := range proj.ItemGroups {
			for _, ref := range ig.PackageRefs {
				if ref.Include == "" || ref.Version == "" {
					continue
				}
				pkgs = append(pkgs, Package{
					Name:      ref.Include,
					Version:   ref.Version,
					Ecosystem: "NuGet",
				})
			}
		}
	} else {
		var cfg packagesConfig
		if err := xml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("invalid packages.config: %w", err)
		}
		for _, p := range cfg.Packages {
			pkgs = append(pkgs, Package{
				Name:      p.ID,
				Version:   p.Version,
				Ecosystem: "NuGet",
			})
		}
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

	var pkgs []Package
	scanner := bufio.NewScanner(f)
	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}

		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pkgs = append(pkgs, Package{
					Name:      parts[0],
					Version:   parts[1],
					Ecosystem: "Go",
				})
			}
			continue
		}

		if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				pkgs = append(pkgs, Package{
					Name:      parts[1],
					Version:   parts[2],
					Ecosystem: "Go",
				})
			}
		}
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
	var currentName, currentVersion string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if currentName != "" && currentVersion != "" {
				pkgs = append(pkgs, Package{
					Name:      currentName,
					Version:   currentVersion,
					Ecosystem: "crates.io",
				})
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
		pkgs = append(pkgs, Package{
			Name:      currentName,
			Version:   currentVersion,
			Ecosystem: "crates.io",
		})
	}
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

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := strings.Trim(line, "[]")
			inDepSection = (sec == "dependencies" || sec == "dev-dependencies" || sec == "build-dependencies")
			continue
		}
		if !inDepSection {
			continue
		}
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
		if name != "" && version != "" {
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   cleanNPMVersion(version),
				Ecosystem: "crates.io",
			})
		}
	}
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
			entry := strings.TrimSuffix(trimmed, ":")
			firstPart := strings.Trim(strings.Split(entry, ",")[0], `" `)
			lastAt := strings.LastIndex(firstPart, "@")
			if lastAt > 0 {
				currentPkgName = firstPart[:lastAt]
			} else {
				currentPkgName = firstPart
			}
			continue
		}

		if currentPkgName != "" && strings.HasPrefix(trimmed, "version ") {
			version := strings.Trim(strings.TrimPrefix(trimmed, "version "), `" `)
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
		if inPackages && strings.HasSuffix(trimmed, ":") {
			pkgSpec := strings.TrimSuffix(trimmed, ":")
			pkgSpec = strings.Trim(pkgSpec, `"' /`)
			lastAt := strings.LastIndex(pkgSpec, "@")
			if lastAt > 0 {
				name := pkgSpec[:lastAt]
				version := pkgSpec[lastAt+1:]
				if idx := strings.Index(version, "("); idx != -1 {
					version = version[:idx]
				}
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
		rawVer = spec[minIdx+len(matchedOp):]
		// If multiple constraints exist (e.g., ">=2.8,<3"), take the first constraint
		rawVer = strings.Split(rawVer, ",")[0]
		rawVer = strings.TrimLeft(strings.TrimSpace(rawVer), "^~>=<! ")
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

	scanner := bufio.NewScanner(f)
	section := ""
	inArray := false

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
			continue
		}

		// 1. Handle PEP 621 [project] dependencies = [ ... ] and [project.optional-dependencies] / [dependency-groups]
		if section == "project" || section == "project.optional-dependencies" || section == "dependency-groups" {
			if !inArray {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				if section == "project" && key != "dependencies" {
					continue
				}
				if strings.HasPrefix(val, "[") {
					for _, item := range extractQuotedStrings(val) {
						name, ver := parsePEP508Spec(item)
						addPkg(name, ver)
					}
					if !hasUnquotedBracket(val[1:], ']') {
						inArray = true
					}
				}
			} else {
				for _, item := range extractQuotedStrings(line) {
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
		isPoetryDepSection := section == "tool.poetry.dependencies" ||
			section == "tool.poetry.dev-dependencies" ||
			(strings.HasPrefix(section, "tool.poetry.group.") && strings.HasSuffix(section, ".dependencies"))

		if isPoetryDepSection {
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
			version = strings.Split(version, ",")[0]
			version = cleanNPMVersion(version)
			addPkg(name, version)
		}
	}

	return pkgs, scanner.Err()
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
	}

	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("invalid conan.lock: %w", err)
	}

	nodesRaw := root.GraphLock.Nodes
	if len(nodesRaw) == 0 {
		nodesRaw = root.Nodes
	}

	if len(nodesRaw) == 0 {
		return nil, nil
	}

	var nodesList []conanNode

	// Try unmarshaling as map[string]conanNode (Conan 2.0 / standard format)
	var nodesMap map[string]conanNode
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
				nodesList = slice[1:] // Skip root consumer node 0
			} else {
				nodesList = slice
			}
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
					version = depObj.VersionGE
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
	dirFiles := make(map[string][]string)
	var venvDirs []string
	var nodeModulesDirs []string
	var vendorDirs []string
	var dotNetAssetFiles []string
	var vcpkgStatusFiles []string
	var dartPackageConfigs []string
	localModuleNames := make(map[string]bool)

	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "venv" || name == ".venv" || name == "env" {
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
				}
				return filepath.SkipDir
			}
			if name == "vcpkg_installed" {
				statusFile := filepath.Join(path, "vcpkg", "status")
				if _, statErr := os.Stat(statusFile); statErr == nil {
					vcpkgStatusFiles = append(vcpkgStatusFiles, statusFile)
				}
				return filepath.SkipDir
			}
			if name == ".dart_tool" {
				pkgCfg := filepath.Join(path, "package_config.json")
				if _, statErr := os.Stat(pkgCfg); statErr == nil {
					dartPackageConfigs = append(dartPackageConfigs, pkgCfg)
				}
				return filepath.SkipDir
			}
			if skipDirs[name] || (strings.HasPrefix(name, ".") && name != ".") {
				return filepath.SkipDir
			}
			if _, statErr := os.Stat(filepath.Join(path, "__init__.py")); statErr == nil {
				localModuleNames[strings.ToLower(name)] = true
			}
			return nil
		}

		fileName := d.Name()
		if fileName == "pyvenv.cfg" {
			venvDirs = append(venvDirs, filepath.Dir(path))
			return nil
		}
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
	if err != nil {
		return nil, nil, err
	}

	var discoveredSources []string
	var manifestPkgs []Package
	hasPyLock := false
	hasNPMLock := false
	hasGoLock := false
	hasPHPLock := false
	hasRubyLock := false
	hasNuGetLock := false
	hasConanLock := false
	hasDartLock := false

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
				continue
			}
			if len(pkgs) == 0 && !IsManifestFile(file) {
				continue
			}
			discoveredSources = append(discoveredSources, file)
			base := strings.ToLower(filepath.Base(file))
			switch {
			case strings.HasSuffix(base, "poetry.lock"), strings.HasSuffix(base, "pipfile.lock"), strings.HasSuffix(base, "uv.lock"), strings.HasSuffix(base, "pdm.lock"):
				hasPyLock = true
			case strings.HasSuffix(base, "package-lock.json"), strings.HasSuffix(base, "yarn.lock"), strings.HasSuffix(base, "pnpm-lock.yaml"):
				hasNPMLock = true
			case strings.HasSuffix(base, "go.sum"):
				hasGoLock = true
			case strings.HasSuffix(base, "composer.lock"):
				hasPHPLock = true
			case strings.HasSuffix(base, "gemfile.lock"):
				hasRubyLock = true
			case strings.HasSuffix(base, "packages.lock.json"):
				hasNuGetLock = true
			case strings.HasSuffix(base, "conan.lock"):
				hasConanLock = true
			case strings.HasSuffix(base, "pubspec.lock"):
				hasDartLock = true
			}
			for i := range pkgs {
				if pkgs[i].ManifestPath == "" {
					pkgs[i].ManifestPath = file
				}
			}
			manifestPkgs = append(manifestPkgs, pkgs...)
		}
	}

	var envPkgs []Package
	if !hasPyLock && len(venvDirs) > 0 {
		for _, vDir := range venvDirs {
			vPkgs := inspectPythonVenv(vDir, localModuleNames)
			if len(vPkgs) > 0 {
				discoveredSources = append(discoveredSources, filepath.Join(vDir, "pyvenv.cfg"))
				envPkgs = append(envPkgs, vPkgs...)
			}
		}
	}

	if !hasNPMLock && len(nodeModulesDirs) > 0 {
		for _, nmDir := range nodeModulesDirs {
			nmPkgs := inspectNodeModules(nmDir)
			if len(nmPkgs) > 0 {
				discoveredSources = append(discoveredSources, nmDir)
				envPkgs = append(envPkgs, nmPkgs...)
			}
		}
	}

	for _, vDir := range vendorDirs {
		// Go vendor/modules.txt
		if !hasGoLock {
			modTxt := filepath.Join(vDir, "modules.txt")
			if gPkgs := inspectGoVendorModules(modTxt); len(gPkgs) > 0 {
				discoveredSources = append(discoveredSources, modTxt)
				envPkgs = append(envPkgs, gPkgs...)
			}
		}
		// PHP vendor/composer/installed.json
		if !hasPHPLock {
			compInst := filepath.Join(vDir, "composer", "installed.json")
			if pPkgs := inspectComposerInstalled(compInst); len(pPkgs) > 0 {
				discoveredSources = append(discoveredSources, compInst)
				envPkgs = append(envPkgs, pPkgs...)
			}
		}
		// Ruby vendor/bundle/**/specifications/*.gemspec
		if !hasRubyLock {
			if rPkgs := inspectRubyVendorBundle(vDir); len(rPkgs) > 0 {
				discoveredSources = append(discoveredSources, vDir)
				envPkgs = append(envPkgs, rPkgs...)
			}
		}
	}

	if !hasNuGetLock && len(dotNetAssetFiles) > 0 {
		for _, af := range dotNetAssetFiles {
			if nPkgs := inspectDotNetAssets(af); len(nPkgs) > 0 {
				discoveredSources = append(discoveredSources, af)
				envPkgs = append(envPkgs, nPkgs...)
			}
		}
	}

	if !hasConanLock && len(vcpkgStatusFiles) > 0 {
		for _, sf := range vcpkgStatusFiles {
			if cPkgs := inspectVcpkgStatus(sf); len(cPkgs) > 0 {
				discoveredSources = append(discoveredSources, sf)
				envPkgs = append(envPkgs, cPkgs...)
			}
		}
	}

	if !hasDartLock && len(dartPackageConfigs) > 0 {
		for _, dcf := range dartPackageConfigs {
			if dPkgs := inspectDartPackageConfig(dcf); len(dPkgs) > 0 {
				discoveredSources = append(discoveredSources, dcf)
				envPkgs = append(envPkgs, dPkgs...)
			}
		}
	}

	finalPkgs := mergeManifestAndEnvPackages(manifestPkgs, envPkgs)

	if len(finalPkgs) == 0 && len(discoveredSources) == 0 {
		srcPkgs, srcFiles := scanSourceCodeImports(rootDir, localModuleNames)
		if len(srcPkgs) > 0 {
			discoveredSources = append(discoveredSources, srcFiles...)
			finalPkgs = srcPkgs
		}
	}

	return finalPkgs, discoveredSources, nil
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
		nk := normKey(mp.Name, mp.Ecosystem)
		if manifestPathByPkg[nk] == "" {
			manifestPathByPkg[nk] = mp.ManifestPath
		}
	}

	var merged []Package
	seen := make(map[string]bool)

	for _, ep := range envPkgs {
		nk := normKey(ep.Name, ep.Ecosystem)
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

	for _, mp := range manifestPkgs {
		nk := normKey(mp.Name, mp.Ecosystem)
		if !envHasPkg[nk] {
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

func inspectPythonVenv(venvDir string, localModules map[string]bool) []Package {
	var metadataFiles []string
	_ = filepath.WalkDir(venvDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "__pycache__" || name == "include" || name == "bin" || name == "Scripts" {
				return filepath.SkipDir
			}
			return nil
		}
		if (d.Name() == "METADATA" || d.Name() == "PKG-INFO") &&
			(strings.HasSuffix(filepath.Dir(path), ".dist-info") || strings.HasSuffix(filepath.Dir(path), ".egg-info")) {
			metadataFiles = append(metadataFiles, path)
		}
		return nil
	})

	sort.Strings(metadataFiles)
	var pkgs []Package
	seen := make(map[string]bool)

	for _, metaPath := range metadataFiles {
		distDir := filepath.Dir(metaPath)
		if isEditableInstall(filepath.Join(distDir, "direct_url.json")) {
			continue
		}

		name, version := parsePythonMetadataFile(metaPath)
		if name == "" || version == "" {
			continue
		}
		norm := strings.ReplaceAll(strings.ToLower(name), "-", "_")
		if defaultVenvSkipPkgs[strings.ToLower(name)] || localModules[norm] {
			continue
		}

		p := Package{
			Name:         name,
			Version:      version,
			Ecosystem:    "PyPI",
			ManifestPath: metaPath,
		}
		if !seen[p.Key()] {
			seen[p.Key()] = true
			pkgs = append(pkgs, p)
		}
	}

	return pkgs
}

func inspectGoVendorModules(modulesTxtPath string) []Package {
	f, err := os.Open(modulesTxtPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var pkgs []Package
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Format: "# github.com/pkg/errors v0.9.1"
		if strings.HasPrefix(line, "# ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && strings.HasPrefix(fields[2], "v") {
				p := Package{
					Name:         fields[1],
					Version:      fields[2],
					Ecosystem:    "Go",
					ManifestPath: modulesTxtPath,
				}
				if !seen[p.Key()] {
					seen[p.Key()] = true
					pkgs = append(pkgs, p)
				}
			}
		}
	}
	return pkgs
}

func inspectComposerInstalled(installedPath string) []Package {
	data, err := os.ReadFile(installedPath)
	if err != nil {
		return nil
	}

	type compPkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	var list []compPkg
	var v2 struct {
		Packages []compPkg `json:"packages"`
	}
	if err := json.Unmarshal(data, &v2); err == nil && len(v2.Packages) > 0 {
		list = v2.Packages
	} else {
		_ = json.Unmarshal(data, &list)
	}

	var pkgs []Package
	seen := make(map[string]bool)
	for _, item := range list {
		name := strings.TrimSpace(item.Name)
		ver := strings.TrimPrefix(strings.TrimSpace(item.Version), "v")
		if name == "" || ver == "" || name == "php" || strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-") {
			continue
		}
		p := Package{
			Name:         name,
			Version:      ver,
			Ecosystem:    "Packagist",
			ManifestPath: installedPath,
		}
		if !seen[p.Key()] {
			seen[p.Key()] = true
			pkgs = append(pkgs, p)
		}
	}
	return pkgs
}

var gemspecFileRe = regexp.MustCompile(`^(.+)-([0-9]+\.[0-9]+(?:\.[0-9a-zA-Z._-]+)?)\.gemspec$`)

func inspectRubyVendorBundle(vendorDir string) []Package {
	var pkgs []Package
	seen := make(map[string]bool)

	_ = filepath.WalkDir(vendorDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Base(filepath.Dir(path)) == "specifications" && strings.HasSuffix(d.Name(), ".gemspec") {
			if m := gemspecFileRe.FindStringSubmatch(d.Name()); len(m) == 3 {
				p := Package{
					Name:         m[1],
					Version:      m[2],
					Ecosystem:    "RubyGems",
					ManifestPath: path,
				}
				if !seen[p.Key()] {
					seen[p.Key()] = true
					pkgs = append(pkgs, p)
				}
			}
		}
		return nil
	})

	return pkgs
}

func inspectDotNetAssets(assetsPath string) []Package {
	data, err := os.ReadFile(assetsPath)
	if err != nil {
		return nil
	}
	var assets struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
	}
	if err := json.Unmarshal(data, &assets); err != nil {
		return nil
	}

	var pkgs []Package
	seen := make(map[string]bool)
	for key, lib := range assets.Libraries {
		if !strings.EqualFold(lib.Type, "package") {
			continue
		}
		parts := strings.SplitN(key, "/", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			p := Package{
				Name:         parts[0],
				Version:      parts[1],
				Ecosystem:    "NuGet",
				ManifestPath: assetsPath,
			}
			if !seen[p.Key()] {
				seen[p.Key()] = true
				pkgs = append(pkgs, p)
			}
		}
	}
	return pkgs
}

func inspectVcpkgStatus(statusPath string) []Package {
	f, err := os.Open(statusPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var pkgs []Package
	seen := make(map[string]bool)
	var curName, curVer, curStatus string
	isFeature := false

	flush := func() {
		if curName != "" && curVer != "" && !isFeature &&
			strings.Contains(curStatus, "installed") && !strings.Contains(curStatus, "not-installed") {
			p := Package{
				Name:         curName,
				Version:      curVer,
				Ecosystem:    "ConanCenter",
				ManifestPath: statusPath,
			}
			if !seen[p.Key()] {
				seen[p.Key()] = true
				pkgs = append(pkgs, p)
			}
		}
		curName, curVer, curStatus = "", "", ""
		isFeature = false
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "Package:") {
			curName = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		} else if strings.HasPrefix(line, "Feature:") {
			isFeature = true
		} else if strings.HasPrefix(line, "Version:") {
			curVer = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		} else if strings.HasPrefix(line, "Status:") {
			curStatus = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		}
	}
	flush()

	return pkgs
}

func inspectDartPackageConfig(configPath string) []Package {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}
	var cfg struct {
		Packages []struct {
			Name    string `json:"name"`
			RootURI string `json:"rootUri"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}

	var pkgs []Package
	seen := make(map[string]bool)
	for _, entry := range cfg.Packages {
		if entry.Name == "" || entry.Name == "flutter" || entry.Name == "flutter_test" || strings.HasPrefix(entry.RootURI, "..") || strings.HasPrefix(entry.RootURI, ".") {
			continue
		}
		// Extract version from .pub-cache URI e.g. ".../http-1.2.0" or ".../http-1.2.0/"
		trimmedURI := strings.TrimRight(entry.RootURI, "/")
		base := filepath.Base(trimmedURI)
		prefix := entry.Name + "-"
		ver := "latest"
		if strings.HasPrefix(base, prefix) && len(base) > len(prefix) {
			ver = base[len(prefix):]
		}
		p := Package{
			Name:         entry.Name,
			Version:      ver,
			Ecosystem:    "Pub",
			ManifestPath: configPath,
		}
		if !seen[p.Key()] {
			seen[p.Key()] = true
			pkgs = append(pkgs, p)
		}
	}
	return pkgs
}

func isEditableInstall(directURLPath string) bool {
	data, err := os.ReadFile(directURLPath)
	if err != nil {
		return false
	}
	var info struct {
		DirInfo struct {
			Editable bool `json:"editable"`
		} `json:"dir_info"`
	}
	if err := json.Unmarshal(data, &info); err == nil {
		return info.DirInfo.Editable
	}
	return false
}

func parsePythonMetadataFile(path string) (string, string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()

	var name, version string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Name:") && name == "" {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		} else if strings.HasPrefix(line, "Version:") && version == "" {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
		if name != "" && version != "" {
			break
		}
	}
	return name, version
}

func inspectNodeModules(nmDir string) []Package {
	hiddenLock := filepath.Join(nmDir, ".package-lock.json")
	if pkgs, err := parseNPMLock(hiddenLock); err == nil && len(pkgs) > 0 {
		return pkgs
	}

	entries, err := os.ReadDir(nmDir)
	if err != nil {
		return nil
	}

	var pkgs []Package
	seen := make(map[string]bool)

	readPkgJSON := func(pkgJSONPath string) {
		data, err := os.ReadFile(pkgJSONPath)
		if err != nil {
			return
		}
		var meta struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(data, &meta); err == nil && meta.Name != "" && meta.Version != "" {
			p := Package{
				Name:         meta.Name,
				Version:      meta.Version,
				Ecosystem:    "npm",
				ManifestPath: pkgJSONPath,
			}
			if !seen[p.Key()] {
				seen[p.Key()] = true
				pkgs = append(pkgs, p)
			}
		}
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if strings.HasPrefix(entry.Name(), "@") {
			scopedDir := filepath.Join(nmDir, entry.Name())
			subEntries, err := os.ReadDir(scopedDir)
			if err != nil {
				continue
			}
			for _, sub := range subEntries {
				if sub.IsDir() {
					readPkgJSON(filepath.Join(scopedDir, sub.Name(), "package.json"))
				}
			}
		} else {
			readPkgJSON(filepath.Join(nmDir, entry.Name(), "package.json"))
		}
	}

	return pkgs
}
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

	if lowerBase == "mix.exs" || lowerBase == "mix.lock" {
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
		if pkgs := inspectDotNetAssets(filePath); len(pkgs) > 0 {
			return pkgs, true
		}
	}
	if _, ok := raw["configVersion"]; ok {
		if pkgs := inspectDartPackageConfig(filePath); len(pkgs) > 0 {
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

	resolveProp := func(val string) string {
		val = strings.TrimSpace(val)
		if strings.HasPrefix(val, "${") && strings.HasSuffix(val, "}") {
			key := val[2 : len(val)-1]
			if resolved, ok := props[key]; ok {
				return resolved
			}
		}
		return val
	}

	allDeps := append(pom.Dependencies, pom.DepMgmt...)
	var pkgs []Package
	seen := make(map[string]bool)
	for _, dep := range allDeps {
		ver := resolveProp(dep.Version)
		group := resolveProp(dep.GroupID)
		artifact := resolveProp(dep.ArtifactID)
		if group == "" || artifact == "" || ver == "" || strings.HasPrefix(ver, "${") {
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
	var proj struct {
		ItemGroups []struct {
			PackageRefs []struct {
				Include     string `xml:"Include,attr"`
				Update      string `xml:"Update,attr"`
				VersionAttr string `xml:"Version,attr"`
				VersionElem string `xml:"Version"`
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

	var pkgs []Package
	seen := make(map[string]bool)
	add := func(name, ver string) {
		name = strings.TrimSpace(name)
		ver = strings.TrimSpace(ver)
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
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "install_requires") {
			inRequires = true
		}
		if inRequires {
			for _, m := range quotedStrRe.FindAllStringSubmatch(line, -1) {
				spec := m[1]
				if spec == "install_requires" {
					continue
				}
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
			if strings.Contains(line, "]") {
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
				ver = strings.TrimLeft(matches[1][1], "~>!=<^ ")
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
		ver := strings.TrimLeft(m[2], "~>!=<^ ")
		ver = strings.Fields(ver)[0]
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
		ver := strings.TrimLeft(val, "=~<>^* ")
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
				ver := strings.TrimLeft(strings.Trim(strings.TrimSpace(parts[1]), `"'`), "^~>=< ")
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
			name, ver := parsePEP508Spec(strings.Replace(spec, "=", "==", 1))
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

var pythonStdlib = map[string]bool{
	"abc": true, "argparse": true, "ast": true, "asyncio": true, "base64": true,
	"bisect": true, "builtins": true, "calendar": true, "collections": true,
	"concurrent": true, "ConfigParser": true, "configparser": true, "contextlib": true,
	"contextvars": true, "copy": true, "csv": true, "ctypes": true, "curses": true,
	"dataclasses": true, "datetime": true, "decimal": true, "difflib": true,
	"dis": true, "doctest": true, "email": true, "enum": true, "errno": true,
	"faulthandler": true, "fcntl": true, "filecmp": true, "fileinput": true,
	"fnmatch": true, "fractions": true, "ftplib": true, "functools": true,
	"gc": true, "getopt": true, "getpass": true, "gettext": true, "glob": true,
	"graphlib": true, "grp": true, "gzip": true, "hashlib": true, "heapq": true,
	"hmac": true, "html": true, "http": true, "imaplib": true, "importlib": true,
	"inspect": true, "io": true, "ipaddress": true, "itertools": true, "json": true,
	"keyword": true, "linecache": true, "locale": true, "logging": true, "lzma": true,
	"mailbox": true, "marshal": true, "math": true, "mimetypes": true, "mmap": true,
	"modulefinder": true, "multiprocessing": true, "netrc": true, "numbers": true,
	"operator": true, "optparse": true, "os": true, "pathlib": true, "pdb": true,
	"pickle": true, "pkgutil": true, "platform": true, "plistlib": true, "poplib": true,
	"posix": true, "pprint": true, "profile": true, "pstats": true, "pty": true,
	"pwd": true, "py_compile": true, "pyclbr": true, "pydoc": true, "queue": true,
	"quopri": true, "random": true, "re": true, "readline": true, "reprlib": true,
	"resource": true, "rlcompleter": true, "runpy": true, "sched": true, "secrets": true,
	"select": true, "selectors": true, "shelve": true, "shlex": true, "shutil": true,
	"signal": true, "site": true, "smtplib": true, "socket": true, "socketserver": true,
	"sqlite3": true, "ssl": true, "stat": true, "statistics": true, "string": true,
	"stringprep": true, "struct": true, "subprocess": true, "symtable": true, "sys": true,
	"sysconfig": true, "syslog": true, "tabnanny": true, "tarfile": true, "tempfile": true,
	"termios": true, "test": true, "textwrap": true, "threading": true, "time": true,
	"timeit": true, "tkinter": true, "token": true, "tokenize": true, "tomllib": true,
	"trace": true, "traceback": true, "tracemalloc": true, "tty": true, "turtle": true,
	"types": true, "typing": true, "unicodedata": true, "unittest": true, "urllib": true,
	"uuid": true, "venv": true, "warnings": true, "wave": true, "weakref": true,
	"webbrowser": true, "winreg": true, "winsound": true, "wsgiref": true, "xml": true,
	"xmlrpc": true, "zipapp": true, "zipfile": true, "zipimport": true, "zlib": true,
	"zoneinfo": true, "__future__": true, "_thread": true, "typing_extensions": true,
}

var pythonImportAliases = map[string]string{
	"cv2":         "opencv-python",
	"bs4":         "beautifulsoup4",
	"sklearn":     "scikit-learn",
	"yaml":        "PyYAML",
	"pil":         "Pillow",
	"dotenv":      "python-dotenv",
	"jwt":         "PyJWT",
	"serial":      "pyserial",
	"usb":         "pyusb",
	"crypto":      "pycryptodome",
	" Cryptodome": "pycryptodomex",
	"dateutil":    "python-dateutil",
	"attr":        "attrs",
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
	pyImportRe   = regexp.MustCompile(`^\s*(?:import|from)\s+([a-zA-Z0-9_]+)(?:\.([a-zA-Z0-9_]+))?`)
	jsImportRe   = regexp.MustCompile(`(?:from\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\))`)
	rustUseRe    = regexp.MustCompile(`^\s*(?:pub\s+)?(?:use|extern\s+crate)\s+([a-zA-Z0-9_]+)`)
	cIncludeRe   = regexp.MustCompile(`^\s*#\s*include\s*<([^>]+)>`)
	javaImportRe = regexp.MustCompile(`^\s*import\s+(?:static\s+)?([a-zA-Z0-9_.]+)`)
	csUsingRe    = regexp.MustCompile(`^\s*using\s+(?:static\s+)?([a-zA-Z0-9_.]+)\s*;`)
	phpUseRe     = regexp.MustCompile(`^\s*use\s+([a-zA-Z0-9_]+)\\([a-zA-Z0-9_]+)`)
	rubyReqRe    = regexp.MustCompile(`^\s*require\s+['"]([^'"]+)['"]`)
	dartImportRe = regexp.MustCompile(`^\s*import\s+['"]package:([a-zA-Z0-9_]+)/`)
)

func scanSourceCodeImports(rootDir string, localModules map[string]bool) ([]Package, []string) {
	var pkgs []Package
	var sourceFiles []string
	seenPkg := make(map[string]bool)
	seenFile := make(map[string]bool)

	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if skipDirs[name] || (strings.HasPrefix(name, ".") && name != ".") {
				return filepath.SkipDir
			}
			localModules[strings.ToLower(name)] = true
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".py" || ext == ".rs" || ext == ".rb" {
			stem := strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
			localModules[strings.ToLower(stem)] = true
		}
		return nil
	})

	record := func(path, name, ecosystem string) {
		if name == "" {
			return
		}
		p := Package{Name: name, Version: "latest", Ecosystem: ecosystem, ManifestPath: path}
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
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				name := d.Name()
				if skipDirs[name] || (strings.HasPrefix(name, ".") && name != ".") {
					return filepath.SkipDir
				}
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		switch ext {
		case ".py":
			for _, pkgName := range extractPythonImports(path, localModules) {
				record(path, pkgName, "PyPI")
			}
		case ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs":
			for _, pkgName := range extractJSImports(path) {
				record(path, pkgName, "npm")
			}
		case ".go":
			for _, pkgName := range extractGoImports(path, localModules) {
				record(path, pkgName, "Go")
			}
		case ".rs":
			for _, pkgName := range extractRustImports(path, localModules) {
				record(path, pkgName, "crates.io")
			}
		case ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx":
			for _, pkgName := range extractCPPIncludes(path, localModules) {
				record(path, pkgName, "ConanCenter")
			}
		case ".java", ".kt", ".scala":
			for _, pkgName := range extractJVMImports(path) {
				record(path, pkgName, "Maven")
			}
		case ".cs", ".fs":
			for _, pkgName := range extractDotNetUsings(path, localModules) {
				record(path, pkgName, "NuGet")
			}
		case ".php":
			for _, pkgName := range extractPHPUses(path, localModules) {
				record(path, pkgName, "Packagist")
			}
		case ".rb":
			for _, pkgName := range extractRubyRequires(path, localModules) {
				record(path, pkgName, "RubyGems")
			}
		case ".dart":
			for _, pkgName := range extractDartImports(path, localModules) {
				record(path, pkgName, "Pub")
			}
		}
		return nil
	})

	return pkgs, sourceFiles
}

func extractPythonImports(filePath string, localModules map[string]bool) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var imports []string
	scanner := bufio.NewScanner(io.LimitReader(f, 256*1024))
	for scanner.Scan() {
		line := scanner.Text()
		m := pyImportRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		topMod := m[1]
		subMod := ""
		if len(m) >= 3 {
			subMod = m[2]
		}
		if pythonStdlib[topMod] || localModules[strings.ToLower(topMod)] || strings.HasPrefix(topMod, "_") {
			continue
		}
		if topMod == "google" && subMod != "" {
			imports = append(imports, "google-"+subMod)
			continue
		}
		if mapped, ok := pythonImportAliases[strings.ToLower(topMod)]; ok {
			imports = append(imports, mapped)
		} else {
			imports = append(imports, topMod)
		}
	}
	return imports
}

func extractJSImports(filePath string) []string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
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
	return imports
}

func extractGoImports(filePath string, localModules map[string]bool) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var imports []string
	inBlock := false
	scanner := bufio.NewScanner(io.LimitReader(f, 256*1024))
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
	return imports
}

func normalizeGoModuleRoot(importPath string, localModules map[string]bool) string {
	parts := strings.Split(importPath, "/")
	if len(parts) < 2 || !strings.Contains(parts[0], ".") || localModules[strings.ToLower(parts[0])] {
		return "" // Go standard library or local package
	}
	// github.com/owner/repo/subpkg -> github.com/owner/repo
	if (parts[0] == "github.com" || parts[0] == "gitlab.com" || parts[0] == "bitbucket.org") && len(parts) >= 3 {
		return strings.Join(parts[:3], "/")
	}
	// golang.org/x/crypto/ssh -> golang.org/x/crypto
	if parts[0] == "golang.org" && len(parts) >= 3 && parts[1] == "x" {
		return strings.Join(parts[:3], "/")
	}
	// gopkg.in/yaml.v3 or gopkg.in/user/pkg.v2
	if parts[0] == "gopkg.in" {
		if len(parts) >= 3 {
			return strings.Join(parts[:3], "/")
		}
		return strings.Join(parts[:2], "/")
	}
	if len(parts) >= 3 {
		return strings.Join(parts[:3], "/")
	}
	return importPath
}

var rustBuiltinCrates = map[string]bool{
	"std": true, "core": true, "alloc": true, "proc_macro": true,
	"test": true, "crate": true, "self": true, "super": true,
}

func extractRustImports(filePath string, localModules map[string]bool) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var imports []string
	scanner := bufio.NewScanner(io.LimitReader(f, 256*1024))
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
	return imports
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

func extractCPPIncludes(filePath string, localModules map[string]bool) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var includes []string
	scanner := bufio.NewScanner(io.LimitReader(f, 256*1024))
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
	return includes
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

func extractJVMImports(filePath string) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var imports []string
	scanner := bufio.NewScanner(io.LimitReader(f, 256*1024))
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
	return imports
}

func extractDotNetUsings(filePath string, localModules map[string]bool) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var usings []string
	scanner := bufio.NewScanner(io.LimitReader(f, 256*1024))
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
	return usings
}

func extractPHPUses(filePath string, localModules map[string]bool) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var uses []string
	scanner := bufio.NewScanner(io.LimitReader(f, 256*1024))
	for scanner.Scan() {
		line := scanner.Text()
		m := phpUseRe.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		vendor := strings.ToLower(m[1])
		pkg := strings.ToLower(m[2])
		if vendor == "app" || vendor == "tests" || localModules[vendor] {
			continue
		}
		uses = append(uses, vendor+"/"+pkg)
	}
	return uses
}

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

func extractRubyRequires(filePath string, localModules map[string]bool) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var reqs []string
	scanner := bufio.NewScanner(io.LimitReader(f, 256*1024))
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
	return reqs
}

func extractDartImports(filePath string, localModules map[string]bool) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var imports []string
	scanner := bufio.NewScanner(io.LimitReader(f, 256*1024))
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
	return imports
}
