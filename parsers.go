package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
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
		strings.HasSuffix(fileName, "requirements.txt"),
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
			strings.HasSuffix(base, "Pipfile.lock"):
			pyLocks = append(pyLocks, p)
		case strings.HasSuffix(base, "requirements.txt"):
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

	var manifestFiles []string
	if fi.IsDir() {
		fmt.Printf("Discovering dependency manifests in directory: %s\n", targetPath)
		manifestFiles, err = FindManifests(targetPath)
		if err != nil {
			return nil, fmt.Errorf("manifest discovery failed: %w", err)
		}
		if len(manifestFiles) == 0 {
			return nil, fmt.Errorf("no supported manifests or lockfiles found in directory: %s", targetPath)
		}
		fmt.Printf("Discovered %d manifest(s)/lockfile(s):\n", len(manifestFiles))
		for _, m := range manifestFiles {
			fmt.Printf("  • %s\n", m)
		}
		fmt.Println()
	} else {
		manifestFiles = []string{targetPath}
	}

	var allPkgs []Package
	seen := make(map[string]bool)

	for _, file := range manifestFiles {
		pkgs, err := ParseManifest(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", file, err)
			continue
		}
		for _, p := range pkgs {
			if p.ManifestPath == "" {
				p.ManifestPath = file
			}
			key := p.Name + "@" + p.Version + "@" + p.Ecosystem
			if !seen[key] {
				seen[key] = true
				allPkgs = append(allPkgs, p)
			}
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
	case strings.HasSuffix(filePath, "poetry.lock"):
		return parsePoetryLock(filePath)
	case strings.HasSuffix(filePath, "Pipfile.lock"):
		return parsePipfileLock(filePath)
	case strings.HasSuffix(filePath, "requirements.txt"):
		return parsePyPI(filePath)

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
		return nil, fmt.Errorf("unsupported manifest: %s", filePath)
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
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strip extras e.g. requests[security]==2.28.0
		line = strings.Split(line, "[")[0]
		// handle ==, >=, <=, !=, ~=
		for _, sep := range []string{"==", ">=", "<=", "!=", "~="} {
			if parts := strings.SplitN(line, sep, 2); len(parts) == 2 {
				pkgs = append(pkgs, Package{
					Name:      strings.TrimSpace(parts[0]),
					Version:   strings.TrimSpace(parts[1]),
					Ecosystem: "PyPI",
				})
				break
			}
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
	var pom mavenPOM
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, fmt.Errorf("invalid pom.xml: %w", err)
	}
	var pkgs []Package
	for _, dep := range pom.Dependencies {
		if dep.Version == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:      dep.GroupID + ":" + dep.ArtifactID,
			Version:   dep.Version,
			Ecosystem: "Maven",
		})
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
