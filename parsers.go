package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

func ParseManifest(filePath string) ([]Package, error) {
	switch {
	case strings.HasSuffix(filePath, "package.json"):
		return parseNPM(filePath)
	case strings.HasSuffix(filePath, "requirements.txt"):
		return parsePyPI(filePath)
	case strings.HasSuffix(filePath, "pom.xml"):
		return parseMaven(filePath)
	case strings.HasSuffix(filePath, ".csproj"),
		strings.HasSuffix(filePath, "packages.config"):
		return parseNuGet(filePath)
	case strings.HasSuffix(filePath, "go.mod"):
		return parseGoMod(filePath)
	case strings.HasSuffix(filePath, "Cargo.lock"):
		return parseCargoLock(filePath)
	case strings.HasSuffix(filePath, "Cargo.toml"):
		return parseCargoToml(filePath)
	case strings.HasSuffix(filePath, "composer.json"):
		return parseComposer(filePath)
	case strings.HasSuffix(filePath, "Gemfile.lock"):
		return parseRubyGem(filePath)
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
