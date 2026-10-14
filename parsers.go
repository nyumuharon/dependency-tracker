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
