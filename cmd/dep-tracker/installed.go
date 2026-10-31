package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// DiscoveryError means at least one discovered input could not be inspected.
// Its presence makes the scan incomplete even when other inputs were readable.
type DiscoveryError struct{ Issues []error }

func (e *DiscoveryError) Error() string {
	return "dependency discovery incomplete: " + errors.Join(e.Issues...).Error()
}
func (e *DiscoveryError) Unwrap() []error { return e.Issues }

func optionalInstalledFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if _, linkErr := os.Lstat(path); linkErr == nil {
			return nil, true, fmt.Errorf("read %s: %w", path, err)
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, true, fmt.Errorf("read %s: %w", path, err)
	}
	return data, true, nil
}

func inspectPythonVenv(venvDir string, localModules map[string]bool) ([]Package, error) {
	var pkgs []Package
	seen := make(map[string]bool)
	var issues []error
	_ = filepath.WalkDir(venvDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			issues = append(issues, fmt.Errorf("walk %s: %w", path, err))
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "__pycache__", "include", "bin", "Scripts":
				return filepath.SkipDir
			}
			return nil
		}
		dir := filepath.Dir(path)
		if (d.Name() != "METADATA" && d.Name() != "PKG-INFO") || (!strings.HasSuffix(dir, ".dist-info") && !strings.HasSuffix(dir, ".egg-info")) {
			return nil
		}
		editable, err := isEditableInstall(filepath.Join(dir, "direct_url.json"))
		if err != nil {
			issues = append(issues, err)
			return nil
		}
		if editable {
			return nil
		}
		name, version, err := parsePythonMetadataFile(path)
		if err != nil {
			issues = append(issues, err)
			return nil
		}
		norm := strings.ReplaceAll(strings.ToLower(name), "-", "_")
		if defaultVenvSkipPkgs[strings.ToLower(name)] || localModules[norm] {
			return nil
		}
		p := Package{Name: name, Version: version, Ecosystem: "PyPI", ManifestPath: path}
		if !seen[p.Key()] {
			seen[p.Key()] = true
			pkgs = append(pkgs, p)
		}
		return nil
	})
	return pkgs, errors.Join(issues...)
}

func isEditableInstall(path string) (bool, error) {
	data, exists, err := optionalInstalledFile(path)
	if err != nil || !exists {
		return false, err
	}
	var info struct {
		DirInfo struct {
			Editable bool `json:"editable"`
		} `json:"dir_info"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return false, fmt.Errorf("invalid %s: %w", path, err)
	}
	if string(data) == "null" {
		return false, fmt.Errorf("invalid %s: expected metadata object", path)
	}
	return info.DirInfo.Editable, nil
}

func parsePythonMetadataFile(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	var name, version string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Name:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		}
		if strings.HasPrefix(line, "Version:") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", fmt.Errorf("read %s: %w", path, err)
	}
	if name == "" || version == "" {
		return "", "", fmt.Errorf("invalid %s: missing Name or Version", path)
	}
	return name, version, nil
}

func inspectGoVendorModules(path string) ([]Package, error) {
	data, exists, err := optionalInstalledFile(path)
	if err != nil || !exists {
		return nil, err
	}
	var pkgs []Package
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	haveHeader := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "# ") {
			if line != "" && !strings.HasPrefix(line, "##") && !haveHeader {
				return pkgs, fmt.Errorf("package entry without module header in %s", path)
			}
			continue
		}
		haveHeader = true
		fields := strings.Fields(line)
		// Replacement-only headers have no version; standard-library replacement
		// targets are not separate installed modules.
		if len(fields) < 3 {
			return pkgs, fmt.Errorf("invalid module header in %s: %s", path, line)
		}
		if fields[2] == "=>" {
			continue
		}
		if !strings.HasPrefix(fields[2], "v") {
			return pkgs, fmt.Errorf("invalid module version in %s: %s", path, line)
		}
		pkgs = append(pkgs, Package{Name: fields[1], Version: fields[2], Ecosystem: "Go", ManifestPath: path})
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("read %s: %w", path, err)
	}
	return pkgs, nil
}

func inspectComposerInstalled(path string) ([]Package, error) {
	data, exists, err := optionalInstalledFile(path)
	if err != nil || !exists {
		return nil, err
	}
	type compPkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var list []compPkg
	if strings.HasPrefix(strings.TrimSpace(string(data)), "[") {
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("invalid %s: %w", path, err)
		}
	} else {
		var v2 struct {
			Packages *[]compPkg `json:"packages"`
		}
		if err := json.Unmarshal(data, &v2); err != nil {
			return nil, fmt.Errorf("invalid %s: %w", path, err)
		}
		if v2.Packages == nil {
			return nil, fmt.Errorf("invalid %s: missing packages array", path)
		}
		list = *v2.Packages
	}
	var pkgs []Package
	for _, item := range list {
		name := strings.TrimSpace(item.Name)
		version := strings.TrimPrefix(strings.TrimSpace(item.Version), "v")
		if name == "php" || strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-") {
			continue
		}
		if name == "" || version == "" {
			return pkgs, fmt.Errorf("invalid package in %s: missing name or version", path)
		}
		pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "Packagist", ManifestPath: path})
	}
	return pkgs, nil
}

func inspectRubyVendorBundle(vendorDir string) ([]Package, error) {
	root := filepath.Join(vendorDir, "bundle")
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("stat %s: %w", root, err)
	}
	var pkgs []Package
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(filepath.Dir(path)) != "specifications" || !strings.HasSuffix(d.Name(), ".gemspec") {
			return nil
		}
		// Ruby gemspecs are code. Verify readability without executing them.
		if _, err := os.ReadFile(path); err != nil {
			return err
		}
		m := gemspecFileRe.FindStringSubmatch(d.Name())
		if len(m) != 3 {
			return fmt.Errorf("cannot determine gem name/version from %s", path)
		}
		pkgs = append(pkgs, Package{Name: m[1], Version: m[2], Ecosystem: "RubyGems", ManifestPath: path})
		return nil
	})
	if err != nil {
		return pkgs, fmt.Errorf("inspect %s: %w", root, err)
	}
	return pkgs, nil
}

func inspectDotNetAssets(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var assets struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
	}
	if err := json.Unmarshal(data, &assets); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", path, err)
	}
	if assets.Libraries == nil {
		return nil, fmt.Errorf("invalid %s: missing libraries object", path)
	}
	var pkgs []Package
	for key, lib := range assets.Libraries {
		if lib.Type == "" {
			return pkgs, fmt.Errorf("invalid library %q in %s: missing type", key, path)
		}
		if !strings.EqualFold(lib.Type, "package") {
			continue
		}
		parts := strings.SplitN(key, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return pkgs, fmt.Errorf("invalid library %q in %s", key, path)
		}
		pkgs = append(pkgs, Package{Name: parts[0], Version: parts[1], Ecosystem: "NuGet", ManifestPath: path})
	}
	return pkgs, nil
}

func inspectVcpkgStatus(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var pkgs []Package
	var name, version, status string
	feature := false
	flush := func() error {
		if strings.Contains(status, "installed") && !strings.Contains(status, "not-installed") && !feature {
			if name == "" || version == "" {
				return fmt.Errorf("invalid installed package in %s: missing Package or Version", path)
			}
			pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "ConanCenter", ManifestPath: path})
		}
		name, version, status = "", "", ""
		feature = false
		return nil
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if err := flush(); err != nil {
				return pkgs, err
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return pkgs, fmt.Errorf("invalid status line in %s: %s", path, line)
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Package":
			name = value
		case "Version":
			version = value
		case "Status":
			status = value
		case "Feature":
			feature = true
		}
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("read %s: %w", path, err)
	}
	if err := flush(); err != nil {
		return pkgs, err
	}
	return pkgs, nil
}

func inspectDartPackageConfig(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg struct {
		Packages *[]struct {
			Name    string `json:"name"`
			RootURI string `json:"rootUri"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", path, err)
	}
	if cfg.Packages == nil {
		return nil, fmt.Errorf("invalid %s: missing packages array", path)
	}
	var pkgs []Package
	for _, entry := range *cfg.Packages {
		if entry.Name == "" || entry.RootURI == "" {
			return pkgs, fmt.Errorf("invalid package in %s: missing name or rootUri", path)
		}
		if entry.Name == "flutter" || entry.Name == "flutter_test" || strings.HasPrefix(entry.RootURI, ".") {
			continue
		}
		uri, err := url.Parse(entry.RootURI)
		if err != nil {
			return pkgs, fmt.Errorf("invalid rootUri in %s: %w", path, err)
		}
		base := filepath.Base(strings.TrimRight(uri.Path, "/"))
		version := "latest"
		if rest, ok := strings.CutPrefix(base, entry.Name+"-"); ok && rest != "" {
			version = rest
		}
		pkgs = append(pkgs, Package{Name: entry.Name, Version: version, Ecosystem: "Pub", ManifestPath: path})
	}
	return pkgs, nil
}

func inspectNodeModules(root string) ([]Package, error) {
	var pkgs []Package
	seen := make(map[string]bool)
	visited := make(map[string]bool)
	var walk func(string, bool) error
	walk = func(dir string, optional bool) error {
		resolved, err := filepath.EvalSymlinks(dir)
		if optional && os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("resolve %s: %w", dir, err)
		}
		absolute, err := filepath.Abs(resolved)
		if err != nil {
			return err
		}
		if visited[absolute] {
			return nil
		}
		visited[absolute] = true
		hiddenLock := filepath.Join(dir, ".package-lock.json")
		if data, exists, err := optionalInstalledFile(hiddenLock); err != nil {
			return err
		} else if exists {
			var metadata map[string]json.RawMessage
			if err := json.Unmarshal(data, &metadata); err != nil {
				return fmt.Errorf("invalid %s: %w", hiddenLock, err)
			}
			if metadata["packages"] == nil && metadata["dependencies"] == nil && metadata["lockfileVersion"] == nil {
				return fmt.Errorf("invalid %s: missing lockfile metadata", hiddenLock)
			}
			locked, err := parseNPMLock(hiddenLock)
			if err != nil {
				return err
			}
			if len(locked) > 0 {
				for _, p := range locked {
					p.ManifestPath = hiddenLock
					if !seen[p.Key()] {
						seen[p.Key()] = true
						pkgs = append(pkgs, p)
					}
				}
				return nil
			}
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("read %s: %w", dir, err)
		}
		readPackage := func(pkgDir string) error {
			path := filepath.Join(pkgDir, "package.json")
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			var meta struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if err := json.Unmarshal(data, &meta); err != nil {
				return fmt.Errorf("invalid %s: %w", path, err)
			}
			if meta.Name == "" || meta.Version == "" {
				return fmt.Errorf("invalid %s: missing name or version", path)
			}
			p := Package{Name: meta.Name, Version: meta.Version, Ecosystem: "npm", ManifestPath: path}
			if !seen[p.Key()] {
				seen[p.Key()] = true
				pkgs = append(pkgs, p)
			}
			return walk(filepath.Join(pkgDir, "node_modules"), true)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".") || (!entry.IsDir() && entry.Type()&os.ModeSymlink == 0) {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if strings.HasPrefix(entry.Name(), "@") {
				scoped, err := os.ReadDir(path)
				if err != nil {
					return fmt.Errorf("read %s: %w", path, err)
				}
				for _, sub := range scoped {
					if sub.IsDir() || sub.Type()&os.ModeSymlink != 0 {
						if err := readPackage(filepath.Join(path, sub.Name())); err != nil {
							return err
						}
					}
				}
			} else if err := readPackage(path); err != nil {
				return err
			}
		}
		return nil
	}
	err := walk(root, false)
	return pkgs, err
}
