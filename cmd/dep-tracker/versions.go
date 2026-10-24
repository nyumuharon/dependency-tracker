package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var exactVersionRE = regexp.MustCompile(`^v?[0-9][0-9A-Za-z.!+_-]*$`)
var semverReleaseRE = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.-]+)?$`)
var wildcardVersionRE = regexp.MustCompile(`(?i)(^|\.)x($|\.)`)

// validateQueryVersion refuses to substitute a constraint or current registry
// release for the version actually declared, locked, or installed by a project.
func validateQueryVersion(p Package) error {
	v := p.Version
	if p.VersionSource == "import" || p.VersionSource == "constraint" || (!exactVersionRE.MatchString(v) || wildcardVersionRE.MatchString(v)) {
		return fmt.Errorf("unresolved version %q for %s; provide a lockfile or installed environment", v, p.Name)
	}
	return nil
}

// compareVersions supports SemVer for SemVer ecosystems and numeric releases
// elsewhere. Unsupported ecosystem-specific qualifiers are deliberately left
// unordered, rather than guessing a potentially unsafe upgrade.
func compareVersions(a, b, ecosystem string) (int, bool) {
	semver := ecosystem == "npm" || ecosystem == "Go" || ecosystem == "crates.io" || ecosystem == "Pub"
	parse := func(v string) ([]uint64, string, bool) {
		if !semverReleaseRE.MatchString(v) {
			return nil, "", false
		}
		v = strings.TrimPrefix(v, "v")
		if !semver && strings.ContainsAny(v, "-+") {
			return nil, "", false
		}
		v = strings.SplitN(v, "+", 2)[0]
		parts := strings.SplitN(v, "-", 2)
		var pre string
		if len(parts) == 2 {
			pre = parts[1]
		}
		var nums []uint64
		for _, part := range strings.Split(parts[0], ".") {
			n, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return nil, "", false
			}
			nums = append(nums, n)
		}
		if semver && len(nums) != 3 {
			return nil, "", false
		}
		return nums, pre, true
	}
	an, ap, ok := parse(a)
	if !ok {
		return 0, false
	}
	bn, bp, ok := parse(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < len(an) || i < len(bn); i++ {
		var av, bv uint64
		if i < len(an) {
			av = an[i]
		}
		if i < len(bn) {
			bv = bn[i]
		}
		if av < bv {
			return -1, true
		}
		if av > bv {
			return 1, true
		}
	}
	if ap == bp {
		return 0, true
	}
	if ap == "" {
		return 1, true
	}
	if bp == "" {
		return -1, true
	}
	as, bs := strings.Split(ap, "."), strings.Split(bp, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		ai, ae := strconv.ParseUint(as[i], 10, 64)
		bi, be := strconv.ParseUint(bs[i], 10, 64)
		if ae == nil && be == nil {
			if ai < bi {
				return -1, true
			}
			return 1, true
		}
		if ae == nil {
			return -1, true
		}
		if be == nil {
			return 1, true
		}
		if as[i] < bs[i] {
			return -1, true
		}
		return 1, true
	}
	if len(as) < len(bs) {
		return -1, true
	}
	return 1, true
}

func normalizeExactPin(v, ecosystem string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "==") && !strings.ContainsAny(v[2:], ",* ") {
		return v[2:]
	}
	if strings.HasPrefix(v, "=") && !strings.HasPrefix(v, "==") {
		return strings.TrimSpace(v[1:])
	}
	if ecosystem == "NuGet" && strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") && !strings.Contains(v, ",") {
		return strings.Trim(v, "[]")
	}
	return v
}

// Only named dependency inputs turn parse failures into scan errors. Unrelated
// JSON/YAML/config files are expected while walking ordinary application trees.
func isNamedDependencyFile(name string) bool {
	if IsManifestFile(name) {
		return true
	}
	switch strings.ToLower(name) {
	case "pipfile", "gemfile", "gradle.lockfile", "build.gradle", "build.gradle.kts", "libs.versions.toml", "setup.py", "setup.cfg", "conanfile.py", "package.resolved", "mix.exs", "mix.lock", "cmakelists.txt", "pubspec.yaml", "pubspec.lock", "environment.yml", "environment.yaml", "directory.packages.props":
		return true
	}
	return strings.HasSuffix(name, ".fsproj") || strings.HasSuffix(name, ".vbproj")
}
