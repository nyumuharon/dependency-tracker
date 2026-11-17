package main

import (
	"strings"

	"github.com/nyumuharon/dependency-tracker/internal/version"
)

var exactVersionRE = version.ExactVersionRE
var wildcardVersionRE = version.WildcardVersionRE

func validateQueryVersion(p Package) error {
	return version.ValidateQueryVersion(p)
}

func compareVersions(a, b, ecosystem string) (int, bool) {
	return version.CompareVersions(a, b, ecosystem)
}

func normalizeExactPin(v, ecosystem string) string {
	return version.NormalizeExactPin(v, ecosystem)
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
