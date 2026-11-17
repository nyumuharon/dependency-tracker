package parser

import (
	"net/http"
	"strings"
	"time"

	"github.com/nyumuharon/dependency-tracker/internal/cache"
	"github.com/nyumuharon/dependency-tracker/internal/intel"
	"github.com/nyumuharon/dependency-tracker/internal/model"
	"github.com/nyumuharon/dependency-tracker/internal/version"
)

type Package = model.Package

var exactVersionRE = version.ExactVersionRE
var wildcardVersionRE = version.WildcardVersionRE

func normalizeExactPin(v, ecosystem string) string {
	return version.NormalizeExactPin(v, ecosystem)
}

func cacheFile(name string) string {
	return cache.File(name)
}

func writeCacheFile(path string, data []byte) {
	cache.WriteFile(path, data)
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

func DisableMavenSleepForTesting() {
	mavenRepositoryURL = "http://127.0.0.1:1/maven2"
	mavenSleep = func(time.Duration) {}
}

func SetHTTPClient(c *http.Client) *http.Client {
	return intel.SetHTTPClient(c)
}
