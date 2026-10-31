package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDiscoveryOptionalSourcesAndPrecedence(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "package.json", `{"dependencies":{"example":"1.0.0"}}`)
	writeFixture(t, root, "unrelated.json", `{"configuration":true}`)
	writeFixture(t, root, "empty.cfg", "")
	writeFixture(t, root, ".hidden/package.json", `{"dependencies":{"ignored":"1.0.0"}}`)
	writeFixture(t, root, "local/__init__.py", "")
	writeFixture(t, root, "runtime/pyvenv.cfg", "home = /usr/bin\n")
	writeFixture(t, root, "runtime/lib/python/site-packages/python_dep.dist-info/METADATA", "Name: python-dep\nVersion: 1.0.0\n\n")
	writeFixture(t, root, "assets/project.assets.json", `{"libraries":{"Library/1.0.0":{"type":"package"}}}`)
	pkgs, _, err := DiscoverDependencies(root)
	if err != nil || len(pkgs) != 3 {
		t.Fatalf("optional sources: %+v %v", pkgs, err)
	}
	for _, reader := range []func(string) error{
		func(p string) error { _, err := FindManifests(p); return err },
		func(p string) error { _, _, err := DiscoverDependencies(p); return err },
	} {
		if err := reader(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("unreadable project ignored")
		}
	}
	if pkgs, files := scanSourceCodeImports(filepath.Join(t.TempDir(), "missing"), map[string]bool{}); len(pkgs) != 0 || len(files) != 0 {
		t.Fatal("unreadable source invented imports")
	}
	cpp := t.TempDir()
	writeFixture(t, cpp, "main.cpp", "#include </absolute>\n")
	if pkgs, _ := scanSourceCodeImports(cpp, map[string]bool{}); len(pkgs) != 0 {
		t.Fatalf("empty package identity invented: %+v", pkgs)
	}
	root = t.TempDir()
	writeFixture(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}`)
	writeFixture(t, root, "node_modules/broken/package.json", "invalid")
	if pkgs, _, err := DiscoverDependencies(root); err != nil || len(pkgs) != 1 {
		t.Fatalf("lockfile priority lost: %+v %v", pkgs, err)
	}
	root = t.TempDir()
	writeFixture(t, root, "Cargo.toml", "[dependencies]\nserde = \"1.0.0\"\n")
	if pkgs, _, err := DiscoverDependencies(root); err != nil || len(pkgs) != 1 {
		t.Fatalf("Cargo manifest not discovered: %+v %v", pkgs, err)
	}
	root = t.TempDir()
	writeFixture(t, root, "conan.lock", `{"nodes":{"0":{"ref":"application/1.0.0"},"1":{"ref":"zlib/1.3.1"}}}`)
	writeFixture(t, root, "conanfile.txt", "[requires]\nzlib/1.0.0\n")
	if pkgs, _, err := DiscoverDependencies(root); err != nil || len(pkgs) != 1 || pkgs[0].Version != "1.3.1" {
		t.Fatalf("Conan lock priority lost: %+v %v", pkgs, err)
	}
	py := writeFixture(t, t.TempDir(), "pyproject.toml", "[project]\ndependencies = [\"requests==2.32.3\"]\n")
	if pkgs, err := ParseManifest(py); err != nil || len(pkgs) != 1 {
		t.Fatalf("pyproject dispatch: %+v %v", pkgs, err)
	}
	installed := writeFixture(t, t.TempDir(), "installed.json", `{"packages":[{"name":"monolog/monolog","version":"3.0.0"}]}`)
	if pkgs, err := ParseManifest(installed); err != nil || len(pkgs) != 1 || pkgs[0].VersionSource != "installed" {
		t.Fatalf("installed source confidence: %+v %v", pkgs, err)
	}
}

func TestOptionalEnvironmentLookupFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	for _, dir := range []string{"obj", "vcpkg_installed", ".dart_tool"} {
		for _, mode := range []string{"absent-metadata", "unreadable"} {
			t.Run(dir+mode, func(t *testing.T) {
				root := t.TempDir()
				writeFixture(t, root, "package.json", `{"dependencies":{"example":"1.0.0"}}`)
				protected := filepath.Join(root, dir)
				if err := os.Mkdir(protected, 0700); err != nil {
					t.Fatal(err)
				}
				if mode == "unreadable" {
					if err := os.Chmod(protected, 0); err != nil {
						t.Fatal(err)
					}
					defer os.Chmod(protected, 0700)
					if _, err := os.Stat(filepath.Join(protected, "file")); !os.IsPermission(err) {
						t.Skip("account bypasses permissions")
					}
				}
				_, _, err := DiscoverDependencies(root)
				if (err != nil) != (mode == "unreadable") {
					t.Fatalf("unexpected metadata outcome: %v", err)
				}
			})
		}
	}
}

func TestLegacyAndPartialManifestRecords(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name, body string
		parse      func(string) ([]Package, error)
		want       int
	}{
		{"Cargo.toml", "[dependencies]\nmalformed\nserde = \"1.0.0\"\n", parseCargoToml, 1},
		{"package-lock.json", `{"packages":{"workspace/app":{"version":"1.0.0"},"node_modules/":{"version":"1.0.0"},"node_modules/a":{"version":"1.0.0"}}}`, parseNPMLock, 1},
		{"yarn.lock", "legacy:\n  version \"1.0.0\"\n", parseYarnLock, 1},
		{"pnpm-lock.yaml", "packages:\n  a@1.0.0_peer@2.0.0:\n    resolution: {}\n  '@scope/pkg@1.0.0(peer@2.0.0)':\n    resolution: {}\n", parsePnpmLock, 2},
		{"composer.lock", `{"packages":[{"name":"php","version":"8.3"},{"name":"ext-json","version":"1.0.0"},{"name":"monolog/monolog","version":"3.0.0"}]}`, parseComposerLock, 1},
		{"go.sum", "\n// comment\nexample.com/module v1.0.0 h1:fixture\n", parseGoSum, 1},
	}
	for _, tc := range cases {
		path := writeFixture(t, root, tc.name, tc.body)
		pkgs, err := tc.parse(path)
		if err != nil || len(pkgs) != tc.want {
			t.Fatalf("%s: %+v %v", tc.name, pkgs, err)
		}
	}
	// A malformed dependency string must not turn a partial inventory into success.
	badPy := writeFixture(t, root, "pyproject.toml", "[project]\ndependencies = [\"unterminated]\n")
	if _, err := parsePyProjectToml(badPy); err == nil {
		t.Fatal("unterminated dependency string accepted")
	}
	// Unsupported lines are ignored without inventing packages from their text.
	py := writeFixture(t, root, "pyproject.toml", "[project]\nunknown\n[tool.poetry.dependencies]\nunknown\nrequests = \"2.32.3\"\n")
	if pkgs, err := parsePyProjectToml(py); err != nil || len(pkgs) != 1 {
		t.Fatalf("%+v %v", pkgs, err)
	}
	setup := "# comment\nsetup(install_requires=[\"install_requires\",\"requests==2.32.3\"])\n"
	if pkgs, err := parseSetupPy("fixture", setup); err != nil || len(pkgs) != 2 {
		t.Fatalf("valid package name discarded: %+v %v", pkgs, err)
	}
	cmake := "find_package(ZLIB REQUIRED)\nFetchContent_Declare(fmt GIT_REPOSITORY https://example.com/fmt GIT_TAG v11.0.0)\n"
	if pkgs, err := parseCMakeLists("fixture", cmake); err != nil || len(pkgs) != 2 {
		t.Fatalf("%+v %v", pkgs, err)
	}
}

func TestTOMLAndYAMLContentBoundaryRecognition(t *testing.T) {
	for _, body := range []string{"[project]\ndependencies=[\"requests==2.32.3\"]\n", "[dependencies]\nserde=\"1.0.0\"\n"} {
		path := writeFixture(t, t.TempDir(), "dependencies.cfg", body)
		if pkgs, ok := tryParseGenericTOMLOrINI(path, body); !ok || len(pkgs) != 1 {
			t.Fatalf("%+v %v", pkgs, ok)
		}
	}
	pipfile := "#comment\n\n[source]\nurl=\"https://pypi.org\"\n[packages]\nunknown\nrequests=\"\"\n"
	if pkgs := parsePipfileToml("fixture", pipfile); len(pkgs) != 1 || pkgs[0].Version != "latest" {
		t.Fatalf("unresolved dependency invented a version: %+v", pkgs)
	}
	setupcfg := "#comment\n\n[options]\ninstall_requires =\n    requests==2.32.3\n[other]\nvalue=true\n"
	if pkgs := parseSetupCfg("fixture", setupcfg); len(pkgs) != 1 {
		t.Fatalf("%+v", pkgs)
	}
	catalog := "[libraries]\nunknown\nlib={unknown, module=\"org.example:lib\",version=\"1.0.0\"}\n"
	if pkgs := parseGradleVersionCatalog("fixture", catalog); len(pkgs) != 1 {
		t.Fatalf("%+v", pkgs)
	}
	pub := "#comment\n\ndependencies:\n  http: 1.0.0\n"
	if pkgs := parsePubspecYAML("fixture", pub); len(pkgs) != 1 {
		t.Fatalf("%+v", pkgs)
	}
	conda := "dependencies:\n  - requests==2.32.3\nvariables:\n  key: value\n"
	if pkgs := parseCondaEnvironmentYAML("fixture", conda); len(pkgs) != 1 {
		t.Fatalf("%+v", pkgs)
	}
	if pkgs, err := parsePubspecLock("fixture", "#comment\npackages:\n#comment\n  http:\n    unsupported line\n    version: 1.0.0\n"); err != nil || len(pkgs) != 1 {
		t.Fatalf("%+v %v", pkgs, err)
	}
	if pkgs, err := parsePubspecLock("fixture", "packages:\n  flutter:\n    source: sdk\n\n"); err != nil || len(pkgs) != 0 {
		t.Fatalf("%+v %v", pkgs, err)
	}
	// Long records must report scanner errors, not pretend a truncated file is empty.
	if _, err := parsePubspecLock("fixture", strings.Repeat("x", 100000)); err == nil {
		t.Fatal("truncated lockfile accepted")
	}
}
