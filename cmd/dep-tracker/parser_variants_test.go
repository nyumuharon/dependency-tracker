package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestCargoAndPythonManifestVariants(t *testing.T) {
	t.Run("cargo-inline", func(t *testing.T) {
		body := `# comment
[package]
name = "application"
[dependencies]
serde = { features = ["derive"], version = "=1.0.210" }
local = { path = "../local" }
rand = "0.8.5"
[features]
default = []
`
		pkgs, err := ParseManifest(writeFixture(t, t.TempDir(), "Cargo.toml", body))
		if err != nil || len(pkgs) != 2 {
			t.Fatalf("%+v %v", pkgs, err)
		}
		for _, p := range pkgs {
			if p.Name == "serde" && (p.Version != "1.0.210" || p.VersionSource != "manifest") {
				t.Fatalf("exact inline pin lost: %+v", p)
			}
		}
	})
	t.Run("poetry-dependency-tables", func(t *testing.T) {
		body := `[project]
name = "application"
dependencies = ["requests>=2.0", "requests>=2.0"] # comment
[tool.poetry.dependencies]
python = "^3.10"
flask = { optional = true, version = "^3.0" }
requests = ">=2.0"
local = { path = "../local" }
[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
`
		pkgs, err := parsePyProjectToml(writeFixture(t, t.TempDir(), "pyproject.toml", body))
		if err != nil || len(pkgs) != 3 {
			t.Fatalf("duplicates, python, or local path included: %+v %v", pkgs, err)
		}
	})
	t.Run("requirements-markers", func(t *testing.T) {
		body := "# comment\n-r other.txt\nrequests==2.32.3 # comment\n\n"
		pkgs, err := parsePyPI(writeFixture(t, t.TempDir(), "requirements.txt", body))
		if err != nil || len(pkgs) != 1 {
			t.Fatalf("%+v %v", pkgs, err)
		}
		for _, spec := range []string{"", " ", ">=1", "a=="} {
			name, version := parsePEP508Spec(spec)
			if name != "" || version != "" {
				t.Errorf("incomplete spec accepted: %q %q %q", spec, name, version)
			}
		}
	})
}

func TestXMLVersionAndPropertyVariants(t *testing.T) {
	t.Run("nuget-child-versions", func(t *testing.T) {
		body := `<Project><ItemGroup>
<PackageReference Update="Library"><Version>1.2.3</Version></PackageReference>
<PackageReference Include="Library" Version="1.2.3"/>
<PackageVersion Include="Other"><Version>2.0.0</Version></PackageVersion>
<PackageReference Include="Missing"/>
</ItemGroup><package id="Third" version="3.0.0"/></Project>`
		for _, name := range []string{"project.csproj", "project.fsproj", "Directory.Packages.props"} {
			pkgs, err := ParseManifest(writeFixture(t, t.TempDir(), name, body))
			if err != nil || len(pkgs) != 3 {
				t.Fatalf("%s: %+v %v", name, pkgs, err)
			}
		}
		if _, err := parseDotNetXML("fixture", []byte("<invalid")); err == nil {
			t.Fatal("malformed XML accepted")
		}
	})
	t.Run("maven-parent-and-project-version", func(t *testing.T) {
		for _, version := range []string{"<version>1.2.3</version>", "<parent><version>1.2.3</version></parent>"} {
			body := `<project>` + version + `<dependencies><dependency><groupId>org.example</groupId><artifactId>library</artifactId><version>${project.version}</version></dependency><dependency><groupId>org.example</groupId><artifactId>unknown</artifactId><version>${unresolved}</version></dependency><dependency><artifactId>missing-group</artifactId><version>1.0.0</version></dependency></dependencies></project>`
			pkgs, err := parseMavenWithProperties("fixture", []byte(body))
			if err != nil || len(pkgs) != 1 || pkgs[0].Version != "1.2.3" {
				t.Fatalf("%+v %v", pkgs, err)
			}
		}
	})
}

func TestGradleLockAndCatalogVariants(t *testing.T) {
	t.Run("lock", func(t *testing.T) {
		body := "# comment\n\nempty=compileClasspath\norg.example:library:1.0.0=runtimeClasspath\norg.example:library:1.0.0=testRuntimeClasspath\n"
		pkgs, err := parseGradleFile("gradle.lockfile", body)
		if err != nil || len(pkgs) != 1 {
			t.Fatalf("%+v %v", pkgs, err)
		}
	})
	t.Run("catalog", func(t *testing.T) {
		body := `# comment
[versions]
one="1.0.0"
[libraries]
one="org.example:one:1.0.0"
two={group="org.example",name="two",version="2.0.0"}
three={module="org.example:three",version.ref="one"}
missing={group="org.example",name="unknown"}
[bundles]
all=["one","two"]
`
		pkgs := parseGradleVersionCatalog("fixture", body)
		if len(pkgs) != 3 {
			t.Fatalf("%+v", pkgs)
		}
	})
}

func TestLockfileLegacyAndMalformedShapes(t *testing.T) {
	t.Run("npm-legacy", func(t *testing.T) {
		body := `{"dependencies":{"good":{"version":"1.0.0","dependencies":{"child":{"version":"2.0.0"}}},"bad":12,"no-version":{}}}`
		pkgs, err := parseNPMLock(writeFixture(t, t.TempDir(), "package-lock.json", body))
		if err != nil || len(pkgs) != 2 {
			t.Fatalf("%+v %v", pkgs, err)
		}
		if _, err := parseNPMLock(writeFixture(t, t.TempDir(), "package-lock.json", `{"packages":{"node_modules/a":{"version":12}}}`)); err == nil {
			t.Fatal("invalid lock version type")
		}
	})
	t.Run("conan-legacy", func(t *testing.T) {
		for _, body := range []string{`{}`, `{"nodes":[{"ref":"openssl/3.3.2"}]}`, `{"nodes":[{"ref":"application/1.0.0"},{"ref":"openssl/3.3.2"},{"ref":"null"},{"ref":"bad"}]}`, `{"nodes":12}`} {
			path := writeFixture(t, t.TempDir(), "conan.lock", body)
			pkgs, err := parseConanLock(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range pkgs {
				if p.Name != "openssl" {
					t.Fatalf("invalid or root dependency included: %+v", p)
				}
			}
		}
	})
	t.Run("vcpkg-variants", func(t *testing.T) {
		body := `{"dependencies":[{"name":"a","version-string":"1.0.0"},{"name":"b","version-date":"2026-01-01"},{"name":""},12]}`
		pkgs, err := parseVcpkg(writeFixture(t, t.TempDir(), "vcpkg.json", body))
		if err != nil || len(pkgs) != 2 {
			t.Fatalf("%+v %v", pkgs, err)
		}
	})
	t.Run("swift-legacy-name", func(t *testing.T) {
		data := []byte(`{"pins":[{"package":"legacy","state":{"version":"1.0.0"}},{"identity":"unversioned","state":{}}]}`)
		if pkgs := parseSwiftPackageResolved("fixture", data); len(pkgs) != 1 || pkgs[0].Name != "legacy" {
			t.Fatalf("%+v", pkgs)
		}
		if pkgs := parseSwiftPackageResolved("fixture", []byte("invalid")); len(pkgs) != 0 {
			t.Fatal("invalid JSON accepted")
		}
	})
	t.Run("conan-noise", func(t *testing.T) {
		body := "[generators]\ncmake\n[requires]\nopenssl/3.3.2 # comment\nzlib/1.3.1 ; comment\n[]\n"
		pkgs, err := parseConanFile(writeFixture(t, t.TempDir(), "conanfile.txt", body))
		if err != nil || len(pkgs) != 2 {
			t.Fatalf("%+v %v", pkgs, err)
		}
	})
}

func TestOptionalFileAndContentDispatch(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct{ name, body string }{
		{"project.assets.json", `{"libraries":{}}`}, {"package_config.json", `{"packages":[]}`}, {"installed.json", `{"packages":[]}`}, {"METADATA", "Name: example\nVersion: 1.0.0\n\n"}, {"PKG-INFO", "Name: example\nVersion: 1.0.0\n\n"},
	} {
		path := writeFixture(t, root, tc.name, tc.body)
		if _, err := ParseManifest(path); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if _, err := ParseManifest(writeFixture(t, root, "METADATA", "invalid")); err == nil {
		t.Fatal("invalid metadata accepted")
	}
	if _, ok := tryParseGenericJSON("fixture", []byte("invalid")); ok {
		t.Fatal("malformed JSON detected as dependencies")
	}
	if _, ok := tryParseGenericXML("fixture", []byte("<unrelated/>")); ok {
		t.Fatal("unrelated XML detected as dependencies")
	}
	if _, ok := tryParseGenericTOMLOrINI("fixture", "unrelated=true"); ok {
		t.Fatal("unrelated TOML detected as dependencies")
	}
	if _, ok := tryParseGenericYAML("fixture", "unrelated: true"); ok {
		t.Fatal("unrelated YAML detected as dependencies")
	}
	path := filepath.Join("testdata", "corpus", "pnpm-v9", "pnpm-lock.yaml")
	data := []byte("packages:\n  example@1.0.0:\n")
	if pkgs, ok := tryParseGenericYAML(path, string(data)); !ok || len(pkgs) != 2 {
		t.Fatalf("existing pnpm file not recognized: %+v %v", pkgs, ok)
	}
	if got := unquotedBracketDelta(`["escaped\"quote", 'single']`); got != 0 {
		t.Fatalf("quoted brackets: %d", got)
	}
	for _, name := range []string{"requirements-dev.txt", "requirements.in", "project.fsproj"} {
		if !isCandidateDependencyFile(name) {
			t.Error(name)
		}
	}
	var response osvResponse
	if err := json.Unmarshal([]byte(`{"vulns":[]}`), &response); err != nil {
		t.Fatal(err)
	}
	if got := parseVulns(response, Package{}); len(got) != 0 {
		t.Fatal("empty advisories invented")
	}
	if _, err := parseMixLock("fixture", "%{unsupported}"); err == nil {
		t.Fatal("unsupported lock syntax accepted")
	}
	if _, err := parsePubspecLock("fixture", "packages:\n  http:\n    source: hosted\n"); err == nil {
		t.Fatal("missing locked version accepted")
	}
	if _, err := parsePubspecLock("fixture", "packages:\n  first:\n    source: hosted\n  next:\n    version: 1.0.0\n"); err == nil {
		t.Fatal("missing intermediate version accepted")
	}
	if _, err := parsePubspecLock("fixture", "packages:\n  first:\n    source: hosted\nsdks:\n"); err == nil {
		t.Fatal("missing version before next section accepted")
	}
	if _, err := parsePubspecLock("fixture", strings.Repeat("x", 100000)); err == nil {
		t.Fatal("truncated lockfile accepted")
	}
}
