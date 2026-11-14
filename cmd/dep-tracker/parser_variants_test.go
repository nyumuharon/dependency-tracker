package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
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
		dir := t.TempDir()
		writeFixture(t, dir, "other.txt", "-r requirements.txt\nflask==3.0.0\n")
		body := "# comment\n-r other.txt\n-c constraints.txt\n--index-url https://example.invalid/simple\nrequests==2.32.3 # comment\n\n"
		pkgs, err := parsePyPI(writeFixture(t, dir, "requirements.txt", body))
		if err != nil || len(pkgs) != 2 || pkgs[0].Name != "flask" || pkgs[0].ManifestPath != filepath.Join(dir, "other.txt") {
			t.Fatalf("include not followed once: %+v %v", pkgs, err)
		}
		if _, err := parsePyPI(writeFixture(t, t.TempDir(), "requirements.txt", "--requirement=missing.txt\n")); err == nil {
			t.Fatal("missing include treated as empty")
		}
		hashed := "requests==2.25.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\njinja2==2.10 --hash=sha256:x\nurllib3 == 1.26.4\npyyaml @ https://example.invalid/pyyaml.whl\n./local-pkg\ngit+https://example.invalid/repo.git\n"
		pkgs, err = parsePyPI(writeFixture(t, t.TempDir(), "requirements.txt", hashed))
		got := map[string]string{}
		for _, p := range pkgs {
			got[p.Name] = p.Version
		}
		want := map[string]string{"requests": "2.25.0", "jinja2": "2.10", "urllib3": "1.26.4", "pyyaml": "@ https://example.invalid/pyyaml.whl"}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("hashes, spaces or direct references misparsed: %v %v", got, err)
		}
		if name, version := parsePEP508Spec("name @ "); name != "" || version != "" {
			t.Errorf("empty direct reference accepted: %q %q", name, version)
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

func pkgVersions(pkgs []Package) map[string]string {
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	return got
}

func TestParserAccuracyFixes(t *testing.T) {
	cases := []struct {
		name, file, body string
		parse            func(string) ([]Package, error)
		want             map[string]string
	}{
		{"go-replace", "go.mod", "module example.com/x\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.3.0 // indirect\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v1.0.0\n\tgithub.com/e/f v1.0.0\n)\nrequire github.com/g/h v1.0.0\n\nreplace golang.org/x/text => golang.org/x/text v0.3.8\nreplace (\n\tgithub.com/a/b v1.0.0 => github.com/fork/b v1.0.1\n\tgithub.com/c/d => ../local/d\n\tgithub.com/e/f v9.9.9 => github.com/e/f v9.9.10\n)\nexclude github.com/g/h v0.9.0\nretract v0.1.0\n", parseGoMod,
			map[string]string{"golang.org/x/text": "v0.3.8", "github.com/fork/b": "v1.0.1", "github.com/e/f": "v1.0.0", "github.com/g/h": "v1.0.0"}},
		{"go-replace-specific-wins", "go.mod", "require github.com/a/b v1.0.0\nreplace github.com/a/b v1.0.0 => github.com/a/b v1.0.2\nreplace github.com/a/b => github.com/a/b v1.0.9\nreplace bad =>\n", parseGoMod,
			map[string]string{"github.com/a/b": "v1.0.2"}},
		{"cargo-lock-sources", "Cargo.lock", "[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"rand\"\nversion = \"0.8.0\"\nsource = \"sparse+https://index.crates.io/\"\n\n[[package]]\nname = \"forked\"\nversion = \"0.1.0\"\nsource = \"git+https://example.invalid/forked\"\n", parseCargoLock,
			map[string]string{"serde": "1.0.0", "rand": "0.8.0"}},
		{"cargo-toml-forms", "Cargo.toml", "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nfoo = { package = \"tokio\", version = \"=1.8.0\" }\nlocal = { path = \"../x\" }\nshared = { workspace = true }\nplain = \"1.0\" # comment\nwithfeatures = { version = \"2.0.0\", features = [\"derive\", \"std\"] }\n\n[dependencies.smallvec]\nversion = \"=1.6.0\"\nfeatures = [\"union\"]\n\n[dependencies.\"renamed\"]\npackage = \"bytes\"\nversion = \"1.0.0\"\n\n[dependencies.from-git]\ngit = \"https://example.invalid/x\"\n\n[target.'cfg(unix)'.dependencies]\nlibc = \"=0.2.0\"\n\n[workspace.dependencies]\nanyhow = \"1.0.0\"\n\n[features]\ndefault = []\n", parseCargoToml,
			map[string]string{"tokio": "=1.8.0", "plain": "1.0", "withfeatures": "2.0.0", "smallvec": "=1.6.0", "bytes": "1.0.0", "libc": "=0.2.0", "anyhow": "1.0.0"}},
		{"npm-v3-alias", "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"root"},"node_modules/foo":{"name":"lodash","version":"4.17.20"},"node_modules/bar":{"version":"1.0.0"},"packages/ws":{"name":"ws-pkg","version":"1.0.0"}}}`, parseNPMLock,
			map[string]string{"lodash": "4.17.20", "bar": "1.0.0"}},
		{"npm-v1-alias", "package-lock.json", `{"lockfileVersion":1,"dependencies":{"foo":{"version":"npm:@scope/real@2.0.0"},"plain":{"version":"1.0.0"}}}`, parseNPMLock,
			map[string]string{"@scope/real": "2.0.0", "plain": "1.0.0"}},
		{"yarn-alias", "yarn.lock", "\"string-width-cjs@npm:string-width@^4.2.0\":\n  version \"4.2.3\"\n\n\"@scope/pkg@npm:^1.0.0\":\n  version: 1.0.1\n\nlodash@^4.17.0:\n  version \"4.17.21\"\n", parseYarnLock,
			map[string]string{"string-width": "4.2.3", "@scope/pkg": "1.0.1", "lodash": "4.17.21"}},
		{"package-json-alias-optional", "package.json", `{"dependencies":{"foo":"npm:lodash@^4.17.0"},"optionalDependencies":{"minimist":"1.2.0"}}`, parseNPM,
			map[string]string{"lodash": "^4.17.0", "minimist": "1.2.0"}},
		{"conan2-lock", "conan.lock", `{"version":"0.5","requires":["zlib/1.2.11#abc%1690000000.0","openssl/3.0.0@user/channel#def"],"build_requires":["cmake/3.27.0"],"python_requires":[]}`, parseConanLock,
			map[string]string{"zlib": "1.2.11", "openssl": "3.0.0", "cmake": "3.27.0"}},
		{"gemfile-lock-platform", "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.10.0-x86_64-linux)\n    rack (2.0.0)\n\nPLATFORMS\n  x86_64-linux\n", parseRubyGem,
			map[string]string{"nokogiri": "1.10.0", "rack": "2.0.0"}},
		{"maven-properties-and-management", "pom.xml", `<project><properties><base>2.9.8</base><jackson.version>${base}</jackson.version><cycle>${cycle}</cycle><major>1</major></properties>
<dependencyManagement><dependencies>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-dependencies</artifactId><version>2.0.0</version><type>pom</type><scope>import</scope></dependency>
<dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.26</version></dependency>
</dependencies></dependencyManagement>
<dependencies>
<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency>
<dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency>
<dependency><groupId>org.example</groupId><artifactId>composed</artifactId><version>${major}.2</version></dependency>
<dependency><groupId>org.example</groupId><artifactId>cyclic</artifactId><version>${cycle}</version></dependency>
<dependency><groupId>org.example</groupId><artifactId>unterminated</artifactId><version>${oops</version></dependency>
</dependencies></project>`, parseMaven,
			map[string]string{"org.yaml:snakeyaml": "1.26", "com.fasterxml.jackson.core:jackson-databind": "2.9.8", "org.example:composed": "1.2"}},
		{"csproj-properties-and-overrides", "app.csproj", `<Project><PropertyGroup><NJ>13.0.1</NJ><Chain>$(NJ)</Chain></PropertyGroup><ItemGroup>
<PackageReference Include="Newtonsoft.Json" Version="$(Chain)" />
<PackageReference Include="Serilog" VersionOverride="2.10.0" />
<PackageReference Include="Unknown" Version="$(Missing)" />
<PackageReference Include="Broken" Version="$(Open" />
</ItemGroup></Project>`, parseNuGet,
			map[string]string{"Newtonsoft.Json": "13.0.1", "Serilog": "2.10.0", "Unknown": "$(Missing)", "Broken": "$(Open"}},
		{"pyproject-sections", "pyproject.toml", "[project]\nname = \"demo\"\ndependencies = [\"requests==2.25.0\"]\n\n[dependency-groups]\ntest = [\"pytest==8.0.0\", {include-group = \"lint\"}]\nlint = [\n  {include-group = \"base\"},\n  \"ruff==0.1.0\",\n]\n\n[tool.uv]\nindex-url = \"https://example.invalid\"\ndev-dependencies = [\"black==23.1.0\"]\n\n[tool.pdm.dev-dependencies]\ndocs = [\"mkdocs==1.4.0\"]\n\n[tool.poetry.dependencies.jinja2]\nversion = \"2.10\"\noptional = true\n\n[tool.poetry.group.dev.dependencies.\"flask\"]\nversion = \"1.0\"\n", parsePyProjectToml,
			map[string]string{"requests": "2.25.0", "pytest": "8.0.0", "ruff": "0.1.0", "black": "23.1.0", "mkdocs": "1.4.0", "jinja2": "2.10", "flask": "1.0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgs, err := tc.parse(writeFixture(t, t.TempDir(), tc.file, tc.body))
			if got := pkgVersions(pkgs); err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v (%v), want %v", got, err, tc.want)
			}
		})
	}
}

func TestLockfilesTakePrecedencePerEcosystem(t *testing.T) {
	in := []string{"Pipfile", "Pipfile.lock", "Gemfile", "Gemfile.lock", "pubspec.yaml", "pubspec.lock", "mix.exs", "mix.lock",
		"app.csproj", "packages.lock.json", "conan.lock", "conanfile.txt", "vcpkg.json", "CMakeLists.txt", "go.mod", "go.sum",
		"package.json", "requirements-dev.txt", "Cargo.toml"}
	var paths []string
	for _, name := range in {
		paths = append(paths, filepath.Join("dir", name))
	}
	var got []string
	for _, p := range filterDirManifests(paths) {
		got = append(got, filepath.Base(p))
	}
	want := []string{"Pipfile.lock", "Gemfile.lock", "pubspec.lock", "mix.lock", "packages.lock.json", "conan.lock", "vcpkg.json", "CMakeLists.txt", "go.mod",
		"package.json", "requirements-dev.txt", "Cargo.toml"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := filterDirManifests([]string{"go.sum"}); len(got) != 1 {
		t.Fatalf("go.sum without go.mod dropped: %v", got)
	}
}
