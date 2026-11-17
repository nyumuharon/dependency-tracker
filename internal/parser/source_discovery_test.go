package parser

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func firstResult(names []string, _ error) []string { return names }

func TestSourceImportFilteringAndAliases(t *testing.T) {
	locals := map[string]bool{"local": true, "local.example": true}
	cases := []struct {
		name, content string
		read          func(string) []string
		want          []string
	}{
		{"python", "# comment\nimport os\nimport local\nimport _private\nfrom google.genai import Client\nimport yaml\nimport external\n", func(p string) []string { return firstResult(extractPythonImports(p, locals)) }, []string{"google-genai", "PyYAML", "external"}},
		{"javascript", "const a=require('fs');const b=require('./local');const c=require('node:fs'); const d=require('https://x'); const e=require('/local');const f=require('@invalid');import p from '@scope/pkg/sub';import q from 'external/sub';", func(p string) []string { return firstResult(extractJSImports(p)) }, []string{"@scope/pkg", "external"}},
		{"go", "// comment\npackage main\nimport \"golang.org/x/crypto/ssh\"\nimport \"gopkg.in/yaml.v3\"\nimport \"gopkg.in/user/pkg.v2/sub\"\nimport \"example.net/project\"\nimport \"google.golang.org/grpc/credentials\"\nimport \"github.com/go-chi/chi/v5/middleware\"\nimport \"github.com/onlyowner\"\nimport \"local.example/pkg\"\nimport \"fmt\"\n", func(p string) []string { return firstResult(extractGoImports(p, locals)) }, []string{"golang.org/x/crypto", "gopkg.in/yaml.v3", "gopkg.in/user/pkg.v2", "example.net/project", "google.golang.org/grpc", "github.com/go-chi/chi/v5", "github.com/onlyowner"}},
		{"rust", "// comment\nuse std::io;\nuse local::Thing;\nextern crate serde;\n", func(p string) []string { return firstResult(extractRustImports(p, locals)) }, []string{"serde"}},
		{"cpp", "//comment\n#include <vector>\n#include <sys/types.h>\n#include <local/header>\n#include <zlib.h>\n#include <fmt/core.h>\n#include <custom/header>\n", func(p string) []string { return firstResult(extractCPPIncludes(p, locals)) }, []string{"zlib", "fmt", "custom"}},
		{"jvm", "//comment\nimport java.util.List;\nimport org.slf4j.Logger;\nimport example.vendor.library.Widget;\nimport short.Name;\n", func(p string) []string { return firstResult(extractJVMImports(p)) }, []string{"org.slf4j:slf4j-api", "example.vendor.library:Widget"}},
		{"dotnet", "//comment\nusing System;\nusing local.Thing;\nusing Microsoft.Extensions.Logging;\nusing CustomLibrary;\n", func(p string) []string { return firstResult(extractDotNetUsings(p, locals)) }, []string{"Microsoft.Extensions", "CustomLibrary"}},
		{"php", "<?php\nuse App\\Model;\nuse Tests\\Fixture;\nuse Local\\Thing;\nuse Monolog\\Logger;\nuse Symfony\\Component\\HttpFoundation\\Request;\nuse Symfony\\Component;\nuse Doctrine\\ORM\\Entity;\n", func(p string) []string { return firstResult(extractPHPUses(p, locals)) }, []string{"monolog/monolog", "symfony/http-foundation", "doctrine/orm"}},
		{"ruby", "#comment\nrequire './local'\nrequire '/local'\nrequire 'json'\nrequire 'local'\nrequire 'sinatra/base'\n", func(p string) []string { return firstResult(extractRubyRequires(p, locals)) }, []string{"sinatra"}},
		{"dart", "//comment\nimport 'dart:io';\nimport 'package:flutter/widgets.dart';\nimport 'package:local/local.dart';\nimport 'package:http/http.dart';\n", func(p string) []string { return firstResult(extractDartImports(p, locals)) }, []string{"http"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			missing := filepath.Join(t.TempDir(), "missing")
			if got := tc.read(missing); len(got) != 0 {
				t.Fatal("unreadable source invented imports")
			}
			path := writeFixture(t, t.TempDir(), "source", tc.content)
			got := tc.read(path)
			sort.Strings(got)
			sort.Strings(tc.want)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestManifestDirectoryAndSingleFileContracts(t *testing.T) {
	root := t.TempDir()
	path := writeFixture(t, root, "package.json", `{"dependencies":{"same":"1.0.0"},"devDependencies":{"same":"1.0.0"}}`)
	for _, target := range []string{root, path} {
		pkgs, err := ParsePath(target)
		if err != nil || len(pkgs) != 1 {
			t.Fatalf("%s: %+v %v", target, pkgs, err)
		}
	}
	if _, err := ParsePath(t.TempDir()); err == nil {
		t.Fatal("an unrecognized empty project must not appear scanned")
	}
	bad := writeFixture(t, t.TempDir(), "package.json", "{bad")
	if _, err := ParsePath(bad); err == nil {
		t.Fatal("malformed direct manifest")
	}
	files, err := FindManifests(root)
	if err != nil || len(files) != 1 {
		t.Fatalf("%v %v", files, err)
	}
	writeFixture(t, root, "node_modules/ignored/package.json", `{}`)
	writeFixture(t, root, ".private/package.json", `{}`)
	files, err = FindManifests(root)
	if err != nil || len(files) != 1 {
		t.Fatalf("ignored build/environment directories were traversed: %v %v", files, err)
	}
}

func TestGenericContentRecognizers(t *testing.T) {
	cases := []struct {
		file string
		body string
		want int
	}{
		{"manifest.json", `{"graph_lock":{"nodes":{"1":{"ref":"openssl/3.3.2"}}}}`, 1},
		{"manifest.json", `{"default":{"requests":{"version":"==2.32.3"}},"develop":{}}`, 1},
		{"manifest.json", `{"packages":[{"name":"monolog/monolog","version":"3.7.0"}],"packages-dev":[]}`, 1},
		{"manifest.json", `{"require":{"monolog/monolog":"^3.0"}}`, 1},
		{"manifest.json", `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`, 1},
		{"manifest.json", `{"pins":[{"identity":"swift-lib","state":{"version":"1.0.0"}}]}`, 1},
		{"manifest.json", `{"libraries":{"Library/1.0.0":{"type":"package"}}}`, 1},
		{"manifest.json", `{"configVersion":2,"packages":[{"name":"http","rootUri":"file:///cache/http-1.0.0"}]}`, 1},
		{"manifest.json", `{"dependencies":[{"name":"zlib","version":"1.3.1"}]}`, 1},
		{"manifest.json", `{"dependencies":{"net8.0":{"Library":{"resolved":"1.0.0"}}}}`, 1},
		{"manifest.json", `{"dependencies":{"a":"1.0.0"}}`, 1},
		{"manifest.json", `{"devDependencies":{"a":"1.0.0"}}`, 1},
		{"manifest.xml", `<project><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0.0</version></dependency></dependencies></project>`, 1},
		{"manifest.props", `<Project><ItemGroup><PackageReference Include="Library" Version="1.0.0"/></ItemGroup></Project>`, 1},
		{"requirements.in", "requests==2.32.3\n", 1},
		{"empty.file", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.file+tc.body[:min(8, len(tc.body))], func(t *testing.T) {
			path := writeFixture(t, t.TempDir(), tc.file, tc.body)
			pkgs, err := parseByContent(path)
			if err != nil || len(pkgs) != tc.want {
				t.Fatalf("%s: got %+v err %v", tc.body, pkgs, err)
			}
		})
	}
	for _, tc := range []struct{ name, body string }{{"unknown.json", `{"unrelated":true}`}, {"unknown.xml", "<root/>"}, {"unknown.cfg", "unrelated = true"}, {"unknown.yaml", "unrelated: true"}} {
		path := writeFixture(t, t.TempDir(), tc.name, tc.body)
		if _, err := parseByContent(path); err == nil {
			t.Fatalf("unrelated content accepted: %s", tc.name)
		}
	}
}

func TestImportCoverageIsPerEcosystem(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	writeFixture(t, root, "web/index.js", "import express from 'express'\n")
	writeFixture(t, root, "tools/fetch.py", "import requests\n")
	writeFixture(t, root, "svc/go.mod", "module example.com/svc\n\ngo 1.22\n")
	writeFixture(t, root, "svc/main.go", "package main\nimport \"github.com/gin-gonic/gin\"\n")
	pkgs, _, err := DiscoverDependencies(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.VersionSource
	}
	want := map[string]string{"left-pad": "manifest", "requests": "import"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v: imports of another ecosystem must not be hidden, imports of a covered one must be", got, want)
	}
}

func TestDependencyFileEcosystems(t *testing.T) {
	cases := map[string]string{
		"package.json": "npm", "yarn.lock": "npm", "pyproject.toml": "PyPI", "Pipfile": "PyPI", "setup.cfg": "PyPI",
		"dev-requirements.txt": "PyPI", "go.mod": "Go", "Cargo.toml": "crates.io", "composer.lock": "Packagist",
		"Gemfile": "RubyGems", "app.gemspec": "RubyGems", "build.gradle.kts": "Maven", "pom.xml": "Maven",
		"packages.config": "NuGet", "App.csproj": "NuGet", "lib.fsproj": "NuGet", "x.vbproj": "NuGet",
		"CMakeLists.txt": "ConanCenter", "vcpkg.json": "ConanCenter", "pubspec.yaml": "Pub", "mix.lock": "Hex",
		"Package.resolved": "SwiftURL", "manifest.json": "",
	}
	for name, want := range cases {
		if got := dependencyFileEcosystem(filepath.Join("dir", name)); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
}

func TestSourceImportReadErrorsAreReported(t *testing.T) {
	for _, read := range []func(string) error{
		func(p string) error { _, err := extractPythonImports(p, nil); return err },
		func(p string) error { _, err := extractJSImports(p); return err },
		func(p string) error { _, err := extractJVMImports(p); return err },
	} {
		if err := read(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("unreadable source file looked clean")
		}
	}
	long := strings.Repeat("x", 100*1024) + "\nimport requests\n"
	path := writeFixture(t, t.TempDir(), "long.py", long)
	if got, err := extractPythonImports(path, map[string]bool{}); err != nil || !reflect.DeepEqual(got, []string{"requests"}) {
		t.Fatalf("a long line hid later imports: %v %v", got, err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	for _, kind := range []string{"file", "dir"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "requirements.txt", "flask==3.0.0\n")
			protected := writeFixture(t, root, "app/main.py", "import requests\n")
			if kind == "dir" {
				protected = filepath.Dir(protected)
			}
			if err := os.Chmod(protected, 0); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(protected, 0700)
			if _, err := os.ReadFile(filepath.Join(root, "app", "main.py")); err == nil {
				t.Skip("account bypasses permissions")
			}
			pkgs, _, err := DiscoverDependencies(root)
			var discoveryErr *DiscoveryError
			if !errors.As(err, &discoveryErr) || len(pkgs) != 1 || pkgs[0].Name != "flask" {
				t.Fatalf("unreadable source must make discovery incomplete and keep readable packages: %+v %v", pkgs, err)
			}
		})
	}
}

func discoveredVersions(t *testing.T, root string) (map[string]string, error) {
	t.Helper()
	pkgs, _, err := DiscoverDependencies(root)
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version + "@" + p.VersionSource
	}
	return got, err
}

func TestDiscoveryDirectoryRules(t *testing.T) {
	root := t.TempDir()
	// build/ next to a manifest is output and skipped; a standalone build/,
	// target/ or env/ folder is a project of its own.
	writeFixture(t, root, "web/package.json", `{"dependencies":{"lodash":"4.17.20"}}`)
	writeFixture(t, root, "web/build/package.json", `{"dependencies":{"left-pad":"1.3.0"}}`)
	writeFixture(t, root, "build/requirements.txt", "flask==3.0.0\n")
	writeFixture(t, root, "target/Cargo.toml", "[dependencies]\nserde = \"=1.0.0\"\n")
	writeFixture(t, root, "env/requirements.txt", "django==4.0.0\n")
	// A virtual environment with any name is inspected, not walked.
	writeFixture(t, root, "svc/myenv/pyvenv.cfg", "home = /usr\n")
	writeFixture(t, root, "svc/myenv/lib/site-packages/requests/__init__.py", "")
	writeFixture(t, root, "svc/myenv/lib/site-packages/requests-2.25.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: requests\nVersion: 2.25.0\n")
	writeFixture(t, root, "svc/myenv/lib/site-packages/requests/package.json", `{"dependencies":{"evil":"1.0.0"}}`)
	writeFixture(t, root, "svc/app.py", "import requests\n")
	got, err := discoveredVersions(t, root)
	want := map[string]string{"lodash": "4.17.20@manifest", "flask": "3.0.0@manifest", "serde": "1.0.0@manifest", "django": "4.0.0@manifest", "requests": "2.25.0@installed"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v (%v), want %v", got, err, want)
	}
	// A scan root is never skipped because of its name.
	named := filepath.Join(t.TempDir(), "build")
	writeFixture(t, named, "requirements.txt", "flask==3.0.0\n")
	if got, err := discoveredVersions(t, named); err != nil || got["flask"] != "3.0.0@manifest" {
		t.Fatalf("root named build skipped: %v %v", got, err)
	}
}

func TestLocalModulesAreScopedToTheirProject(t *testing.T) {
	root := t.TempDir()
	// Folders without __init__.py and unrelated folders do not hide packages.
	writeFixture(t, root, "site/alembic/env.py", "x = 1\n")
	writeFixture(t, root, "site/docker/Dockerfile", "FROM scratch\n")
	writeFixture(t, root, "site/main.py", "import alembic\nimport docker\nimport mypkg\nimport helper\n\"\"\"\nfrom settings import x\n\"\"\"\nimport os, yaml as y\nfrom google.protobuf import message\nimport google.cloud.storage\nimport google.cloud\nimport typing_extensions\nfrom . import sibling\n")
	writeFixture(t, root, "site/helper.py", "")
	writeFixture(t, root, "site/src/mypkg/__init__.py", "")
	// A module named like a package may import that package.
	writeFixture(t, root, "site/proj/__init__.py", "")
	writeFixture(t, root, "site/proj/celery.py", "from celery import Celery\n")
	// Sibling projects do not hide each other's imports.
	writeFixture(t, root, "a/app.py", "import requests\n")
	writeFixture(t, root, "b/requests/__init__.py", "")
	writeFixture(t, root, "b/run.py", "import requests\n")
	// Ruby lib/ and Rust modules remain local.
	writeFixture(t, root, "gem/lib/mylib.rb", "")
	writeFixture(t, root, "gem/app.rb", "require 'mylib'\nrequire 'sinatra'\n")
	got, err := discoveredVersions(t, root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for name := range got {
		names = append(names, name)
	}
	sort.Strings(names)
	want := []string{"PyYAML", "alembic", "celery", "docker", "google-cloud-storage", "protobuf", "requests", "sinatra", "typing_extensions"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("got %v, want %v", names, want)
	}
}

func TestDiscoveryKeepsPartialResults(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "requirements.txt", "flask==3.0.0\n")
	writeFixture(t, root, "fixtures/package.json", "{ broken")
	pkgs, sources, err := DiscoverDependencies(root)
	var discoveryErr *DiscoveryError
	if !errors.As(err, &discoveryErr) || len(pkgs) != 1 || pkgs[0].Name != "flask" || len(sources) != 2 {
		t.Fatalf("malformed manifest must not discard other results: %+v %v %v", pkgs, sources, err)
	}
	if _, err := ParsePath(root); !errors.As(err, &discoveryErr) {
		t.Fatalf("ParsePath lost the discovery error: %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	locked := filepath.Join(root, "locked")
	writeFixture(t, root, "locked/requirements.txt", "django==4.0.0\n")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0700)
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("account bypasses permissions")
	}
	if pkgs, _, err := DiscoverDependencies(root); !errors.As(err, &discoveryErr) || len(pkgs) != 1 {
		t.Fatalf("unreadable directory must not discard other results: %+v %v", pkgs, err)
	}
}

func TestInstalledVersionReplacesDeclaredPin(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "requirements/base.txt", "requests==2.20.0\nflask==3.0.0\n")
	writeFixture(t, root, "requirements.txt", "-r requirements/base.txt\nurllib3==1.26.0\n")
	writeFixture(t, root, ".venv/lib/site-packages/requests-2.31.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n")
	writeFixture(t, root, ".venv/lib/site-packages/urllib3-1.26.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: urllib3\nVersion: 1.26.0\n")
	pkgs, _, err := DiscoverDependencies(root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range pkgs {
		got = append(got, p.Name+"@"+p.Version)
	}
	sort.Strings(got)
	want := []string{"flask@3.0.0", "requests@2.31.0", "urllib3@1.26.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
