package parser

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMalformedInstalledEnvironmentsMakeDiscoveryIncomplete(t *testing.T) {
	for _, tc := range []struct{ name, path, content string }{
		{"python", ".venv/lib/python3.12/site-packages/broken-1.dist-info/METADATA", "Name: broken\n\n"},
		{"python-direct-url", ".venv/lib/python3.12/site-packages/broken-1.dist-info/direct_url.json", "{bad"},
		{"node", "node_modules/broken/package.json", "{bad"},
		{"node-lock-shape", "node_modules/.package-lock.json", "{}"},
		{"dotnet-type", "obj/project.assets.json", `{"libraries":{"example/1.0.0":{}}}`},
		{"composer", "vendor/composer/installed.json", "{bad"},
		{"dotnet", "obj/project.assets.json", "{\"libraries\":{\"invalid\":{\"type\":\"package\"}}}"},
		{"ruby", "vendor/bundle/ruby/3.3.0/specifications/broken.gemspec", "# unreadable version"},
		{"vcpkg", "vcpkg_installed/vcpkg/status", "Package: broken\nStatus: install ok installed\n\n"},
		{"dart", ".dart_tool/package_config.json", `{"packages":[{"name":"broken"}]}`},
		{"go", "vendor/modules.txt", "# example.com/broken bad-version\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "package.json", `{"dependencies":{"safe":"1.0.0"}}`)
			writeFixture(t, root, tc.path, tc.content)
			if tc.name == "python-direct-url" {
				writeFixture(t, root, ".venv/lib/python3.12/site-packages/broken-1.dist-info/METADATA", "Name: broken\nVersion: 1.0\n\n")
			}
			pkgs, _, err := DiscoverDependencies(root)
			var incomplete *DiscoveryError
			if !errors.As(err, &incomplete) {
				t.Fatalf("bad environment was silently ignored: %v", err)
			}
			if !strings.Contains(err.Error(), filepath.Base(tc.path)) {
				t.Fatalf("missing input path: %v", err)
			}
			if len(pkgs) == 0 {
				t.Fatal("readable manifests should be preserved with the error")
			}
		})
	}
}

func TestUnreadableInstalledMetadataIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file mode test")
	}
	root := t.TempDir()
	path := writeFixture(t, root, "node_modules/example/package.json", `{"name":"example","version":"1.0.0"}`)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0600)
	if _, err := os.ReadFile(path); err == nil {
		t.Skip("test account can bypass file permissions")
	}
	if _, _, err := DiscoverDependencies(root); err == nil {
		t.Fatal("unreadable installed package was silently ignored")
	}
}

func TestInstalledMetadataVariantsAndSymlinkCycle(t *testing.T) {
	t.Run("composer-v1-and-v2", func(t *testing.T) {
		for _, body := range []string{`[{"name":"monolog/monolog","version":"v3.7.0"}]`, `{"packages":[{"name":"monolog/monolog","version":"v3.7.0"}]}`} {
			path := writeFixture(t, t.TempDir(), "installed.json", body)
			pkgs, err := inspectComposerInstalled(path)
			if err != nil || len(pkgs) != 1 || pkgs[0].Version != "3.7.0" {
				t.Fatalf("%+v %v", pkgs, err)
			}
		}
	})
	t.Run("ruby", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "bundle/ruby/3.3.0/specifications/rack-3.1.7.gemspec", "# fixture")
		pkgs, err := inspectRubyVendorBundle(root)
		if err != nil || len(pkgs) != 1 || pkgs[0].Name != "rack" {
			t.Fatalf("%+v %v", pkgs, err)
		}
	})
	t.Run("symlink-cycle", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "example/package.json", `{"name":"example","version":"1.0.0"}`)
		nested := filepath.Join(root, "example", "node_modules")
		if err := os.MkdirAll(nested, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "example"), filepath.Join(nested, "cycle")); err != nil {
			t.Skip(err)
		}
		pkgs, err := inspectNodeModules(root)
		if err != nil || len(pkgs) != 1 {
			t.Fatalf("cycle should terminate without losing the package: %+v %v", pkgs, err)
		}
	})
}

func TestParsersRejectUnreadableInputs(t *testing.T) {
	parsers := map[string]func(string) ([]Package, error){
		"npm": parseNPM, "python": parsePyPI, "maven": parseMaven, "nuget": parseNuGet, "go-mod": parseGoMod, "cargo-lock": parseCargoLock, "cargo-toml": parseCargoToml, "composer": parseComposer, "ruby": parseRubyGem, "npm-lock": parseNPMLock, "yarn": parseYarnLock, "pnpm": parsePnpmLock, "pyproject": parsePyProjectToml, "poetry": parsePoetryLock, "pipfile": parsePipfileLock, "composer-lock": parseComposerLock, "go-sum": parseGoSum, "nuget-lock": parseNuGetLock, "conan": parseConanFile, "conan-lock": parseConanLock, "vcpkg": parseVcpkg, "content": parseByContent,
	}
	missing := filepath.Join(t.TempDir(), "missing")
	for name, parse := range parsers {
		t.Run(name, func(t *testing.T) {
			if _, err := parse(missing); err == nil {
				t.Fatal("unreadable manifest must return an error")
			}
		})
	}
}

func TestStructuredParsersRejectMalformedData(t *testing.T) {
	for name, parse := range map[string]func(string) ([]Package, error){"npm": parseNPM, "maven": parseMaven, "nuget": parseNuGet, "composer": parseComposer, "npm-lock": parseNPMLock, "pipfile": parsePipfileLock, "composer-lock": parseComposerLock, "nuget-lock": parseNuGetLock, "conan-lock": parseConanLock, "vcpkg": parseVcpkg} {
		t.Run(name, func(t *testing.T) {
			path := writeFixture(t, t.TempDir(), "invalid", `{ "incomplete":`)
			if _, err := parse(path); err == nil {
				t.Fatal("malformed manifest must return an error")
			}
		})
	}
	if !isNamedDependencyFile("app.vbproj") || !isNamedDependencyFile("Pipfile") {
		t.Fatal("expected .vbproj and Pipfile to be named dependency files")
	}
	if _, err := ParsePath(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for missing ParsePath")
	}
	unavailable := errors.New("working directory unavailable")
	if _, err := inspectNodeModulesWithPath(t.TempDir(), func(string) (string, error) { return "", unavailable }); !errors.Is(err, unavailable) {
		t.Fatalf("directory failure was lost: %v", err)
	}
	conanTxt := writeFixture(t, t.TempDir(), "conanfile.txt", "# comment\n[requires]\nzlib/1.3.1\n")
	if pkgs, err := parseConanFile(conanTxt); err != nil || len(pkgs) != 1 {
		t.Fatalf("unexpected conanfile.txt parse: %+v %v", pkgs, err)
	}
	vcpkgFile := writeFixture(t, t.TempDir(), "vcpkg.json", `{"dependencies":[{"name":"zlib"}]}`)
	if pkgs, err := parseVcpkg(vcpkgFile); err != nil || len(pkgs) != 1 || pkgs[0].Version != "latest" {
		t.Fatalf("unexpected vcpkg.json parse: %+v %v", pkgs, err)
	}
}

func TestIntelligentContentAndSourceDiscovery(t *testing.T) {
	// 1. Maven POM with ${property} interpolation
	pomDir := t.TempDir()
	pomPath := filepath.Join(pomDir, "pom.xml")
	pomXML := `<project>
		<version>1.0.0</version>
		<properties>
			<log4j.version>2.14.1</log4j.version>
		</properties>
		<dependencies>
			<dependency>
				<groupId>org.apache.logging.log4j</groupId>
				<artifactId>log4j-core</artifactId>
				<version>${log4j.version}</version>
			</dependency>
		</dependencies>
	</project>`
	if err := os.WriteFile(pomPath, []byte(pomXML), 0644); err != nil {
		t.Fatalf("write pom: %v", err)
	}
	pomPkgs, err := ParseManifest(pomPath)
	if err != nil || len(pomPkgs) != 1 || pomPkgs[0].Version != "2.14.1" {
		t.Fatalf("expected interpolated Maven version 2.14.1, got %+v (err=%v)", pomPkgs, err)
	}

	// 2. Gradle build.gradle.kts + libs.versions.toml
	gradleDir := t.TempDir()
	gradleKts := filepath.Join(gradleDir, "build.gradle.kts")
	_ = os.WriteFile(gradleKts, []byte(`dependencies { implementation("com.google.guava:guava:32.1.2-jre") }`), 0644)
	gPkgs, err := ParseManifest(gradleKts)
	if err != nil || len(gPkgs) != 1 || gPkgs[0].Name != "com.google.guava:guava" {
		t.Fatalf("expected guava from build.gradle.kts, got %+v (err=%v)", gPkgs, err)
	}

	// 3. Zero-manifest project fallback (source code import scanning across languages)
	srcDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(srcDir, "app.py"), []byte("import os\nimport requests\nfrom bs4 import BeautifulSoup\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "index.js"), []byte("const fs = require('fs');\nimport express from 'express';\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\nimport (\n\t\"fmt\"\n\t\"github.com/gin-gonic/gin/binding\"\n)\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "lib.rs"), []byte("use std::collections::HashMap;\nuse serde::Serialize;\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "main.cpp"), []byte("#include <iostream>\n#include <openssl/ssl.h>\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "App.java"), []byte("import java.util.List;\nimport org.apache.logging.log4j.LogManager;\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "Program.cs"), []byte("using System;\nusing Newtonsoft.Json;\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "index.php"), []byte("<?php\nuse Monolog\\Logger;\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "app.rb"), []byte("require 'json'\nrequire 'sinatra/base'\n"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "main.dart"), []byte("import 'package:flutter/material.dart';\nimport 'package:http/http.dart';\n"), 0644)

	discoveredPkgs, sources, err := DiscoverDependencies(srcDir)
	if err != nil {
		t.Fatalf("DiscoverDependencies failed: %v", err)
	}
	if len(sources) != 10 {
		t.Fatalf("expected 10 source files discovered, got %d", len(sources))
	}
	found := make(map[string]string)
	for _, p := range discoveredPkgs {
		found[p.Name] = p.Ecosystem
	}
	expectedImports := map[string]string{
		"requests":                            "PyPI",
		"beautifulsoup4":                      "PyPI",
		"express":                             "npm",
		"github.com/gin-gonic/gin":            "Go",
		"serde":                               "crates.io",
		"openssl":                             "ConanCenter",
		"org.apache.logging.log4j:log4j-core": "Maven",
		"Newtonsoft.Json":                     "NuGet",
		"monolog/monolog":                     "Packagist",
		"sinatra":                             "RubyGems",
		"http":                                "Pub",
	}
	for name, eco := range expectedImports {
		if found[name] != eco {
			t.Errorf("expected %s (%s) from source imports, got %q", name, eco, found[name])
		}
	}

	// 4. Installed environment artifacts (project.assets.json, vendor/modules.txt, vendor/composer/installed.json, vcpkg/status, .dart_tool/package_config.json)
	envDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(envDir, "obj"), 0755)
	_ = os.WriteFile(filepath.Join(envDir, "obj", "project.assets.json"), []byte(`{
		"libraries": {
			"Newtonsoft.Json/13.0.3": { "type": "package" },
			"MyProject/1.0.0": { "type": "project" }
		}
	}`), 0644)
	_ = os.MkdirAll(filepath.Join(envDir, "vendor", "composer"), 0755)
	_ = os.WriteFile(filepath.Join(envDir, "vendor", "modules.txt"), []byte("# github.com/pkg/errors v0.9.1\n"), 0644)
	_ = os.WriteFile(filepath.Join(envDir, "vendor", "composer", "installed.json"), []byte(`{
		"packages": [{ "name": "monolog/monolog", "version": "v2.9.1" }]
	}`), 0644)
	_ = os.MkdirAll(filepath.Join(envDir, "vcpkg_installed", "vcpkg"), 0755)
	_ = os.WriteFile(filepath.Join(envDir, "vcpkg_installed", "vcpkg", "status"), []byte("Package: zlib\nVersion: 1.3.1\nStatus: install ok installed\n\n"), 0644)
	_ = os.MkdirAll(filepath.Join(envDir, ".dart_tool"), 0755)
	_ = os.WriteFile(filepath.Join(envDir, ".dart_tool", "package_config.json"), []byte(`{
		"configVersion": 2,
		"packages": [{ "name": "dio", "rootUri": "file:///home/user/.pub-cache/hosted/pub.dev/dio-5.4.0" }]
	}`), 0644)

	envPkgs, _, err := DiscoverDependencies(envDir)
	if err != nil {
		t.Fatalf("env DiscoverDependencies failed: %v", err)
	}
	envMap := make(map[string]string)
	for _, p := range envPkgs {
		envMap[p.Name] = p.Version + "@" + p.Ecosystem
	}
	if envMap["Newtonsoft.Json"] != "13.0.3@NuGet" ||
		envMap["github.com/pkg/errors"] != "v0.9.1@Go" ||
		envMap["monolog/monolog"] != "2.9.1@Packagist" ||
		envMap["zlib"] != "1.3.1@ConanCenter" ||
		envMap["dio"] != "5.4.0@Pub" {
		t.Fatalf("unexpected environment introspection results: %+v", envMap)
	}
}
