package main

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestSourceImportFilteringAndAliases(t *testing.T) {
	locals := map[string]bool{"local": true, "local.example": true}
	cases := []struct {
		name, content string
		read          func(string) []string
		want          []string
	}{
		{"python", "# comment\nimport os\nimport local\nimport _private\nfrom google.genai import Client\nimport yaml\nimport external\n", func(p string) []string { return extractPythonImports(p, locals) }, []string{"google-genai", "PyYAML", "external"}},
		{"javascript", "const a=require('fs');const b=require('./local');const c=require('node:fs'); const d=require('https://x'); const e=require('/local');const f=require('@invalid');import p from '@scope/pkg/sub';import q from 'external/sub';", extractJSImports, []string{"@scope/pkg", "external"}},
		{"go", "// comment\npackage main\nimport \"golang.org/x/crypto/ssh\"\nimport \"gopkg.in/yaml.v3\"\nimport \"gopkg.in/user/pkg.v2/sub\"\nimport \"example.net/project\"\nimport \"example.net/project/module/sub\"\nimport \"local.example/pkg\"\nimport \"fmt\"\n", func(p string) []string { return extractGoImports(p, locals) }, []string{"golang.org/x/crypto", "gopkg.in/yaml.v3", "gopkg.in/user/pkg.v2", "example.net/project", "example.net/project/module"}},
		{"rust", "// comment\nuse std::io;\nuse local::Thing;\nextern crate serde;\n", func(p string) []string { return extractRustImports(p, locals) }, []string{"serde"}},
		{"cpp", "//comment\n#include <vector>\n#include <sys/types.h>\n#include <local/header>\n#include <zlib.h>\n#include <fmt/core.h>\n#include <custom/header>\n", func(p string) []string { return extractCPPIncludes(p, locals) }, []string{"zlib", "fmt", "custom"}},
		{"jvm", "//comment\nimport java.util.List;\nimport org.slf4j.Logger;\nimport example.vendor.library.Widget;\nimport short.Name;\n", extractJVMImports, []string{"org.slf4j:slf4j-api", "example.vendor.library:Widget"}},
		{"dotnet", "//comment\nusing System;\nusing local.Thing;\nusing Microsoft.Extensions.Logging;\nusing CustomLibrary;\n", func(p string) []string { return extractDotNetUsings(p, locals) }, []string{"Microsoft.Extensions", "CustomLibrary"}},
		{"php", "<?php\nuse App\\Model;\nuse Tests\\Fixture;\nuse Local\\Thing;\nuse Monolog\\Logger;\n", func(p string) []string { return extractPHPUses(p, locals) }, []string{"monolog/logger"}},
		{"ruby", "#comment\nrequire './local'\nrequire '/local'\nrequire 'json'\nrequire 'local'\nrequire 'sinatra/base'\n", func(p string) []string { return extractRubyRequires(p, locals) }, []string{"sinatra"}},
		{"dart", "//comment\nimport 'dart:io';\nimport 'package:flutter/widgets.dart';\nimport 'package:local/local.dart';\nimport 'package:http/http.dart';\n", func(p string) []string { return extractDartImports(p, locals) }, []string{"http"}},
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
