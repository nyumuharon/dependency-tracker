package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstalledReadersRejectMissingOrMalformedInputs(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	checks := []struct {
		name string
		call func() error
	}{
		{"python-walk", func() error { _, err := inspectPythonVenv(missing, nil); return err }},
		{"python-file", func() error { _, _, err := parsePythonMetadataFile(missing); return err }},
		{"dotnet-file", func() error { _, err := inspectDotNetAssets(missing); return err }},
		{"vcpkg-file", func() error { _, err := inspectVcpkgStatus(missing); return err }},
		{"dart-file", func() error { _, err := inspectDartPackageConfig(missing); return err }},
		{"node-directory", func() error { _, err := inspectNodeModules(missing); return err }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("missing required input accepted")
			}
		})
	}
	for _, tc := range []struct {
		name, body string
		read       func(string) ([]Package, error)
	}{
		{"composer-array", "[invalid", inspectComposerInstalled}, {"composer-shape", "null", inspectComposerInstalled},
		{"composer-platform", `{"packages":[{"name":"php","version":"8.3"},{"name":"broken"}]}`, inspectComposerInstalled},
		{"dotnet-json", "invalid", inspectDotNetAssets}, {"dotnet-shape", "{}", inspectDotNetAssets},
		{"dart-json", "invalid", inspectDartPackageConfig}, {"dart-shape", "{}", inspectDartPackageConfig},
		{"dart-uri", `{"packages":[{"name":"http","rootUri":"file://%invalid"}]}`, inspectDartPackageConfig},
		{"vcpkg-line", "invalid status", inspectVcpkgStatus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFixture(t, t.TempDir(), "metadata", tc.body)
			if _, err := tc.read(path); err == nil {
				t.Fatal("malformed installed metadata accepted")
			}
		})
	}
	for _, read := range []func(string) ([]Package, error){inspectComposerInstalled, inspectGoVendorModules} {
		if _, err := read(root); err == nil {
			t.Fatal("directory accepted as metadata file")
		}
	}
	for _, body := range []string{"null", "{invalid"} {
		path := writeFixture(t, t.TempDir(), "direct_url.json", body)
		if _, err := isEditableInstall(path); err == nil {
			t.Fatal("invalid editable metadata accepted")
		}
	}
	path := writeFixture(t, t.TempDir(), "direct_url.json", `{"dir_info":{"editable":true}}`)
	if editable, err := isEditableInstall(path); err != nil || !editable {
		t.Fatalf("%v %v", editable, err)
	}
	var wrapped *os.PathError
	issue := &os.PathError{Op: "read", Path: "fixture", Err: os.ErrPermission}
	if !errors.As(&DiscoveryError{Issues: []error{issue}}, &wrapped) {
		t.Fatal("discovery error lost its cause")
	}
}

func TestInstalledReaderBoundaryRecords(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".venv/include/ignored.dist-info/METADATA", "invalid")
	writeFixture(t, root, ".venv/lib/python/site-packages/editable.dist-info/METADATA", "Name: local\nVersion: 1.0.0\n\n")
	writeFixture(t, root, ".venv/lib/python/site-packages/editable.dist-info/direct_url.json", `{"dir_info":{"editable":true}}`)
	writeFixture(t, root, ".venv/lib/python/site-packages/local.dist-info/METADATA", "Name: local\nVersion: 1.0.0\n\n")
	writeFixture(t, root, ".venv/lib/python/site-packages/pip.dist-info/METADATA", "Name: pip\nVersion: 1.0.0\n\n")
	pkgs, err := inspectPythonVenv(filepath.Join(root, ".venv"), map[string]bool{"local": true})
	if err != nil || len(pkgs) != 0 {
		t.Fatalf("local/bootstrap packages included: %+v %v", pkgs, err)
	}
	status := writeFixture(t, root, "status", "Package: zlib\nFeature: tools\nVersion: 1.3.1\nStatus: install ok installed\n\nPackage: curl\nVersion: 1.0.0\nStatus: purge ok not-installed\n")
	if pkgs, err := inspectVcpkgStatus(status); err != nil || len(pkgs) != 0 {
		t.Fatalf("uninstalled/features included: %+v %v", pkgs, err)
	}
	config := writeFixture(t, root, "package_config.json", `{"packages":[{"name":"flutter","rootUri":"../sdk"},{"name":"local","rootUri":"../local"},{"name":"external","rootUri":"file:///cache/unknown-layout"}]}`)
	if pkgs, err := inspectDartPackageConfig(config); err != nil || len(pkgs) != 1 || pkgs[0].Version != "latest" {
		t.Fatalf("unknown version invented: %+v %v", pkgs, err)
	}
	modules := writeFixture(t, root, "modules.txt", "## explicit; go 1.22\n# example.com/local => ../local\n# example.com/dep v1.0.0\nexample.com/dep/pkg\n")
	if pkgs, err := inspectGoVendorModules(modules); err != nil || len(pkgs) != 1 {
		t.Fatalf("%+v %v", pkgs, err)
	}
	for _, body := range []string{"orphan/package\n", "# incomplete\n"} {
		path := writeFixture(t, t.TempDir(), "modules.txt", body)
		if _, err := inspectGoVendorModules(path); err == nil {
			t.Fatal("invalid vendor header accepted")
		}
	}
}

func TestNodeMetadataShapesAndScope(t *testing.T) {
	for _, body := range []string{"invalid", `{"packages":{"node_modules/a":{"version":12}}}`} {
		root := t.TempDir()
		writeFixture(t, root, ".package-lock.json", body)
		if _, err := inspectNodeModules(root); err == nil {
			t.Fatal("invalid hidden lock accepted")
		}
	}
	root := t.TempDir()
	writeFixture(t, root, ".package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`)
	if pkgs, err := inspectNodeModules(root); err != nil || len(pkgs) != 1 {
		t.Fatalf("hidden lock not read: %+v %v", pkgs, err)
	}
	root = t.TempDir()
	writeFixture(t, root, ".package-lock.json", `{"lockfileVersion":3,"packages":{}}`)
	writeFixture(t, root, "not-a-directory", "ignored")
	writeFixture(t, root, "@scope/not-a-directory", "ignored")
	writeFixture(t, root, "@scope/pkg/package.json", `{"name":"@scope/pkg","version":"1.0.0"}`)
	if pkgs, err := inspectNodeModules(root); err != nil || len(pkgs) != 1 {
		t.Fatalf("scoped packages lost: %+v %v", pkgs, err)
	}
	for _, body := range []string{`{"name":"a"}`, ""} {
		root := t.TempDir()
		writeFixture(t, root, "a/package.json", body)
		if _, err := inspectNodeModules(root); err == nil {
			t.Fatal("invalid installed package accepted")
		}
	}
	root = t.TempDir()
	writeFixture(t, root, "a/package.json", `{"name":"a","version":"1.0.0"}`)
	writeFixture(t, root, "a/node_modules", "not a directory")
	if _, err := inspectNodeModules(root); err == nil {
		t.Fatal("invalid nested environment accepted")
	}
}

func TestMetadataScannerFailures(t *testing.T) {
	root := t.TempDir()
	huge := strings.Repeat("x", 4*1024*1024+1)
	for _, tc := range []struct {
		name string
		read func(string) error
	}{
		{"python", func(p string) error { _, _, err := parsePythonMetadataFile(p); return err }},
		{"go", func(p string) error { _, err := inspectGoVendorModules(p); return err }},
		{"vcpkg", func(p string) error { _, err := inspectVcpkgStatus(p); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFixture(t, root, tc.name, huge)
			if err := tc.read(path); err == nil {
				t.Fatal("truncated metadata accepted")
			}
		})
	}
}

func TestOptionalBrokenSymlinkIsAnError(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "broken")
	if err := os.Symlink(filepath.Join(root, "missing"), path); err != nil {
		t.Skip(err)
	}
	if _, _, err := optionalInstalledFile(path); err == nil {
		t.Fatal("broken optional metadata link was treated as absent")
	}
}

func TestEnvironmentDirectoryPermissionErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	root := t.TempDir()
	unreadable := filepath.Join(root, "bundle")
	if err := os.Mkdir(unreadable, 0111); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(unreadable, 0700)
	if _, err := os.ReadDir(unreadable); err == nil {
		t.Skip("account bypasses permissions")
	}
	if _, err := inspectRubyVendorBundle(root); err == nil {
		t.Fatal("unreadable gem environment ignored")
	}
	if _, err := inspectPythonVenv(unreadable, nil); err == nil {
		t.Fatal("unreadable Python environment ignored")
	}
	if _, err := inspectNodeModules(unreadable); err == nil {
		t.Fatal("unreadable Node environment ignored")
	}
}

func TestRemainingInstalledPermissionAndTailErrors(t *testing.T) {
	root := t.TempDir()
	status := writeFixture(t, root, "status", "Package: broken\nStatus: install ok installed")
	if _, err := inspectVcpkgStatus(status); err == nil {
		t.Fatal("invalid final status record accepted")
	}
	root = t.TempDir()
	writeFixture(t, root, "@scope/broken/readme", "not package metadata")
	if _, err := inspectNodeModules(root); err == nil {
		t.Fatal("scoped package without metadata accepted")
	}
	root = t.TempDir()
	writeFixture(t, root, "bundle/README", "unrelated")
	if pkgs, err := inspectRubyVendorBundle(root); err != nil || len(pkgs) != 0 {
		t.Fatalf("unrelated files included: %+v %v", pkgs, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	for _, kind := range []string{"ruby-stat", "ruby-read", "scope-read"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			var protected string
			switch kind {
			case "ruby-stat":
				protected = filepath.Join(root, "vendor")
				writeFixture(t, protected, "bundle/README", "fixture")
			case "ruby-read":
				protected = writeFixture(t, root, "bundle/specifications/rack-3.1.7.gemspec", "fixture")
			case "scope-read":
				protected = filepath.Join(root, "@scope")
				writeFixture(t, protected, "pkg/package.json", `{"name":"@scope/pkg","version":"1.0.0"}`)
			}
			if err := os.Chmod(protected, 0); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(protected, 0700)
			if kind == "ruby-read" {
				if _, err := os.ReadFile(protected); err == nil {
					t.Skip("account bypasses permissions")
				}
			}
			var err error
			switch kind {
			case "ruby-stat":
				_, err = inspectRubyVendorBundle(protected)
			case "ruby-read":
				_, err = inspectRubyVendorBundle(root)
			case "scope-read":
				_, err = inspectNodeModules(root)
			}
			if err == nil {
				t.Fatal("unreadable installed input accepted")
			}
		})
	}
}
