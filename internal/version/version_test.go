package version

import (
	"testing"

	"github.com/nyumuharon/dependency-tracker/internal/model"
)

func TestValidateQueryVersion(t *testing.T) {
	// Valid versions
	for _, v := range []string{"1.0.0", "v2.1", "0.0.1-alpha"} {
		if err := ValidateQueryVersion(model.Package{Name: "pkg", Version: v, VersionSource: "manifest"}); err != nil {
			t.Fatalf("expected valid for %s, got: %v", v, err)
		}
	}

	// Invalid versions
	for _, p := range []model.Package{
		{Name: "p1", Version: "1.0.0", VersionSource: "import"},
		{Name: "p2", Version: "1.0.0", VersionSource: "constraint"},
		{Name: "p3", Version: "1.x.0", VersionSource: "manifest"},
		{Name: "p4", Version: "^1.0", VersionSource: "manifest"},
	} {
		if err := ValidateQueryVersion(p); err == nil {
			t.Fatalf("expected error for %+v", p)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b, eco string
		want      int
		ok        bool
	}{
		// SemVer
		{"1.0.0", "1.0.0", "npm", 0, true},
		{"1.0.0", "2.0.0", "npm", -1, true},
		{"2.0.0", "1.0.0", "npm", 1, true},
		{"1.0.0-alpha", "1.0.0", "npm", -1, true},
		{"1.0.0", "1.0.0-alpha", "npm", 1, true},
		{"1.0.0-alpha.1", "1.0.0-alpha.2", "npm", -1, true},
		{"1.0.0-alpha.2", "1.0.0-alpha.1", "npm", 1, true},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", "npm", -1, true},
		{"1.0.0-alpha.beta", "1.0.0-alpha.1", "npm", 1, true},
		{"1.0.0-alpha", "1.0.0-alpha", "npm", 0, true},
		{"1.0.0-a.b", "1.0.0-a.b.c", "npm", -1, true},
		{"1.0.0-a.b.c", "1.0.0-a.b", "npm", 1, true},
		{"1.0.0-alpha", "1.0.0-beta", "npm", -1, true},
		{"1.0.0-beta", "1.0.0-alpha", "npm", 1, true},
		{"1.0.0+build1", "1.0.0+build2", "npm", 0, true},

		// Non-semver
		{"1.0", "1.0.1", "PyPI", -1, true},
		{"1.0.1", "1.0", "PyPI", 1, true},
		{"1.0", "1.0.0", "PyPI", 0, true},
		{"1.0.0-alpha", "1.0.0", "PyPI", 0, false},
		{"invalid", "1.0.0", "npm", 0, false},
		{"1.0.0", "invalid", "npm", 0, false},
		{"1.0", "2.0", "npm", 0, false}, // semver with len(nums) != 3
		{"1.99999999999999999999999999999999999999999999999999999.0", "1.0.0", "npm", 0, false}, // overflow uint64
		{"1.0.0-alpha.1", "1.0.0-alpha.1.1", "npm", -1, true},
	}

	for _, tc := range cases {
		got, ok := CompareVersions(tc.a, tc.b, tc.eco)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("CompareVersions(%q, %q, %q): got (%d, %v), want (%d, %v)", tc.a, tc.b, tc.eco, got, ok, tc.want, tc.ok)
		}
	}
}

func TestNormalizeExactPin(t *testing.T) {
	for _, tc := range []struct {
		in, eco, want string
	}{
		{"==1.2.3", "PyPI", "1.2.3"},
		{"== 1.2.3", "PyPI", "1.2.3"},
		{"==1.2.*", "PyPI", "==1.2.*"},
		{"=1.2.3", "npm", "1.2.3"},
		{"[1.2.3]", "NuGet", "1.2.3"},
		{"[1.0, 2.0]", "NuGet", "[1.0, 2.0]"},
		{"^1.0.0", "npm", "^1.0.0"},
	} {
		got := NormalizeExactPin(tc.in, tc.eco)
		if got != tc.want {
			t.Fatalf("NormalizeExactPin(%q, %q): got %q, want %q", tc.in, tc.eco, got, tc.want)
		}
	}
}
