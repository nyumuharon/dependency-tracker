package cache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCacheFileAndWriteFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DEP_TRACKER_CACHE_DIR", dir)

	p := File("test.json")
	if filepath.Dir(p) != dir {
		t.Fatalf("unexpected cache file path: %s", p)
	}

	data := []byte(`{"hello":"world"}`)
	WriteFile(p, data)
	got, err := os.ReadFile(p)
	if err != nil || string(got) != string(data) {
		t.Fatalf("read cache file: %v, got %s", err, string(got))
	}

	// Write failures: missing directory and blocked directory
	WriteFile(filepath.Join(dir, "missing", "test.json"), []byte("x"))
	blocked := filepath.Join(dir, "blocked_dir")
	if err := os.Mkdir(blocked, 0755); err != nil {
		t.Fatal(err)
	}
	WriteFile(blocked, []byte("x"))
}

func TestCacheFilePlatformFallback(t *testing.T) {
	t.Setenv("DEP_TRACKER_CACHE_DIR", "")

	old := PlatformCacheDir
	defer func() { PlatformCacheDir = old }()

	// Error path: fallback to TempDir
	PlatformCacheDir = func() (string, error) {
		return "", errors.New("no cache dir")
	}
	p := File("fallback.json")
	if !filepath.IsAbs(p) {
		t.Fatalf("expected absolute path, got %s", p)
	}

	// Normal path
	tmp := t.TempDir()
	PlatformCacheDir = func() (string, error) {
		return tmp, nil
	}
	p2 := File("normal.json")
	if filepath.Dir(filepath.Dir(p2)) != tmp {
		t.Fatalf("expected path inside %s, got %s", tmp, p2)
	}
}
