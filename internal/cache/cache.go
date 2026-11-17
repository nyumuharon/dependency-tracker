package cache

import (
	"os"
	"path/filepath"
)

// PlatformCacheDir provides hook for platform cache path override during tests.
var PlatformCacheDir = os.UserCacheDir

// File returns the absolute path to a named cache file in DEP_TRACKER_CACHE_DIR
// or the platform user cache directory.
func File(name string) string {
	dir := os.Getenv("DEP_TRACKER_CACHE_DIR")
	if dir == "" {
		base, err := PlatformCacheDir()
		if err != nil {
			base = os.TempDir()
		}
		dir = filepath.Join(base, "dependency_risk_tracker")
	}
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, name)
}

// WriteFile replaces a cache file atomically: the data is written to a
// temporary file in the same directory and renamed over the old file, so a
// concurrent run never reads a half-written cache. Cache writes are best
// effort, so failures are ignored.
func WriteFile(path string, data []byte) {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return
	}
	_, writeErr := tmp.Write(data)
	closeErr := tmp.Close()
	if writeErr != nil || closeErr != nil || os.Rename(tmp.Name(), path) != nil {
		_ = os.Remove(tmp.Name())
	}
}
