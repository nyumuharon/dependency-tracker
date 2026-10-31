package main

import (
	"os"
	"path/filepath"
)

// DEP_TRACKER_CACHE_DIR provides explicit isolation for CI and offline testing
// on every supported OS; normal installations retain their platform cache path.
var platformCacheDir = os.UserCacheDir

func cacheFile(name string) string {
	dir := os.Getenv("DEP_TRACKER_CACHE_DIR")
	if dir == "" {
		base, err := platformCacheDir()
		if err != nil {
			base = os.TempDir()
		}
		dir = filepath.Join(base, "dependency_risk_tracker")
	}
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, name)
}
