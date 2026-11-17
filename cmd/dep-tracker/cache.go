package main

import (
	"github.com/nyumuharon/dependency-tracker/internal/cache"
)

var platformCacheDir = cache.PlatformCacheDir

func cacheFile(name string) string {
	old := cache.PlatformCacheDir
	cache.PlatformCacheDir = platformCacheDir
	defer func() { cache.PlatformCacheDir = old }()
	return cache.File(name)
}

func writeCacheFile(path string, data []byte) {
	cache.WriteFile(path, data)
}
