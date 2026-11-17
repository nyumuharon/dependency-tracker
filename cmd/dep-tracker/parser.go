package main

import (
	"github.com/nyumuharon/dependency-tracker/internal/parser"
)

type DiscoveryError = parser.DiscoveryError

func ParsePath(targetPath string) ([]Package, error) {
	return parser.ParsePath(targetPath)
}

func DiscoverDependencies(root string) ([]Package, []string, error) {
	return parser.DiscoverDependencies(root)
}

func ParseManifest(path string) ([]Package, error) {
	return parser.ParseManifest(path)
}

func IsManifestFile(fileName string) bool {
	return parser.IsManifestFile(fileName)
}

func disableMavenSleep() {
	parser.DisableMavenSleepForTesting()
}
