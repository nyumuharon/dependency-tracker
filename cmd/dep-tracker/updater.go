package main

import (
	"net/http"

	"github.com/nyumuharon/dependency-tracker/internal/updater"
)

type updaterOptions = updater.Options
type updateTempFile = updater.UpdateTempFile
type updateFileCreator = updater.UpdateFileCreator

func defaultUpdater() updaterOptions {
	return updater.DefaultUpdater(appVersion)
}

func runUpdate(version string) error {
	return updater.RunUpdate(appVersion, version)
}

func runUpdateWith(opts updaterOptions) error {
	return updater.RunUpdateWith(opts)
}

func releaseChecksum(manifest, asset string) (string, error) {
	return updater.ReleaseChecksum(manifest, asset)
}

func downloadVerifiedUpdate(client *http.Client, releaseURL, binaryName, destinationDir string) (string, error) {
	return updater.DownloadVerifiedUpdate(client, releaseURL, binaryName, destinationDir)
}

func downloadVerifiedUpdateTo(client *http.Client, releaseURL, binaryName, destinationDir string, create updateFileCreator) (string, error) {
	return updater.DownloadVerifiedUpdateTo(client, releaseURL, binaryName, destinationDir, create)
}
