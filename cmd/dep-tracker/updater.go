package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"`
}

// updaterOptions keeps platform and filesystem boundaries explicit so failure
// handling can be tested without replacing the running test executable.
type updaterOptions struct {
	apiClient, downloadClient           *http.Client
	apiURL, releaseBase, platform, arch string
	executable                          func() (string, error)
	resolve                             func(string) (string, error)
	fs                                  updateFS
}
type updateFS struct {
	rename func(string, string) error
	remove func(string) error
	chmod  func(string, os.FileMode) error
}

func defaultUpdater() updaterOptions {
	return updaterOptions{
		apiClient: &http.Client{Timeout: 15 * time.Second}, downloadClient: &http.Client{Timeout: 10 * time.Minute},
		apiURL:      "https://api.github.com/repos/nyumuharon/dependency-tracker/releases/latest",
		releaseBase: "https://github.com/nyumuharon/dependency-tracker/releases/download",
		platform:    runtime.GOOS, arch: runtime.GOARCH, executable: os.Executable, resolve: filepath.EvalSymlinks,
		fs: updateFS{rename: os.Rename, remove: os.Remove, chmod: os.Chmod},
	}
}
func runUpdate() error { return runUpdateWith(defaultUpdater()) }

func runUpdateWith(opts updaterOptions) error {
	fmt.Printf("Checking for updates (current version: v%s)...\n", appVersion)

	req, err := http.NewRequest("GET", opts.apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create update request: %w", err)
	}
	req.Header.Set("User-Agent", "dep-tracker-updater")

	resp, err := opts.apiClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to reach GitHub release API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub release check returned status %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return fmt.Errorf("failed to decode release information: %w", err)
	}

	latestTag := strings.TrimSpace(rel.TagName)

	comparison, valid := compareVersions(latestTag, appVersion, "Go")
	if !valid {
		return fmt.Errorf("invalid release version %q", latestTag)
	}
	if comparison <= 0 {
		fmt.Printf("✓ dep-tracker is already up to date (v%s).\n", appVersion)
		return nil
	}

	fmt.Printf("Found newer version: %s (installed: v%s)\n", latestTag, appVersion)

	// Determine binary name for current platform
	goos := opts.platform
	goarch := opts.arch

	var binaryName string
	switch goos {
	case "windows":
		binaryName = fmt.Sprintf("dep-tracker-windows-%s.exe", goarch)
	case "darwin":
		binaryName = fmt.Sprintf("dep-tracker-darwin-%s", goarch)
	case "linux":
		binaryName = fmt.Sprintf("dep-tracker-linux-%s", goarch)
	default:
		return fmt.Errorf("self-update is not supported on %s/%s", goos, goarch)
	}

	releaseURL := opts.releaseBase + "/" + latestTag
	fmt.Printf("Downloading %s from %s...\n", binaryName, latestTag)

	exePath, err := opts.executable()
	if err != nil {
		return fmt.Errorf("cannot find current executable path: %w", err)
	}
	exePath, err = opts.resolve(exePath)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}
	tmpPath, err := downloadVerifiedUpdate(opts.downloadClient, releaseURL, binaryName, filepath.Dir(exePath))
	if err != nil {
		return err
	}
	defer opts.fs.remove(tmpPath)

	// Replace the current executable
	if goos == "windows" {
		oldPath := exePath + ".old"
		_ = opts.fs.remove(oldPath) // Remove any leftover previous backup

		if err := opts.fs.rename(exePath, oldPath); err != nil {
			opts.fs.remove(tmpPath)
			return fmt.Errorf("unable to replace executable: %w", err)
		}

		if err := opts.fs.rename(tmpPath, exePath); err != nil {
			_ = opts.fs.rename(oldPath, exePath) // Rollback if new copy failed
			opts.fs.remove(tmpPath)
			return fmt.Errorf("unable to install new executable: %w", err)
		}

		_ = opts.fs.remove(oldPath) // Clean up old file if allowed
	} else {
		// Linux & macOS atomic swap
		if err := opts.fs.chmod(tmpPath, 0755); err != nil {
			opts.fs.remove(tmpPath)
			return fmt.Errorf("failed to mark binary as executable: %w", err)
		}
		if err := opts.fs.rename(tmpPath, exePath); err != nil {
			opts.fs.remove(tmpPath)
			if os.IsPermission(err) {
				return fmt.Errorf("permission denied updating %s (try running: sudo dep-tracker update)", exePath)
			}
			return fmt.Errorf("unable to swap executable: %w", err)
		}
	}

	fmt.Printf("\n============================================================\n")
	fmt.Printf(" ✓ dep-tracker updated successfully to %s!\n", latestTag)
	fmt.Printf(" Location: %s\n", exePath)
	fmt.Printf("============================================================\n")
	return nil
}

// releaseChecksum requires one well-formed checksum for the exact asset name.
func releaseChecksum(manifest, asset string) (string, error) {
	var checksum string
	for _, line := range strings.Split(manifest, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != asset {
			continue
		}
		if checksum != "" {
			return "", fmt.Errorf("duplicate checksum for %s", asset)
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil || len(decoded) != sha256.Size {
			return "", fmt.Errorf("invalid checksum for %s", asset)
		}
		checksum = strings.ToLower(fields[0])
	}
	if checksum == "" {
		return "", fmt.Errorf("missing checksum for %s", asset)
	}
	return checksum, nil
}

// downloadVerifiedUpdate returns a temporary binary only after verifying the
// checksum. It never changes the installed executable and removes failed downloads.
func downloadVerifiedUpdate(client *http.Client, releaseURL, binaryName, destinationDir string) (path string, err error) {
	checksumResp, err := client.Get(releaseURL + "/SHA256SUMS.txt")
	if err != nil {
		return "", fmt.Errorf("download checksums: %w", err)
	}
	defer checksumResp.Body.Close()
	if checksumResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum download returned HTTP %d", checksumResp.StatusCode)
	}
	checksums, err := io.ReadAll(io.LimitReader(checksumResp.Body, 1024*1024))
	if err != nil {
		return "", fmt.Errorf("read checksums: %w", err)
	}
	expectedHash, err := releaseChecksum(string(checksums), binaryName)
	if err != nil {
		return "", err
	}
	binResp, err := client.Get(releaseURL + "/" + binaryName)
	if err != nil {
		return "", fmt.Errorf("download binary: %w", err)
	}
	defer binResp.Body.Close()
	if binResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("binary download returned HTTP %d", binResp.StatusCode)
	}
	tmpFile, err := os.CreateTemp(destinationDir, ".dep-tracker-update-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create update file in %s: %w", destinationDir, err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if err != nil {
			os.Remove(tmpPath)
		}
	}()
	hasher := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(tmpFile, hasher), binResp.Body)
	closeErr := tmpFile.Close()
	if copyErr != nil {
		return "", fmt.Errorf("download interrupted: %w", copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("save update: %w", closeErr)
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expectedHash {
		return "", fmt.Errorf("checksum mismatch for %s; update cancelled", binaryName)
	}
	return tmpPath, nil
}
