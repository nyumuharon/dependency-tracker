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

func parseSemver(v string) (int, int, int) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	var major, minor, patch int
	if len(parts) >= 1 {
		fmt.Sscanf(parts[0], "%d", &major)
	}
	if len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &minor)
	}
	if len(parts) >= 3 {
		fmt.Sscanf(parts[2], "%d", &patch)
	}
	return major, minor, patch
}

func isNewer(latest, current string) bool {
	lMaj, lMin, lPatch := parseSemver(latest)
	cMaj, cMin, cPatch := parseSemver(current)
	if lMaj != cMaj {
		return lMaj > cMaj
	}
	if lMin != cMin {
		return lMin > cMin
	}
	return lPatch > cPatch
}

func runUpdate() error {
	fmt.Printf("Checking for updates (current version: v%s)...\n", appVersion)

	apiClient := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/nyumuharon/dependency-tracker/releases/latest", nil)
	if err != nil {
		return fmt.Errorf("failed to create update request: %w", err)
	}
	req.Header.Set("User-Agent", "dep-tracker-updater")

	resp, err := apiClient.Do(req)
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

	if !isNewer(latestTag, appVersion) {
		fmt.Printf("✓ dep-tracker is already up to date (v%s).\n", appVersion)
		return nil
	}

	fmt.Printf("Found newer version: %s (installed: v%s)\n", latestTag, appVersion)

	// Determine binary name for current platform
	goos := runtime.GOOS
	goarch := runtime.GOARCH

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

	releaseURL := fmt.Sprintf("https://github.com/nyumuharon/dependency-tracker/releases/download/%s", latestTag)
	fmt.Printf("Downloading %s from %s...\n", binaryName, latestTag)

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find current executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}
	downloadClient := &http.Client{Timeout: 10 * time.Minute}
	tmpPath, err := downloadVerifiedUpdate(downloadClient, releaseURL, binaryName, filepath.Dir(exePath))
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	// Replace the current executable
	if goos == "windows" {
		oldPath := exePath + ".old"
		_ = os.Remove(oldPath) // Remove any leftover previous backup

		if err := os.Rename(exePath, oldPath); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("unable to replace executable: %w", err)
		}

		if err := os.Rename(tmpPath, exePath); err != nil {
			_ = os.Rename(oldPath, exePath) // Rollback if new copy failed
			os.Remove(tmpPath)
			return fmt.Errorf("unable to install new executable: %w", err)
		}

		_ = os.Remove(oldPath) // Clean up old file if allowed
	} else {
		// Linux & macOS atomic swap
		if err := os.Chmod(tmpPath, 0755); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("failed to mark binary as executable: %w", err)
		}
		if err := os.Rename(tmpPath, exePath); err != nil {
			os.Remove(tmpPath)
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
