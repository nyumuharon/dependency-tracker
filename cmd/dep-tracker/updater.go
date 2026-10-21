package main

import (
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

func runUpdate() error {
	fmt.Printf("Checking for updates (current version: v%s)...\n", appVersion)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/nyumuharon/dependency-tracker/releases/latest", nil)
	if err != nil {
		return fmt.Errorf("failed to create update request: %w", err)
	}
	req.Header.Set("User-Agent", "dep-tracker-updater")

	resp, err := client.Do(req)
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
	cleanLatest := strings.TrimPrefix(latestTag, "v")
	cleanCurrent := strings.TrimPrefix(appVersion, "v")

	if cleanLatest == cleanCurrent || latestTag == "" {
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

	downloadURL := fmt.Sprintf("https://github.com/nyumuharon/dependency-tracker/releases/download/%s/%s", latestTag, binaryName)
	fmt.Printf("Downloading %s from %s...\n", binaryName, latestTag)

	binResp, err := client.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer binResp.Body.Close()

	if binResp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with HTTP %d from %s", binResp.StatusCode, downloadURL)
	}

	// Determine currently running executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find current executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}

	exeDir := filepath.Dir(exePath)
	tmpPath := filepath.Join(exeDir, fmt.Sprintf(".dep-tracker-update-%d.tmp", time.Now().UnixNano()))

	// Save downloaded file to temp path
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		if os.IsPermission(err) {
			if goos == "windows" {
				return fmt.Errorf("permission denied writing to %s (try running terminal as Administrator)", exeDir)
			}
			return fmt.Errorf("permission denied writing to %s (try running: sudo dep-tracker update)", exeDir)
		}
		return fmt.Errorf("failed to create temporary file: %w", err)
	}

	_, copyErr := io.Copy(tmpFile, binResp.Body)
	tmpFile.Close()
	if copyErr != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("download stream interrupted: %w", copyErr)
	}

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
