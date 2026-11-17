package updater

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
	"syscall"
	"time"

	"github.com/nyumuharon/dependency-tracker/internal/version"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"`
}

// Options keeps platform and filesystem boundaries explicit so failure
// handling can be tested without replacing the running test executable.
type Options struct {
	ApiClient, DownloadClient           *http.Client
	ApiURL, ReleaseBase, Platform, Arch string
	// Version selects a specific release ("1.0.8"), older or newer; empty
	// means the latest release, installed only when it is newer.
	Version    string
	AppVersion string
	Executable func() (string, error)
	Resolve    func(string) (string, error)
	Fs         UpdateFS
}

type UpdateFS struct {
	Rename func(string, string) error
	Remove func(string) error
	Chmod  func(string, os.FileMode) error
}

func DefaultUpdater(appVersion string) Options {
	return Options{
		ApiClient: &http.Client{Timeout: 15 * time.Second}, DownloadClient: &http.Client{Timeout: 10 * time.Minute},
		ApiURL:      "https://api.github.com/repos/nyumuharon/dependency-tracker/releases/latest",
		ReleaseBase: "https://github.com/nyumuharon/dependency-tracker/releases/download",
		Platform:    runtime.GOOS, Arch: runtime.GOARCH, Executable: os.Executable, Resolve: filepath.EvalSymlinks,
		Fs:         UpdateFS{Rename: os.Rename, Remove: os.Remove, Chmod: os.Chmod},
		AppVersion: appVersion,
	}
}

func RunUpdate(appVersion, targetVersion string) error {
	opts := DefaultUpdater(appVersion)
	opts.Version = targetVersion
	return RunUpdateWith(opts)
}

func RunUpdateWith(opts Options) error {
	target := strings.TrimPrefix(strings.TrimSpace(opts.Version), "v")
	apiURL := opts.ApiURL
	if target != "" {
		if _, valid := version.CompareVersions(target, opts.AppVersion, "Go"); !valid {
			return fmt.Errorf("invalid version %q (expected a release number such as 1.0.8)", opts.Version)
		}
		apiURL = strings.TrimSuffix(apiURL, "/latest") + "/tags/v" + target
		fmt.Printf("Looking up release v%s (current version: v%s)...\n", target, opts.AppVersion)
	} else {
		fmt.Printf("Checking for updates (current version: v%s)...\n", opts.AppVersion)
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create update request: %w", err)
	}
	req.Header.Set("User-Agent", "dep-tracker-updater")

	resp, err := opts.ApiClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to reach GitHub release API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound && target != "" {
		return fmt.Errorf("release v%s does not exist; see https://github.com/nyumuharon/dependency-tracker/releases", target)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub release check returned status %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return fmt.Errorf("failed to decode release information: %w", err)
	}

	latestTag := strings.TrimSpace(rel.TagName)

	comparison, valid := version.CompareVersions(latestTag, opts.AppVersion, "Go")
	if !valid {
		return fmt.Errorf("invalid release version %q", latestTag)
	}
	switch {
	case comparison == 0 && target != "":
		fmt.Printf("✓ dep-tracker v%s is already installed.\n", opts.AppVersion)
		return nil
	case comparison <= 0 && target == "":
		fmt.Printf("✓ dep-tracker is already up to date (v%s).\n", opts.AppVersion)
		return nil
	case comparison < 0:
		fmt.Printf("Downgrading to %s (installed: v%s)\n", latestTag, opts.AppVersion)
	default:
		fmt.Printf("Found newer version: %s (installed: v%s)\n", latestTag, opts.AppVersion)
	}

	// Determine binary name for current platform
	goos := opts.Platform
	goarch := opts.Arch

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

	releaseURL := opts.ReleaseBase + "/" + latestTag
	fmt.Printf("Downloading %s from %s...\n", binaryName, latestTag)

	exePath, err := opts.Executable()
	if err != nil {
		return fmt.Errorf("cannot find current executable path: %w", err)
	}
	exePath, err = opts.Resolve(exePath)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}
	tmpPath, err := DownloadVerifiedUpdate(opts.DownloadClient, releaseURL, binaryName, filepath.Dir(exePath))
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}
	defer func() {
		_ = opts.Fs.Remove(tmpPath)
	}()

	// Windows locks the running .exe file; move it out of the way before replacing
	if goos == "windows" {
		oldExePath := exePath + ".old"
		_ = opts.Fs.Remove(oldExePath) // Clean up any previous failed update residue
		if err := opts.Fs.Rename(exePath, oldExePath); err != nil {
			return fmt.Errorf("failed to move current executable aside: %w", err)
		}
		if err := opts.Fs.Rename(tmpPath, exePath); err != nil {
			// Try to restore original executable if update installation fails
			_ = opts.Fs.Rename(oldExePath, exePath)
			return fmt.Errorf("failed to install new executable (rolled back): %w", err)
		}
		_ = opts.Fs.Remove(oldExePath) // Best effort, Windows may still keep it locked until exit
	} else {
		// Unix: make executable before replacing
		if err := opts.Fs.Chmod(tmpPath, 0755); err != nil {
			return fmt.Errorf("failed to set executable permissions: %w", err)
		}
		if err := opts.Fs.Rename(tmpPath, exePath); err != nil {
			var pathErr *os.PathError
			if (errorsAsPathError(err, &pathErr) && pathErr.Err == syscall.EACCES) || os.IsPermission(err) {
				return fmt.Errorf("permission denied updating %s (try running: sudo dep-tracker update)", exePath)
			}
			return fmt.Errorf("failed to replace executable: %w", err)
		}
	}

	fmt.Printf("\n============================================================\n")
	fmt.Printf(" ✓ dep-tracker updated successfully to %s!\n", latestTag)
	fmt.Printf(" Location: %s\n", exePath)
	fmt.Printf("============================================================\n")
	return nil
}

func errorsAsPathError(err error, target **os.PathError) bool {
	if pe, ok := err.(*os.PathError); ok {
		*target = pe
		return true
	}
	return false
}

// ReleaseChecksum requires one well-formed checksum for the exact asset name.
func ReleaseChecksum(manifest, asset string) (string, error) {
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

type UpdateTempFile interface {
	io.WriteCloser
	Name() string
}
type UpdateFileCreator func(string, string) (UpdateTempFile, error)

func DownloadVerifiedUpdate(client *http.Client, releaseURL, binaryName, destinationDir string) (string, error) {
	return DownloadVerifiedUpdateTo(client, releaseURL, binaryName, destinationDir, func(dir, pattern string) (UpdateTempFile, error) { return os.CreateTemp(dir, pattern) })
}

func DownloadVerifiedUpdateTo(client *http.Client, releaseURL, binaryName, destinationDir string, create UpdateFileCreator) (path string, err error) {
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
	expectedHash, err := ReleaseChecksum(string(checksums), binaryName)
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
	tmpFile, err := create(destinationDir, ".dep-tracker-update-*.tmp")
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
