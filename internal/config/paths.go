package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	customConfigDir string
	dirMutex        sync.RWMutex
)

// SetCustomConfigDir sets an explicit configuration directory (e.g. from --config flag).
func SetCustomConfigDir(dir string) {
	dirMutex.Lock()
	defer dirMutex.Unlock()
	customConfigDir = dir
}

// GetConfigDir returns the base configuration directory for SSHM.
// Priority:
// 1. Explicitly set via SetCustomConfigDir
// 2. SSHM_CONFIG_DIR environment variable
// 3. Windows: %APPDATA%\sshm (or %USERPROFILE%\.sshm)
// 4. Unix/macOS: ~/.sshm
func GetConfigDir() (string, error) {
	dirMutex.RLock()
	custom := customConfigDir
	dirMutex.RUnlock()

	if custom != "" {
		return custom, nil
	}

	if env := os.Getenv("SSHM_CONFIG_DIR"); env != "" {
		return env, nil
	}

	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			return filepath.Join(appData, "sshm"), nil
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine user home directory: %w", err)
	}

	return filepath.Join(home, ".sshm"), nil
}

// EnsureConfigDir ensures the configuration directory exists with secure permissions (0700).
func EnsureConfigDir() (string, error) {
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create configuration directory %q: %w", dir, err)
	}

	// Double check directory permissions on non-windows platforms
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dir, 0700)
	}

	return dir, nil
}

// GetProfilesPath returns the path to the profiles metadata file.
func GetProfilesPath() (string, error) {
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "profiles.json"), nil
}

// GetVaultPath returns the path to the encrypted credentials vault file.
func GetVaultPath() (string, error) {
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vault.enc"), nil
}

// GetKnownHostsPath returns the default known_hosts path.
func GetKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}
