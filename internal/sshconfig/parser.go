package sshconfig

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alwin/sshm/pkg/models"
)

// DefaultConfigPath returns the standard OpenSSH configuration path for the current OS.
func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine home directory: %w", err)
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

// ParseSSHConfig reads and parses an OpenSSH config file into a slice of SSHProfile models.
func ParseSSHConfig(path string) ([]*models.SSHProfile, error) {
	if path == "" {
		var err error
		path, err = DefaultConfigPath()
		if err != nil {
			return nil, err
		}
	} else {
		path = models.ExpandHome(path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open SSH config file %q: %w", path, err)
	}
	defer file.Close()

	var profiles []*models.SSHProfile
	var current *models.SSHProfile
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, val := parseConfigLine(line)
		if key == "" {
			continue
		}

		keyLower := strings.ToLower(key)

		if keyLower == "host" {
			// Save current if valid
			if current != nil && isValidHostPattern(current.Name) {
				fillDefaults(current)
				profiles = append(profiles, current)
			}

			// A Host line can specify multiple names; we take the first clean alphanumeric identifier
			hostAliases := strings.Fields(val)
			if len(hostAliases) > 0 && isValidHostPattern(hostAliases[0]) {
				current = models.NewSSHProfile(hostAliases[0], hostAliases[0], 22, "")
			} else {
				current = nil
			}
			continue
		}

		if current == nil {
			continue
		}

		switch keyLower {
		case "hostname":
			current.Host = val
		case "port":
			if p, err := strconv.Atoi(val); err == nil && p > 0 {
				current.Port = p
			}
		case "user":
			current.Username = val
		case "identityfile":
			current.KeyPath = val
			current.AuthMethod = models.AuthMethodKey
		case "proxyjump":
			current.ProxyJump = val
		case "proxycommand":
			current.ProxyCommand = val
		case "forwardagent":
			current.ForwardAgent = strings.ToLower(val) == "yes"
		case "serveraliveinterval":
			if interval, err := strconv.Atoi(val); err == nil {
				current.ServerAliveInterval = interval
			}
		case "serveralivecountmax":
			if maxCount, err := strconv.Atoi(val); err == nil {
				current.ServerAliveCountMax = maxCount
			}
		case "compression":
			current.Compression = strings.ToLower(val) == "yes"
		}
	}

	if current != nil && isValidHostPattern(current.Name) {
		fillDefaults(current)
		profiles = append(profiles, current)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading SSH config: %w", err)
	}

	return profiles, nil
}

func parseConfigLine(line string) (key, val string) {
	// Lines can be separated by spaces or '='
	if idx := strings.Index(line, "="); idx != -1 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}

func isValidHostPattern(name string) bool {
	if name == "" || strings.ContainsAny(name, "*?") {
		return false
	}
	return true
}

func fillDefaults(p *models.SSHProfile) {
	if p.Host == "" {
		p.Host = p.Name
	}
	if p.Port <= 0 {
		p.Port = 22
	}
	if p.Username == "" {
		p.Username = "root"
	}
	if p.KeyPath != "" {
		p.AuthMethod = models.AuthMethodKey
	}
}
