package models

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AuthMethod represents the authentication mechanism for SSH.
type AuthMethod string

const (
	AuthMethodKey      AuthMethod = "key"
	AuthMethodPassword AuthMethod = "password"
	AuthMethodAgent    AuthMethod = "agent"
)

var validProfileNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

// SSHProfile holds the complete non-secret configuration of an SSH connection.
// Secrets such as passwords, private keys, or passphrases MUST NEVER be stored here.
type SSHProfile struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name"`
	Host                  string            `json:"host"`
	Port                  int               `json:"port"`
	Username              string            `json:"username"`
	AuthMethod            AuthMethod        `json:"auth_method"`
	KeyPath               string            `json:"key_path,omitempty"`
	KeyInVault            bool              `json:"key_in_vault,omitempty"`
	ProxyJump             string            `json:"proxy_jump,omitempty"`
	ProxyCommand          string            `json:"proxy_command,omitempty"`
	ForwardAgent          bool              `json:"forward_agent,omitempty"`
	StrictHostKeyChecking string            `json:"strict_host_key_checking,omitempty"` // "ask", "yes", "no", "accept-new"
	KnownHostsFile        string            `json:"known_hosts_file,omitempty"`
	ConnectTimeout        int               `json:"connect_timeout,omitempty"`         // in seconds, 0 = default (15s)
	ServerAliveInterval   int               `json:"server_alive_interval,omitempty"`   // in seconds, 0 = disabled
	ServerAliveCountMax   int               `json:"server_alive_count_max,omitempty"` // default 3
	Compression           bool              `json:"compression,omitempty"`
	IdentityAgent         string            `json:"identity_agent,omitempty"`
	LocalForwards         []string          `json:"local_forwards,omitempty"`  // e.g. ["8080:localhost:80", "127.0.0.1:3000:3000"]
	RemoteForwards        []string          `json:"remote_forwards,omitempty"` // e.g. ["9000:localhost:9000"]
	DynamicForward        string            `json:"dynamic_forward,omitempty"` // e.g. "1080" (SOCKS5)
	AdditionalOptions     map[string]string `json:"additional_options,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// NewSSHProfile creates a profile with safe, standard defaults.
func NewSSHProfile(name, host string, port int, username string) *SSHProfile {
	if port <= 0 {
		port = 22
	}
	now := time.Now().UTC()
	return &SSHProfile{
		ID:                    name,
		Name:                  name,
		Host:                  host,
		Port:                  port,
		Username:              username,
		AuthMethod:            AuthMethodKey,
		StrictHostKeyChecking: "ask",
		ConnectTimeout:        15,
		ServerAliveInterval:   0,
		ServerAliveCountMax:   3,
		LocalForwards:         make([]string, 0),
		RemoteForwards:        make([]string, 0),
		AdditionalOptions:     make(map[string]string),
		CreatedAt:             now,
		UpdatedAt:             now,
	}
}

// Validate checks that all required fields are present and valid.
func (p *SSHProfile) Validate() error {
	trimmedName := strings.TrimSpace(p.Name)
	if trimmedName == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if !validProfileNameRegex.MatchString(trimmedName) {
		return fmt.Errorf("profile name %q contains invalid characters (allowed: alphanumeric, -, _, .)", trimmedName)
	}

	trimmedHost := strings.TrimSpace(p.Host)
	if trimmedHost == "" {
		return fmt.Errorf("host/IP cannot be empty")
	}

	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("port %d is invalid; must be between 1 and 65535", p.Port)
	}

	trimmedUser := strings.TrimSpace(p.Username)
	if trimmedUser == "" {
		return fmt.Errorf("username cannot be empty")
	}

	switch p.AuthMethod {
	case AuthMethodKey:
		if !p.KeyInVault && p.KeyPath != "" {
			expanded := ExpandHome(p.KeyPath)
			if _, err := os.Stat(expanded); err != nil {
				return fmt.Errorf("private key file does not exist at %q: %w", p.KeyPath, err)
			}
		}
	case AuthMethodPassword:
		// Password is valid (stored in vault or prompted)
	case AuthMethodAgent:
		// SSH Agent is valid
	default:
		return fmt.Errorf("invalid authentication method %q (must be 'key', 'password', or 'agent')", p.AuthMethod)
	}

	if p.StrictHostKeyChecking != "" {
		s := strings.ToLower(p.StrictHostKeyChecking)
		if s != "ask" && s != "yes" && s != "no" && s != "accept-new" {
			return fmt.Errorf("invalid strict host key checking value %q (must be 'ask', 'yes', 'no', or 'accept-new')", p.StrictHostKeyChecking)
		}
	}

	for _, lf := range p.LocalForwards {
		if _, err := ParsePortForwardSpec(lf); err != nil {
			return fmt.Errorf("invalid local forward rule %q: %w", lf, err)
		}
	}

	for _, rf := range p.RemoteForwards {
		if _, err := ParsePortForwardSpec(rf); err != nil {
			return fmt.Errorf("invalid remote forward rule %q: %w", rf, err)
		}
	}

	if p.DynamicForward != "" {
		port, err := strconv.Atoi(p.DynamicForward)
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid dynamic forward port %q: must be between 1 and 65535", p.DynamicForward)
		}
	}

	return nil
}

// ForwardRule parsed representation of a port forwarding rule.
type ForwardRule struct {
	BindHost   string
	LocalPort  int
	RemoteHost string
	RemotePort int
}

// ParsePortForwardSpec parses port forwarding specifications like:
// "8080:localhost:80", "127.0.0.1:8080:remote:80", or "8080:80" (defaulting to localhost)
func ParsePortForwardSpec(spec string) (*ForwardRule, error) {
	spec = strings.TrimSpace(spec)
	parts := strings.Split(spec, ":")

	rule := &ForwardRule{
		BindHost:   "127.0.0.1",
		RemoteHost: "127.0.0.1",
	}

	switch len(parts) {
	case 2:
		// format: "local_port:remote_port" (remote_host defaults to 127.0.0.1)
		lPort, err := strconv.Atoi(parts[0])
		if err != nil || lPort <= 0 || lPort > 65535 {
			return nil, fmt.Errorf("invalid local port %q", parts[0])
		}
		rPort, err := strconv.Atoi(parts[1])
		if err != nil || rPort <= 0 || rPort > 65535 {
			return nil, fmt.Errorf("invalid remote port %q", parts[1])
		}
		rule.LocalPort = lPort
		rule.RemotePort = rPort

	case 3:
		// format: "local_port:remote_host:remote_port"
		lPort, err := strconv.Atoi(parts[0])
		if err != nil || lPort <= 0 || lPort > 65535 {
			return nil, fmt.Errorf("invalid local port %q", parts[0])
		}
		rPort, err := strconv.Atoi(parts[2])
		if err != nil || rPort <= 0 || rPort > 65535 {
			return nil, fmt.Errorf("invalid remote port %q", parts[2])
		}
		rule.LocalPort = lPort
		rule.RemoteHost = parts[1]
		rule.RemotePort = rPort

	case 4:
		// format: "bind_addr:local_port:remote_host:remote_port"
		rule.BindHost = parts[0]
		lPort, err := strconv.Atoi(parts[1])
		if err != nil || lPort <= 0 || lPort > 65535 {
			return nil, fmt.Errorf("invalid local port %q", parts[1])
		}
		rPort, err := strconv.Atoi(parts[3])
		if err != nil || rPort <= 0 || rPort > 65535 {
			return nil, fmt.Errorf("invalid remote port %q", parts[3])
		}
		rule.LocalPort = lPort
		rule.RemoteHost = parts[2]
		rule.RemotePort = rPort

	default:
		return nil, fmt.Errorf("expected format [bind_address:]local_port:remote_host:remote_port or local_port:remote_port")
	}

	return rule, nil
}

// ExpandHome expands leading '~/' or '~' to user's home directory.
func ExpandHome(path string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "~/") || path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		if path == "~" {
			return home
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
