package models

import (
	"fmt"
	"strings"
)

// ConnectionError provides a structured, user-friendly error description for SSH/SFTP connection issues.
// It never leaks secrets, passwords, or private keys.
type ConnectionError struct {
	ProfileName string
	Host        string
	Port        int
	User        string
	Reason      string
	Checklist   []string
	Err         error
}

func (e *ConnectionError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("✗ Unable to connect to %q.\n\n", e.ProfileName))
	sb.WriteString(fmt.Sprintf("Host: %s\n", e.Host))
	sb.WriteString(fmt.Sprintf("Port: %d\n", e.Port))
	sb.WriteString(fmt.Sprintf("User: %s\n", e.User))
	if e.Reason != "" {
		sb.WriteString(fmt.Sprintf("\nReason: %s\n", e.Reason))
	}
	if len(e.Checklist) > 0 {
		sb.WriteString("\nCheck:\n")
		for _, item := range e.Checklist {
			sb.WriteString(fmt.Sprintf("- %s\n", item))
		}
	}
	if e.Err != nil && e.Reason == "" {
		sb.WriteString(fmt.Sprintf("\nDetails: %v\n", e.Err))
	}
	return sb.String()
}

func (e *ConnectionError) Unwrap() error {
	return e.Err
}

// NewConnectionTimeoutError creates a structured timeout error.
func NewConnectionTimeoutError(profile *SSHProfile, err error) *ConnectionError {
	return &ConnectionError{
		ProfileName: profile.Name,
		Host:        profile.Host,
		Port:        profile.Port,
		User:        profile.Username,
		Reason:      "Connection timed out.",
		Checklist: []string{
			"Server availability and status",
			"Firewall rules and security groups (ingress on port)",
			"Host/IP address correctness",
			"Local network and VPN connection",
		},
		Err: err,
	}
}

// NewAuthFailedError creates a structured authentication failed error.
func NewAuthFailedError(profile *SSHProfile, err error) *ConnectionError {
	checklist := []string{
		"Username correctness",
		"Authorized keys on the remote server (~/.ssh/authorized_keys permissions 0600)",
	}
	if profile.AuthMethod == AuthMethodKey {
		checklist = append(checklist, "Private key matches server public key", "Passphrase is valid for the encrypted key")
	} else if profile.AuthMethod == AuthMethodPassword {
		checklist = append(checklist, "Password is correct and account is not locked")
	} else if profile.AuthMethod == AuthMethodAgent {
		checklist = append(checklist, "SSH Agent is running (SSH_AUTH_SOCK) and has identities loaded (ssh-add -l)")
	}

	return &ConnectionError{
		ProfileName: profile.Name,
		Host:        profile.Host,
		Port:        profile.Port,
		User:        profile.Username,
		Reason:      "Permission denied (publickey/password).",
		Checklist:   checklist,
		Err:         err,
	}
}

// NewHostKeyMismatchError creates a host-key verification error.
func NewHostKeyMismatchError(host string, port int, fingerprint string) error {
	return fmt.Errorf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"+
		"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"+
		"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"+
		"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n"+
		"Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n"+
		"The fingerprint for the host key sent by %s:%d is:\n%s\n"+
		"Host key verification failed.", host, port, fingerprint)
}
