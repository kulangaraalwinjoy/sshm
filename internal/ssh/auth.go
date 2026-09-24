package ssh

import (
	"fmt"
	"net"
	"os"

	"github.com/alwin/sshm/internal/cli/ui"
	"github.com/alwin/sshm/internal/logging"
	"github.com/alwin/sshm/pkg/models"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ResolveAuthMethods produces the appropriate slice of ssh.AuthMethod for a profile and credentials.
func ResolveAuthMethods(profile *models.SSHProfile, creds *models.ProfileCredentials) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	switch profile.AuthMethod {
	case models.AuthMethodKey:
		signer, err := resolveKeySigner(profile, creds)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))

	case models.AuthMethodPassword:
		password := ""
		if creds != nil && creds.Password != "" {
			password = creds.Password
		} else {
			// Prompt for password securely
			prompt := fmt.Sprintf("Enter password for %s@%s", profile.Username, profile.Host)
			p, err := ui.PromptPassword(prompt)
			if err != nil {
				return nil, fmt.Errorf("password prompt error: %w", err)
			}
			password = p
		}
		methods = append(methods, ssh.Password(password))
		// Also support keyboard-interactive for servers that only accept keyboard-interactive
		methods = append(methods, ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = password
			}
			return answers, nil
		}))

	case models.AuthMethodAgent:
		agentMethod, err := resolveAgentAuth(profile)
		if err != nil {
			return nil, err
		}
		methods = append(methods, agentMethod)

	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", profile.AuthMethod)
	}

	return methods, nil
}

func resolveKeySigner(profile *models.SSHProfile, creds *models.ProfileCredentials) (ssh.Signer, error) {
	var keyBytes []byte

	if profile.KeyInVault && creds != nil && len(creds.PrivateKey) > 0 {
		keyBytes = creds.PrivateKey
	} else if profile.KeyPath != "" {
		expandedPath := models.ExpandHome(profile.KeyPath)
		data, err := os.ReadFile(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key at %q: %w", profile.KeyPath, err)
		}
		keyBytes = data
	} else {
		return nil, fmt.Errorf("profile is configured for private key auth but no key path or vault key found")
	}

	passphrase := ""
	if creds != nil && creds.Passphrase != "" {
		passphrase = creds.Passphrase
	}

	// First try parsing key without passphrase
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err == nil {
		return signer, nil
	}

	// If failed, check if encrypted key and try with passphrase
	if passphrase == "" {
		// Prompt user for key passphrase
		prompt := fmt.Sprintf("Enter passphrase for private key (%s)", profile.KeyPath)
		p, pErr := ui.PromptPassword(prompt)
		if pErr != nil {
			return nil, fmt.Errorf("failed to prompt for key passphrase: %w", pErr)
		}
		passphrase = p
	}

	signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted private key: %w", err)
	}

	return signer, nil
}

func resolveAgentAuth(profile *models.SSHProfile) (ssh.AuthMethod, error) {
	agentSock := os.Getenv("SSH_AUTH_SOCK")
	if profile.IdentityAgent != "" {
		agentSock = models.ExpandHome(profile.IdentityAgent)
	}

	if agentSock == "" {
		return nil, fmt.Errorf("SSH agent authentication requested, but SSH_AUTH_SOCK is not set")
	}

	conn, err := net.Dial("unix", agentSock)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH agent at %q: %w", agentSock, err)
	}

	agentClient := agent.NewClient(conn)
	signers, err := agentClient.Signers()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve keys from SSH agent: %w", err)
	}

	if len(signers) == 0 {
		logging.Warnf("SSH agent is running at %q, but has no identities loaded (run 'ssh-add')", agentSock)
	}

	return ssh.PublicKeysCallback(agentClient.Signers), nil
}
