package knownhosts

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/kulangaraalwinjoy/sshm/internal/cli/ui"
	"github.com/kulangaraalwinjoy/sshm/internal/config"
	"github.com/kulangaraalwinjoy/sshm/internal/logging"
	"github.com/kulangaraalwinjoy/sshm/pkg/models"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var fileLock sync.Mutex

// HostKeyVerifier verifies host keys against known_hosts with interactive prompts for unknown keys.
type HostKeyVerifier struct {
	knownHostsPath string
	strictMode     string // "ask", "yes", "no", "accept-new"
	promptCallback func(prompt string) (bool, error)
}

// NewHostKeyVerifier creates a new verifier.
func NewHostKeyVerifier(knownHostsPath, strictMode string, promptCb func(prompt string) (bool, error)) *HostKeyVerifier {
	if knownHostsPath == "" {
		knownHostsPath = config.GetKnownHostsPath()
	} else {
		knownHostsPath = models.ExpandHome(knownHostsPath)
	}

	if strictMode == "" {
		strictMode = "ask"
	}

	if promptCb == nil {
		promptCb = func(prompt string) (bool, error) {
			return ui.PromptConfirm(prompt, false)
		}
	}

	return &HostKeyVerifier{
		knownHostsPath: knownHostsPath,
		strictMode:     strings.ToLower(strictMode),
		promptCallback: promptCb,
	}
}

// FingerprintSHA256 formats public key as standard SHA256 OpenSSH fingerprint.
func FingerprintSHA256(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	b64 := base64.StdEncoding.EncodeToString(hash[:])
	return "SHA256:" + strings.TrimRight(b64, "=")
}

// Verify implements ssh.HostKeyCallback.
func (v *HostKeyVerifier) Verify(hostname string, remote net.Addr, key ssh.PublicKey) error {
	if v.strictMode == "no" {
		logging.Warnf("StrictHostKeyChecking=no: skipping host key verification for %s", hostname)
		return nil
	}

	if remote == nil {
		remote = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	}

	hostAddr := hostname
	if remote != nil {
		hostAddr = remote.String()
	}

	// If known_hosts file does not exist, create directory and empty file
	if err := v.ensureKnownHostsFile(); err != nil {
		return err
	}

	khCallback, err := knownhosts.New(v.knownHostsPath)
	if err != nil {
		return fmt.Errorf("failed to parse known_hosts at %q: %w", v.knownHostsPath, err)
	}

	verifyErr := khCallback(hostname, remote, key)
	if verifyErr == nil {
		// Key matched and is trusted
		return nil
	}

	fingerprint := FingerprintSHA256(key)
	keyType := key.Type()

	var keyErr *knownhosts.KeyError
	if ok := isKeyError(verifyErr, &keyErr); ok && len(keyErr.Want) > 0 {
		// CHANGED HOST KEY - POTENTIAL MITM!
		hostNameOnly, portStr, _ := net.SplitHostPort(hostname)
		if hostNameOnly == "" {
			hostNameOnly = hostname
		}
		port := 22
		if portStr != "" {
			fmt.Sscanf(portStr, "%d", &port)
		}

		mismatchErr := models.NewHostKeyMismatchError(hostNameOnly, port, fingerprint)
		ui.PrintError("\n%s\n", mismatchErr.Error())

		if v.strictMode == "yes" || v.strictMode == "accept-new" {
			return mismatchErr
		}

		// If "ask", give user explicit choice with severe warning
		warningPrompt := fmt.Sprintf("%s\nDo you want to ignore this warning and overwrite the key? (HIGH RISK)",
			ui.Red("Host key mismatch detected!"))
		accepted, pErr := v.promptCallback(warningPrompt)
		if pErr != nil || !accepted {
			return mismatchErr
		}

		// User explicitly accepted overwrite
		return v.addHostKey(hostname, remote, key)
	}

	// Unknown host key
	if v.strictMode == "yes" {
		return fmt.Errorf("host key verification failed for %s: unknown host key and StrictHostKeyChecking=yes", hostname)
	}

	if v.strictMode == "accept-new" {
		logging.Infof("StrictHostKeyChecking=accept-new: automatically adding new host key for %s", hostname)
		return v.addHostKey(hostname, remote, key)
	}

	// StrictHostKeyChecking=ask
	promptMsg := fmt.Sprintf("\n%s\n\nHost: %s\nKey type: %s\nFingerprint: %s\n\nDo you trust this host key?",
		ui.Yellow("WARNING: Unknown SSH host."),
		hostAddr,
		keyType,
		ui.Bold(fingerprint),
	)

	fmt.Println(promptMsg)
	accepted, pErr := v.promptCallback("Accept and save host key?")
	if pErr != nil || !accepted {
		return fmt.Errorf("host key verification rejected by user for %s", hostname)
	}

	return v.addHostKey(hostname, remote, key)
}

func (v *HostKeyVerifier) ensureKnownHostsFile() error {
	fileLock.Lock()
	defer fileLock.Unlock()

	dir := filepath.Dir(v.knownHostsPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory for known_hosts: %w", err)
	}

	if _, err := os.Stat(v.knownHostsPath); os.IsNotExist(err) {
		if err := os.WriteFile(v.knownHostsPath, []byte{}, 0600); err != nil {
			return fmt.Errorf("failed to create known_hosts file: %w", err)
		}
	}
	return nil
}

func (v *HostKeyVerifier) addHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	fileLock.Lock()
	defer fileLock.Unlock()

	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key) + "\n"

	f, err := os.OpenFile(v.knownHostsPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts to add key: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("failed to append host key: %w", err)
	}

	logging.Infof("Added host key for %s to %s", hostname, v.knownHostsPath)
	return nil
}

func isKeyError(err error, target **knownhosts.KeyError) bool {
	if ke, ok := err.(*knownhosts.KeyError); ok {
		*target = ke
		return true
	}
	return false
}
