package ssh

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alwin/sshm/internal/logging"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// InteractiveSession runs a full interactive SSH terminal session with PTY and raw mode.
func (c *Client) InteractiveSession() (int, error) {
	session, err := c.Client.NewSession()
	if err != nil {
		return 1, fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	stdinFd := int(os.Stdin.Fd())
	stdoutFd := int(os.Stdout.Fd())

	isTerm := term.IsTerminal(stdinFd)

	if isTerm {
		// Put terminal into raw mode
		oldState, err := term.MakeRaw(stdinFd)
		if err != nil {
			return 1, fmt.Errorf("failed to set terminal to raw mode: %w", err)
		}
		defer func() {
			_ = term.Restore(stdinFd, oldState)
		}()

		// Query initial window dimensions
		width, height, err := term.GetSize(stdoutFd)
		if err != nil || width <= 0 || height <= 0 {
			width = 80
			height = 24
		}

		termType := os.Getenv("TERM")
		if termType == "" {
			termType = "xterm-256color"
		}

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		if err := session.RequestPty(termType, height, width, modes); err != nil {
			return 1, fmt.Errorf("failed to request PTY: %w", err)
		}

		// Start platform-specific window resize monitor
		stopResize := monitorWindowResize(stdoutFd, session)
		defer stopResize()
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	logging.Debugf("Requesting remote shell on %s", c.Profile.Name)
	if err := session.Shell(); err != nil {
		return 1, fmt.Errorf("failed to start remote shell: %w", err)
	}

	// Wait for remote command/shell to exit
	err = session.Wait()
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			logging.Debugf("Remote command exited with code %d", exitErr.ExitStatus())
			return exitErr.ExitStatus(), nil
		}
		// ExitMissingError occurs if session closed without explicit status
		var missingErr *ssh.ExitMissingError
		if errors.As(err, &missingErr) {
			return 0, nil
		}
		if err != io.EOF {
			return 1, err
		}
	}

	return 0, nil
}
