//go:build !windows

package ssh

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func monitorWindowResize(stdoutFd int, session *ssh.Session) func() {
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.SIGWINCH)

	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-done:
				return
			case <-sigwinch:
				width, height, err := term.GetSize(stdoutFd)
				if err == nil && width > 0 && height > 0 {
					_ = session.WindowChange(height, width)
				}
			}
		}
	}()

	return func() {
		close(done)
		signal.Stop(sigwinch)
	}
}
