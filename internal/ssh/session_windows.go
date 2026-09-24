//go:build windows

package ssh

import (
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func monitorWindowResize(stdoutFd int, session *ssh.Session) func() {
	done := make(chan struct{})

	go func() {
		lastW, lastH := 0, 0
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				w, h, err := term.GetSize(stdoutFd)
				if err == nil && (w != lastW || h != lastH) && w > 0 && h > 0 {
					lastW, lastH = w, h
					_ = session.WindowChange(h, w)
				}
			}
		}
	}()

	return func() {
		close(done)
	}
}
