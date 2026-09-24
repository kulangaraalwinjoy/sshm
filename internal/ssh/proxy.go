package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kulangaraalwinjoy/sshm/internal/logging"
	"golang.org/x/crypto/ssh"
)

// ParseProxyJumpSpec parses a proxy jump specification: [user@]host[:port]
func ParseProxyJumpSpec(spec string) (user, host string, port int, err error) {
	spec = strings.TrimSpace(spec)
	user = ""
	port = 22

	// Extract user if present
	if idx := strings.Index(spec, "@"); idx != -1 {
		user = spec[:idx]
		spec = spec[idx+1:]
	}

	// Extract host and port
	if strings.Contains(spec, ":") {
		h, pStr, splitErr := net.SplitHostPort(spec)
		if splitErr != nil {
			return "", "", 0, fmt.Errorf("invalid proxy jump host:port %q: %w", spec, splitErr)
		}
		p, convErr := strconv.Atoi(pStr)
		if convErr != nil {
			return "", "", 0, fmt.Errorf("invalid proxy jump port %q: %w", pStr, convErr)
		}
		host = h
		port = p
	} else {
		host = spec
	}

	if host == "" {
		return "", "", 0, fmt.Errorf("empty host in proxy jump specification")
	}

	return user, host, port, nil
}

// DialViaProxyCommand spawns a command and wraps its stdin/stdout as a net.Conn.
func DialViaProxyCommand(command string, host string, port int) (net.Conn, error) {
	// Replace %h with host and %p with port
	cmdStr := strings.ReplaceAll(command, "%h", host)
	cmdStr = strings.ReplaceAll(cmdStr, "%p", strconv.Itoa(port))

	logging.Debugf("Executing ProxyCommand: %s", cmdStr)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", cmdStr)
	} else {
		cmd = exec.Command("sh", "-c", cmdStr)
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open stdin for proxy command: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open stdout for proxy command: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start proxy command: %w", err)
	}

	return &pipeConn{
		stdin:  stdinPipe,
		stdout: stdoutPipe,
		cmd:    cmd,
	}, nil
}

// pipeConn adapts an exec.Cmd's stdio into net.Conn
type pipeConn struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
	cmd    *exec.Cmd
}

func (c *pipeConn) Read(b []byte) (n int, err error) {
	return c.stdout.Read(b)
}

func (c *pipeConn) Write(b []byte) (n int, err error) {
	return c.stdin.Write(b)
}

func (c *pipeConn) Close() error {
	_ = c.stdin.Close()
	_ = c.stdout.Close()
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (c *pipeConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (c *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return "pipe" }
func (a dummyAddr) String() string  { return string(a) }

// DialJumpHost connects to a jump host and returns an SSH client connection.
func DialJumpHost(ctx context.Context, jumpUser, jumpHost string, jumpPort int, config *ssh.ClientConfig) (*ssh.Client, error) {
	addr := net.JoinHostPort(jumpHost, strconv.Itoa(jumpPort))
	d := net.Dialer{Timeout: config.Timeout}

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to reach jump host %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed SSH handshake with jump host %s: %w", addr, err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}
