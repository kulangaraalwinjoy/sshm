package ssh

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/alwin/sshm/internal/knownhosts"
	"github.com/alwin/sshm/internal/logging"
	"github.com/alwin/sshm/pkg/models"
	"golang.org/x/crypto/ssh"
)

// Client wraps an active ssh.Client with session management and keep-alive handling.
type Client struct {
	Client  *ssh.Client
	Profile *models.SSHProfile
	stopCh  chan struct{}
}

// Connect establishes an SSH connection according to the profile and credentials.
func Connect(profile *models.SSHProfile, creds *models.ProfileCredentials, verifier *knownhosts.HostKeyVerifier) (*Client, error) {
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("invalid profile configuration: %w", err)
	}

	authMethods, err := ResolveAuthMethods(profile, creds)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare authentication: %w", err)
	}

	timeout := 15 * time.Second
	if profile.ConnectTimeout > 0 {
		timeout = time.Duration(profile.ConnectTimeout) * time.Second
	}

	var hostKeyCallback ssh.HostKeyCallback
	if verifier != nil {
		hostKeyCallback = verifier.Verify
	} else {
		defaultVerifier := knownhosts.NewHostKeyVerifier(profile.KnownHostsFile, profile.StrictHostKeyChecking, nil)
		hostKeyCallback = defaultVerifier.Verify
	}

	sshConfig := &ssh.ClientConfig{
		User:            profile.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}

	targetAddr := net.JoinHostPort(profile.Host, strconv.Itoa(profile.Port))
	logging.Debugf("Connecting to %s as %s", targetAddr, profile.Username)

	var rawConn net.Conn

	// Handle ProxyCommand
	if profile.ProxyCommand != "" {
		logging.Debugf("Dialing via ProxyCommand: %s", profile.ProxyCommand)
		pcConn, pcErr := DialViaProxyCommand(profile.ProxyCommand, profile.Host, profile.Port)
		if pcErr != nil {
			return nil, fmt.Errorf("ProxyCommand connection failed: %w", pcErr)
		}
		rawConn = pcConn
	} else if profile.ProxyJump != "" {
		// Handle ProxyJump
		jUser, jHost, jPort, jErr := ParseProxyJumpSpec(profile.ProxyJump)
		if jErr != nil {
			return nil, jErr
		}
		if jUser == "" {
			jUser = profile.Username
		}
		logging.Debugf("Dialing jump host %s:%d as %s", jHost, jPort, jUser)

		jumpConfig := &ssh.ClientConfig{
			User:            jUser,
			Auth:            authMethods,
			HostKeyCallback: hostKeyCallback,
			Timeout:         timeout,
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		jumpClient, jDialErr := DialJumpHost(ctx, jUser, jHost, jPort, jumpConfig)
		if jDialErr != nil {
			return nil, fmt.Errorf("failed to connect to jump host: %w", jDialErr)
		}

		logging.Debugf("Routing to target %s via jump host", targetAddr)
		jConn, routeErr := jumpClient.Dial("tcp", targetAddr)
		if routeErr != nil {
			_ = jumpClient.Close()
			return nil, fmt.Errorf("failed to route via jump host to %s: %w", targetAddr, routeErr)
		}
		rawConn = jConn
	} else {
		// Standard direct TCP connection
		d := net.Dialer{Timeout: timeout}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		directConn, dialErr := d.DialContext(ctx, "tcp", targetAddr)
		if dialErr != nil {
			if netErr, ok := dialErr.(net.Error); ok && netErr.Timeout() {
				return nil, models.NewConnectionTimeoutError(profile, dialErr)
			}
			return nil, &models.ConnectionError{
				ProfileName: profile.Name,
				Host:        profile.Host,
				Port:        profile.Port,
				User:        profile.Username,
				Reason:      dialErr.Error(),
				Checklist: []string{
					"Host reachability and DNS resolution",
					"Port availability and firewall rules",
					"Network connectivity",
				},
				Err: dialErr,
			}
		}
		rawConn = directConn
	}

	// Handshake over established net.Conn
	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, targetAddr, sshConfig)
	if err != nil {
		_ = rawConn.Close()
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "unable to authenticate") || strings.Contains(errStr, "permission denied") {
			return nil, models.NewAuthFailedError(profile, err)
		}
		return nil, fmt.Errorf("SSH handshake failed with %s: %w", targetAddr, err)
	}

	sshClient := ssh.NewClient(sshConn, chans, reqs)
	client := &Client{
		Client:  sshClient,
		Profile: profile,
		stopCh:  make(chan struct{}),
	}

	// Start keep-alive ticker if configured
	if profile.ServerAliveInterval > 0 {
		client.startKeepAlive(profile.ServerAliveInterval, profile.ServerAliveCountMax)
	}

	return client, nil
}

func (c *Client) startKeepAlive(intervalSecs int, maxCount int) {
	if intervalSecs <= 0 {
		return
	}
	if maxCount <= 0 {
		maxCount = 3
	}

	ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
	go func() {
		missedCount := 0
		for {
			select {
			case <-c.stopCh:
				ticker.Stop()
				return
			case <-ticker.C:
				_, _, err := c.Client.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					missedCount++
					logging.Debugf("Keep-alive request missed (%d/%d): %v", missedCount, maxCount, err)
					if missedCount >= maxCount {
						logging.Warnf("Server alive count max exceeded (%d), terminating connection", maxCount)
						_ = c.Close()
						return
					}
				} else {
					missedCount = 0
				}
			}
		}
	}()
}

// Close gracefully terminates the SSH connection and background keep-alives.
func (c *Client) Close() error {
	select {
	case <-c.stopCh:
		// already closed
	default:
		close(c.stopCh)
	}
	if c.Client != nil {
		return c.Client.Close()
	}
	return nil
}
