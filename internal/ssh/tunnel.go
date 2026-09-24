package ssh

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/kulangaraalwinjoy/sshm/internal/cli/ui"
	"github.com/kulangaraalwinjoy/sshm/internal/logging"
	"github.com/kulangaraalwinjoy/sshm/pkg/models"
	"golang.org/x/crypto/ssh"
)

// ActiveTunnel represents a running port forwarding listener.
type ActiveTunnel struct {
	Type        string // "local", "remote", "dynamic"
	Description string
	LocalAddr   string
	RemoteAddr  string
	ActiveConns int64
	closer      func() error
}

// TunnelManager coordinates active SSH tunnels.
type TunnelManager struct {
	client  *Client
	tunnels []*ActiveTunnel
	mu      sync.Mutex
	stopCh  chan struct{}
}

// NewTunnelManager creates a TunnelManager for an existing SSH client.
func NewTunnelManager(client *Client) *TunnelManager {
	return &TunnelManager{
		client:  client,
		tunnels: make([]*ActiveTunnel, 0),
		stopCh:  make(chan struct{}),
	}
}

// AddLocalForward starts listening on a local port and forwards traffic to the remote host:port via SSH.
// Example: local 8080 forwards to server's port 80 (8080:localhost:80).
func (tm *TunnelManager) AddLocalForward(rule *models.ForwardRule) (*ActiveTunnel, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	bindAddr := net.JoinHostPort(rule.BindHost, strconv.Itoa(rule.LocalPort))
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind local port %s: %w", bindAddr, err)
	}

	actualLocalAddr := listener.Addr().String()
	remoteTarget := net.JoinHostPort(rule.RemoteHost, strconv.Itoa(rule.RemotePort))
	desc := fmt.Sprintf("%s -> %s (via %s)", actualLocalAddr, remoteTarget, tm.client.Profile.Name)

	tunnel := &ActiveTunnel{
		Type:        "local",
		Description: desc,
		LocalAddr:   actualLocalAddr,
		RemoteAddr:  remoteTarget,
		closer:      listener.Close,
	}

	tm.tunnels = append(tm.tunnels, tunnel)

	// Accept loop
	go func() {
		defer listener.Close()

		for {
			localConn, err := listener.Accept()
			if err != nil {
				select {
				case <-tm.stopCh:
					return
				default:
					logging.Debugf("Local forward listener accept ended: %v", err)
					return
				}
			}

			atomic.AddInt64(&tunnel.ActiveConns, 1)
			logging.Debugf("[%s] Connection accepted from %s", desc, localConn.RemoteAddr())

			go func(c net.Conn) {
				defer c.Close()
				defer atomic.AddInt64(&tunnel.ActiveConns, -1)

				remoteConn, dialErr := tm.client.Client.Dial("tcp", remoteTarget)
				if dialErr != nil {
					logging.Errorf("Failed to dial remote target %s via SSH: %v", remoteTarget, dialErr)
					return
				}
				defer remoteConn.Close()

				pipeBidirectional(c, remoteConn)
			}(localConn)
		}
	}()

	return tunnel, nil
}

// AddRemoteForward requests the remote SSH server to listen on a port and forward connections back to local destination.
func (tm *TunnelManager) AddRemoteForward(rule *models.ForwardRule) (*ActiveTunnel, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	remoteListenAddr := net.JoinHostPort(rule.BindHost, strconv.Itoa(rule.RemotePort))
	remoteListener, err := tm.client.Client.Listen("tcp", remoteListenAddr)
	if err != nil {
		return nil, fmt.Errorf("remote server failed to listen on %s: %w", remoteListenAddr, err)
	}

	localTarget := net.JoinHostPort(rule.RemoteHost, strconv.Itoa(rule.LocalPort))
	desc := fmt.Sprintf("%s (remote) -> %s (local)", remoteListenAddr, localTarget)

	tunnel := &ActiveTunnel{
		Type:        "remote",
		Description: desc,
		LocalAddr:   localTarget,
		RemoteAddr:  remoteListenAddr,
		closer:      remoteListener.Close,
	}

	tm.tunnels = append(tm.tunnels, tunnel)

	go func() {
		defer remoteListener.Close()

		for {
			remoteConn, err := remoteListener.Accept()
			if err != nil {
				select {
				case <-tm.stopCh:
					return
				default:
					logging.Debugf("Remote forward listener ended: %v", err)
					return
				}
			}

			atomic.AddInt64(&tunnel.ActiveConns, 1)
			logging.Debugf("[%s] Remote connection accepted", desc)

			go func(rc net.Conn) {
				defer rc.Close()
				defer atomic.AddInt64(&tunnel.ActiveConns, -1)

				localConn, dialErr := net.Dial("tcp", localTarget)
				if dialErr != nil {
					logging.Errorf("Failed to connect to local destination %s: %v", localTarget, dialErr)
					return
				}
				defer localConn.Close()

				pipeBidirectional(rc, localConn)
			}(remoteConn)
		}
	}()

	return tunnel, nil
}

// AddDynamicForward starts a local SOCKS5 proxy routing through the SSH client.
func (tm *TunnelManager) AddDynamicForward(bindHost string, port int) (*ActiveTunnel, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	bindAddr := net.JoinHostPort(bindHost, strconv.Itoa(port))
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind dynamic forward port %s: %w", bindAddr, err)
	}

	actualAddr := listener.Addr().String()
	desc := fmt.Sprintf("SOCKS5 Dynamic Proxy on %s (via %s)", actualAddr, tm.client.Profile.Name)

	tunnel := &ActiveTunnel{
		Type:        "dynamic",
		Description: desc,
		LocalAddr:   actualAddr,
		RemoteAddr:  "dynamic (SOCKS5)",
		closer:      listener.Close,
	}

	tm.tunnels = append(tm.tunnels, tunnel)

	go func() {
		defer listener.Close()

		for {
			clientConn, err := listener.Accept()
			if err != nil {
				select {
				case <-tm.stopCh:
					return
				default:
					return
				}
			}

			atomic.AddInt64(&tunnel.ActiveConns, 1)

			go func(c net.Conn) {
				defer c.Close()
				defer atomic.AddInt64(&tunnel.ActiveConns, -1)

				handleSocks5Connection(c, tm.client.Client)
			}(clientConn)
		}
	}()

	return tunnel, nil
}

// handleSocks5Connection implements a lightweight RFC 1928 SOCKS5 handshake.
func handleSocks5Connection(conn net.Conn, sshClient *ssh.Client) {
	buf := make([]byte, 256)

	// 1. Version identifier / method selection message
	n, err := io.ReadFull(conn, buf[:2])
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Respond with NO AUTHENTICATION REQUIRED (0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Client request
	// [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 { // Only CONNECT command (0x01) supported
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	var targetHost string
	switch buf[3] {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		targetHost = net.IP(ipBuf).String()

	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		targetHost = string(domainBuf)

	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		targetHost = net.IP(ipBuf).String()

	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	// Port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	targetPort := (int(portBuf[0]) << 8) | int(portBuf[1])
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))

	logging.Debugf("[SOCKS5] Connecting to %s via SSH", targetAddr)
	remoteConn, dialErr := sshClient.Dial("tcp", targetAddr)
	if dialErr != nil {
		logging.Errorf("[SOCKS5] Failed to dial %s: %v", targetAddr, dialErr)
		_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}
	defer remoteConn.Close()

	// Respond SUCCESS (0x00)
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	pipeBidirectional(conn, remoteConn)
}

// Stop closes all running tunnels.
func (tm *TunnelManager) Stop() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	select {
	case <-tm.stopCh:
		return
	default:
		close(tm.stopCh)
	}

	for _, t := range tm.tunnels {
		if t.closer != nil {
			_ = t.closer()
		}
	}
	tm.tunnels = nil
}

// StartAll starts all tunnels configured in profile or passed as command line arguments.
func (tm *TunnelManager) StartAll(localSpecs, remoteSpecs []string, dynamicPort string) error {
	for _, spec := range localSpecs {
		rule, err := models.ParsePortForwardSpec(spec)
		if err != nil {
			return err
		}
		t, err := tm.AddLocalForward(rule)
		if err != nil {
			return err
		}
		ui.PrintSuccess("Local forward: %s", t.Description)
	}

	for _, spec := range remoteSpecs {
		rule, err := models.ParsePortForwardSpec(spec)
		if err != nil {
			return err
		}
		t, err := tm.AddRemoteForward(rule)
		if err != nil {
			return err
		}
		ui.PrintSuccess("Remote forward: %s", t.Description)
	}

	if dynamicPort != "" {
		port, err := strconv.Atoi(dynamicPort)
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid dynamic forward port: %s", dynamicPort)
		}
		t, err := tm.AddDynamicForward("127.0.0.1", port)
		if err != nil {
			return err
		}
		ui.PrintSuccess("Dynamic proxy: %s", t.Description)
	}

	return nil
}

// pipeBidirectional pumps data between two network connections until one terminates.
func pipeBidirectional(c1, c2 io.ReadWriteCloser) {
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(c1, c2)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(c2, c1)
		errCh <- err
	}()

	<-errCh
}
