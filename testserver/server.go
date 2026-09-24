package testserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Server is an in-memory mock SSH and SFTP server for testing.
type Server struct {
	listener     net.Listener
	config       *ssh.ServerConfig
	hostSigner   ssh.Signer
	hostPubKey   ssh.PublicKey
	rootDir      string
	validUser    string
	validPass    string
	validClientKey ssh.PublicKey
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewServer spins up an embedded test SSH & SFTP server listening on a local loopback port.
func NewServer(rootDir, username, password string) (*Server, error) {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind test listener: %w", err)
	}

	s := &Server{
		listener:   l,
		hostSigner: hostSigner,
		hostPubKey: hostSigner.PublicKey(),
		rootDir:    rootDir,
		validUser:  username,
		validPass:  password,
		stopCh:     make(chan struct{}),
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if conn.User() == s.validUser && string(pass) == s.validPass {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %s", conn.User())
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.validClientKey != nil && conn.User() == s.validUser {
				if string(key.Marshal()) == string(s.validClientKey.Marshal()) {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("key rejected for %s", conn.User())
		},
	}
	config.AddHostKey(hostSigner)
	s.config = config

	s.wg.Add(1)
	go s.acceptLoop()

	return s, nil
}

// SetClientPublicKey configures a trusted public key for key-based authentication testing.
func (s *Server) SetClientPublicKey(key ssh.PublicKey) {
	s.validClientKey = key
}

// Addr returns the host:port address of the server.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Port returns the server's listening port.
func (s *Server) Port() int {
	_, pStr, _ := net.SplitHostPort(s.Addr())
	p, _ := strconv.Atoi(pStr)
	return p
}

// HostPublicKey returns the server's public key for host key verification tests.
func (s *Server) HostPublicKey() ssh.PublicKey {
	return s.hostPubKey
}

// RootDir returns the root directory exposed via SFTP.
func (s *Server) RootDir() string {
	return s.rootDir
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				return
			}
		}

		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(netConn net.Conn) {
	defer netConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			s.handleSessionChannel(newChan)
		case "direct-tcpip":
			s.handleDirectTCPIP(newChan)
		default:
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

func (s *Server) handleSessionChannel(newChan ssh.NewChannel) {
	channel, requests, err := newChan.Accept()
	if err != nil {
		return
	}

	go func() {
		defer channel.Close()

		for req := range requests {
			switch req.Type {
			case "subsystem":
				subsystem := string(req.Payload[4:])
				if subsystem == "sftp" {
					_ = req.Reply(true, nil)
					// Start SFTP server rooted at s.rootDir
					sftpServer, err := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(s.rootDir))
					if err == nil {
						_ = sftpServer.Serve()
					}
					return
				}
				_ = req.Reply(false, nil)

			case "shell", "pty-req":
				_ = req.Reply(true, nil)
				if req.Type == "shell" {
					// Send welcome banner and close cleanly
					_, _ = io.WriteString(channel, "Mock SSH Shell Connected\r\n")
					// Send exit status 0
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				}

			default:
				_ = req.Reply(false, nil)
			}
		}
	}()
}

func (s *Server) handleDirectTCPIP(newChan ssh.NewChannel) {
	type forwardData struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}

	var d forwardData
	if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
		return
	}

	target := net.JoinHostPort(d.DestAddr, strconv.Itoa(int(d.DestPort)))
	destConn, err := net.Dial("tcp", target)
	if err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to dial target %s: %v", target, err))
		return
	}
	defer destConn.Close()

	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	go ssh.DiscardRequests(reqs)

	errCh := make(chan error, 2)
	go func() {
		_, e := io.Copy(destConn, ch)
		errCh <- e
	}()
	go func() {
		_, e := io.Copy(ch, destConn)
		errCh <- e
	}()

	<-errCh
}

// Close stops the mock SSH server.
func (s *Server) Close() error {
	select {
	case <-s.stopCh:
		return nil
	default:
		close(s.stopCh)
	}

	err := s.listener.Close()
	s.wg.Wait()
	_ = os.RemoveAll(s.rootDir)
	return err
}
