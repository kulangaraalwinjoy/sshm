package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alwin/sshm/internal/knownhosts"
	"github.com/alwin/sshm/internal/sftp"
	"github.com/alwin/sshm/internal/ssh"
	"github.com/alwin/sshm/internal/transfer"
	"github.com/alwin/sshm/pkg/models"
	"github.com/alwin/sshm/testserver"
	gossh "golang.org/x/crypto/ssh"
)

func TestSSHConnection_PasswordAuth(t *testing.T) {
	tempDir := t.TempDir()
	server, err := testserver.NewServer(tempDir, "testuser", "secretpass123")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer server.Close()

	profile := models.NewSSHProfile("test-profile", "127.0.0.1", server.Port(), "testuser")
	profile.AuthMethod = models.AuthMethodPassword
	profile.StrictHostKeyChecking = "no"

	creds := &models.ProfileCredentials{
		Password: "secretpass123",
	}

	client, err := ssh.Connect(profile, creds, nil)
	if err != nil {
		t.Fatalf("ssh.Connect failed with valid password: %v", err)
	}
	defer client.Close()

	// Verify session can run
	session, err := client.Client.NewSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Close()

	var buf bytes.Buffer
	session.Stdout = &buf
	if err := session.Shell(); err != nil {
		t.Fatalf("failed to open shell: %v", err)
	}
	_ = session.Wait()

	if !bytes.Contains(buf.Bytes(), []byte("Mock SSH Shell Connected")) {
		t.Errorf("shell output unexpected: %s", buf.String())
	}
}

func TestSSHConnection_PrivateKeyAuth(t *testing.T) {
	tempDir := t.TempDir()
	server, err := testserver.NewServer(tempDir, "keyuser", "unused")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer server.Close()

	// Generate client key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	server.SetClientPublicKey(signer.PublicKey())

	// Save private key to temp file
	keyPath := filepath.Join(tempDir, "id_ed25519")
	keyData := gossh.MarshalAuthorizedKey(signer.PublicKey())
	_ = os.WriteFile(keyPath+".pub", keyData, 0600)

	// Encode private key in OpenSSH/PKCS8 format
	// For testing, we use signer directly via vault credential bytes
	pemBytes := formatEd25519PrivateKey(priv)
	_ = os.WriteFile(keyPath, pemBytes, 0600)

	profile := models.NewSSHProfile("key-profile", "127.0.0.1", server.Port(), "keyuser")
	profile.AuthMethod = models.AuthMethodKey
	profile.KeyPath = keyPath
	profile.StrictHostKeyChecking = "no"

	client, err := ssh.Connect(profile, nil, nil)
	if err != nil {
		t.Fatalf("ssh.Connect failed with private key: %v", err)
	}
	defer client.Close()
}

func TestSSHConnection_AuthFailure(t *testing.T) {
	tempDir := t.TempDir()
	server, err := testserver.NewServer(tempDir, "user", "correctpass")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer server.Close()

	profile := models.NewSSHProfile("fail-profile", "127.0.0.1", server.Port(), "user")
	profile.AuthMethod = models.AuthMethodPassword
	profile.StrictHostKeyChecking = "no"

	creds := &models.ProfileCredentials{
		Password: "wrongpassword",
	}

	_, err = ssh.Connect(profile, creds, nil)
	if err == nil {
		t.Fatalf("expected connection to fail with wrong password, but succeeded")
	}

	// Verify structured error
	connErr, ok := err.(*models.ConnectionError)
	if !ok {
		t.Fatalf("expected *models.ConnectionError, got %T: %v", err, err)
	}
	if connErr.Reason != "Permission denied (publickey/password)." {
		t.Errorf("expected permission denied reason, got: %s", connErr.Reason)
	}
}

func TestSFTP_UploadAndDownload(t *testing.T) {
	tempDir := t.TempDir()
	serverDir := filepath.Join(tempDir, "server_root")
	clientDir := filepath.Join(tempDir, "client_root")
	_ = os.MkdirAll(serverDir, 0755)
	_ = os.MkdirAll(clientDir, 0755)

	server, err := testserver.NewServer(serverDir, "sftpuser", "sftppass")
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Close()

	profile := models.NewSSHProfile("sftp-test", "127.0.0.1", server.Port(), "sftpuser")
	profile.AuthMethod = models.AuthMethodPassword
	profile.StrictHostKeyChecking = "no"
	creds := &models.ProfileCredentials{Password: "sftppass"}

	client, err := ssh.Connect(profile, creds, nil)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	sftpClient, err := sftp.NewSFTPClient(client.Client)
	if err != nil {
		t.Fatalf("sftp client failed: %v", err)
	}
	defer sftpClient.Close()

	engine := transfer.NewEngine(sftpClient.Client)

	// 1. Upload single file
	localUploadFile := filepath.Join(clientDir, "testfile.txt")
	testData := []byte("Hello secure world through SFTP transfer!")
	_ = os.WriteFile(localUploadFile, testData, 0644)

	err = engine.Upload(localUploadFile, ".")
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	// Verify uploaded file exists on server
	uploadedOnServer := filepath.Join(serverDir, "testfile.txt")
	serverContent, err := os.ReadFile(uploadedOnServer)
	if err != nil {
		t.Fatalf("file not found on server: %v", err)
	}
	if !bytes.Equal(serverContent, testData) {
		t.Fatalf("server content mismatch: got %q, want %q", serverContent, testData)
	}

	// 2. Download file back
	downloadDest := filepath.Join(clientDir, "downloaded.txt")
	err = engine.Download("testfile.txt", downloadDest)
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}

	downloadedContent, err := os.ReadFile(downloadDest)
	if err != nil {
		t.Fatalf("downloaded file not found: %v", err)
	}
	if !bytes.Equal(downloadedContent, testData) {
		t.Fatalf("downloaded content mismatch")
	}

	// 3. Recursive directory upload and download
	nestedLocalDir := filepath.Join(clientDir, "nested_folder")
	_ = os.MkdirAll(filepath.Join(nestedLocalDir, "sub"), 0755)
	_ = os.WriteFile(filepath.Join(nestedLocalDir, "file1.txt"), []byte("nested file 1"), 0644)
	_ = os.WriteFile(filepath.Join(nestedLocalDir, "sub", "file2.txt"), []byte("nested file 2"), 0644)

	err = engine.Upload(nestedLocalDir, "remote_nested")
	if err != nil {
		t.Fatalf("recursive upload failed: %v", err)
	}

	// Verify nested files exist on server
	serverFile2 := filepath.Join(serverDir, "remote_nested", "nested_folder", "sub", "file2.txt")
	f2Content, err := os.ReadFile(serverFile2)
	if err != nil {
		t.Fatalf("nested file on server not found: %v", err)
	}
	if string(f2Content) != "nested file 2" {
		t.Errorf("nested file content mismatch")
	}
}

func TestPortTunnel_ServerPortToLocal(t *testing.T) {
	// This specifically tests the user's requirement:
	// "port 80 of server connect to a local port"
	tempDir := t.TempDir()
	server, err := testserver.NewServer(tempDir, "tunneluser", "tunnelpass")
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Close()

	// Start a mock HTTP server simulating server port 80 (e.g. a web server on the remote host)
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock web server: %v", err)
	}
	defer httpListener.Close()

	_, httpPortStr, _ := net.SplitHostPort(httpListener.Addr().String())
	httpPort, _ := net.LookupPort("tcp", httpPortStr)

	mockHTTPServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("HTTP from remote server port 80"))
		}),
	}
	go func() {
		_ = mockHTTPServer.Serve(httpListener)
	}()
	defer mockHTTPServer.Close()

	// Connect SSH client
	profile := models.NewSSHProfile("tunnel-test", "127.0.0.1", server.Port(), "tunneluser")
	profile.AuthMethod = models.AuthMethodPassword
	profile.StrictHostKeyChecking = "no"
	creds := &models.ProfileCredentials{Password: "tunnelpass"}

	client, err := ssh.Connect(profile, creds, nil)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	// Establish local port forward: local port 0 (ephemeral) -> server:httpPort
	tm := ssh.NewTunnelManager(client)
	defer tm.Stop()

	rule := &models.ForwardRule{
		BindHost:   "127.0.0.1",
		LocalPort:  0, // Ephemeral port
		RemoteHost: "127.0.0.1",
		RemotePort: httpPort,
	}

	tunnel, err := tm.AddLocalForward(rule)
	if err != nil {
		t.Fatalf("AddLocalForward failed: %v", err)
	}

	// Make an HTTP request to the local tunnel port
	localURL := fmt.Sprintf("http://%s/", tunnel.LocalAddr)
	httpClient := &http.Client{Timeout: 3 * time.Second}

	resp, err := httpClient.Get(localURL)
	if err != nil {
		t.Fatalf("HTTP request through tunnel failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	expected := "HTTP from remote server port 80"
	if string(body) != expected {
		t.Fatalf("tunnel response mismatch: got %q, want %q", string(body), expected)
	}
}

func TestHostKeyVerification(t *testing.T) {
	tempDir := t.TempDir()
	knownHostsPath := filepath.Join(tempDir, "known_hosts")

	server, err := testserver.NewServer(tempDir, "user", "pass")
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Close()

	// 1. Test "yes" with unknown key -> rejects
	vStrictYes := knownhosts.NewHostKeyVerifier(knownHostsPath, "yes", nil)
	err = vStrictYes.Verify(server.Addr(), nil, server.HostPublicKey())
	if err == nil {
		t.Fatalf("expected StrictHostKeyChecking=yes to reject unknown key")
	}

	// 2. Test "ask" with approval callback -> saves and succeeds
	accepted := false
	promptCb := func(prompt string) (bool, error) {
		accepted = true
		return true, nil
	}

	vAsk := knownhosts.NewHostKeyVerifier(knownHostsPath, "ask", promptCb)
	err = vAsk.Verify(server.Addr(), nil, server.HostPublicKey())
	if err != nil {
		t.Fatalf("expected approved host key to succeed, got: %v", err)
	}
	if !accepted {
		t.Errorf("prompt callback was not called")
	}

	// 3. Test verifying again -> now trusted, no prompt needed
	promptCalledAgain := false
	vTrusted := knownhosts.NewHostKeyVerifier(knownHostsPath, "yes", func(p string) (bool, error) {
		promptCalledAgain = true
		return false, nil
	})
	err = vTrusted.Verify(server.Addr(), nil, server.HostPublicKey())
	if err != nil {
		t.Fatalf("expected known host to be accepted immediately, got: %v", err)
	}
	if promptCalledAgain {
		t.Errorf("prompt should not be called for already known host key")
	}
}

func formatEd25519PrivateKey(priv ed25519.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}
