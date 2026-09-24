package sftp

import (
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SFTPClient wraps the pkg/sftp.Client to provide high-level filesystem operations.
type SFTPClient struct {
	Client *sftp.Client
}

// NewSFTPClient initializes an SFTP client over an established SSH client connection.
func NewSFTPClient(sshClient *ssh.Client) (*SFTPClient, error) {
	client, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SFTP subsystem: %w", err)
	}
	return &SFTPClient{Client: client}, nil
}

// Close closes the SFTP client.
func (c *SFTPClient) Close() error {
	if c.Client != nil {
		return c.Client.Close()
	}
	return nil
}

// GetWD returns the current remote working directory (defaults to "." if not resolved).
func (c *SFTPClient) GetWD() (string, error) {
	wd, err := c.Client.Getwd()
	if err != nil {
		return ".", nil
	}
	return wd, nil
}

// ListDirectory reads and returns directory entries sorted (directories first, then alphabetically).
func (c *SFTPClient) ListDirectory(remotePath string) ([]os.FileInfo, error) {
	entries, err := c.Client.ReadDir(remotePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote directory %s: %w", remotePath, err)
	}

	sort.Slice(entries, func(i, j int) bool {
		// Directories first
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})

	return entries, nil
}

// Stat returns file info for remote path.
func (c *SFTPClient) Stat(remotePath string) (os.FileInfo, error) {
	return c.Client.Stat(remotePath)
}

// Mkdir creates a directory.
func (c *SFTPClient) Mkdir(remotePath string) error {
	return c.Client.Mkdir(remotePath)
}

// MkdirAll creates a directory and any necessary parents.
func (c *SFTPClient) MkdirAll(remotePath string) error {
	return c.Client.MkdirAll(remotePath)
}

// Remove removes a single file or empty directory.
func (c *SFTPClient) Remove(remotePath string) error {
	return c.Client.Remove(remotePath)
}

// RemoveAll removes a remote path and all children recursively.
func (c *SFTPClient) RemoveAll(remotePath string) error {
	fi, err := c.Client.Stat(remotePath)
	if err != nil {
		return err
	}

	if !fi.IsDir() {
		return c.Client.Remove(remotePath)
	}

	entries, err := c.Client.ReadDir(remotePath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		subPath := path.Join(remotePath, entry.Name())
		if err := c.RemoveAll(subPath); err != nil {
			return err
		}
	}

	return c.Client.RemoveDirectory(remotePath)
}

// Rename renames or moves a remote file or directory.
func (c *SFTPClient) Rename(oldPath, newPath string) error {
	return c.Client.Rename(oldPath, newPath)
}

// CopyFile copies a remote file to another remote location.
func (c *SFTPClient) CopyFile(src, dst string) error {
	srcFile, err := c.Client.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open remote source file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := c.Client.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create remote destination file: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy remote file data: %w", err)
	}

	return nil
}
