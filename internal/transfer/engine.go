package transfer

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/alwin/sshm/internal/cli/ui"
	"github.com/alwin/sshm/internal/logging"
	"github.com/pkg/sftp"
)

const bufferSize = 64 * 1024 // 64 KB streaming buffer

// Engine coordinates upload and download operations over SFTP.
type Engine struct {
	client *sftp.Client
}

// NewEngine creates a new TransferEngine with an active SFTP client.
func NewEngine(client *sftp.Client) *Engine {
	return &Engine{client: client}
}

// Upload transfers a local file or directory to a remote destination.
func (e *Engine) Upload(localPath, remoteDest string) error {
	localPath = filepath.Clean(localPath)
	fi, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("local path error: %w", err)
	}

	if fi.IsDir() {
		return e.uploadDirectory(localPath, remoteDest)
	}

	return e.uploadSingleFile(localPath, remoteDest, fi)
}

func (e *Engine) uploadSingleFile(localPath, remoteDest string, fi os.FileInfo) error {
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file %q: %w", localPath, err)
	}
	defer localFile.Close()

	// Determine final remote target path
	targetRemotePath := remoteDest
	if rFi, err := e.client.Stat(remoteDest); err == nil && rFi.IsDir() {
		targetRemotePath = path.Join(remoteDest, filepath.Base(localPath))
	} else if strings.HasSuffix(remoteDest, "/") || strings.HasSuffix(remoteDest, "\\") {
		_ = e.client.MkdirAll(remoteDest)
		targetRemotePath = path.Join(remoteDest, filepath.Base(localPath))
	}

	// Ensure remote parent directory exists
	remoteDir := path.Dir(targetRemotePath)
	if remoteDir != "." && remoteDir != "/" {
		_ = e.client.MkdirAll(remoteDir)
	}

	remoteFile, err := e.client.Create(targetRemotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file %q: %w", targetRemotePath, err)
	}
	defer remoteFile.Close()

	pb := ui.NewProgressBar("Uploading", filepath.Base(localPath), fi.Size())
	countingReader := &countingReader{
		reader:     localFile,
		onProgress: pb.Update,
	}

	buf := make([]byte, bufferSize)
	_, err = io.CopyBuffer(remoteFile, countingReader, buf)
	if err != nil {
		return fmt.Errorf("upload streaming failed: %w", err)
	}

	pb.Finish()
	_ = e.client.Chmod(targetRemotePath, fi.Mode())

	return nil
}

func (e *Engine) uploadDirectory(localDir, remoteDest string) error {
	baseDirName := filepath.Base(localDir)
	targetBaseRemote := path.Join(remoteDest, baseDirName)

	logging.Infof("Uploading directory tree: %s -> %s", localDir, targetBaseRemote)

	return filepath.Walk(localDir, func(currentLocal string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(localDir, currentLocal)
		if err != nil {
			return err
		}

		// Convert local OS path separators to standard SFTP /
		remoteRel := filepath.ToSlash(relPath)
		remoteCurrent := path.Join(targetBaseRemote, remoteRel)

		if info.IsDir() {
			return e.client.MkdirAll(remoteCurrent)
		}

		return e.uploadSingleFile(currentLocal, remoteCurrent, info)
	})
}

// Download transfers a remote file or directory to a local destination.
func (e *Engine) Download(remotePath, localDest string) error {
	remotePath = path.Clean(remotePath)
	rFi, err := e.client.Stat(remotePath)
	if err != nil {
		return fmt.Errorf("remote path error: %w", err)
	}

	if rFi.IsDir() {
		return e.downloadDirectory(remotePath, localDest)
	}

	return e.downloadSingleFile(remotePath, localDest, rFi)
}

func (e *Engine) downloadSingleFile(remotePath, localDest string, rFi os.FileInfo) error {
	remoteFile, err := e.client.Open(remotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file %q: %w", remotePath, err)
	}
	defer remoteFile.Close()

	targetLocalPath := localDest
	if lFi, err := os.Stat(localDest); err == nil && lFi.IsDir() {
		targetLocalPath = filepath.Join(localDest, path.Base(remotePath))
	} else if strings.HasSuffix(localDest, "/") || strings.HasSuffix(localDest, "\\") {
		_ = os.MkdirAll(localDest, 0755)
		targetLocalPath = filepath.Join(localDest, path.Base(remotePath))
	}

	// Ensure local parent dir exists
	localDir := filepath.Dir(targetLocalPath)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return fmt.Errorf("failed to create local directory: %w", err)
	}

	localFile, err := os.OpenFile(targetLocalPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, rFi.Mode())
	if err != nil {
		return fmt.Errorf("failed to create local file %q: %w", targetLocalPath, err)
	}
	defer localFile.Close()

	pb := ui.NewProgressBar("Downloading", path.Base(remotePath), rFi.Size())
	countingReader := &countingReader{
		reader:     remoteFile,
		onProgress: pb.Update,
	}

	buf := make([]byte, bufferSize)
	_, err = io.CopyBuffer(localFile, countingReader, buf)
	if err != nil {
		return fmt.Errorf("download streaming failed: %w", err)
	}

	pb.Finish()
	return nil
}

func (e *Engine) downloadDirectory(remoteDir, localDest string) error {
	baseName := path.Base(remoteDir)
	localBaseDir := filepath.Join(localDest, baseName)

	logging.Infof("Downloading remote directory tree: %s -> %s", remoteDir, localBaseDir)

	walker := e.client.Walk(remoteDir)
	for walker.Step() {
		if walker.Err() != nil {
			return walker.Err()
		}

		currentRemote := walker.Path()
		rel, err := filepath.Rel(filepath.FromSlash(remoteDir), filepath.FromSlash(currentRemote))
		if err != nil {
			return err
		}

		currentLocal := filepath.Join(localBaseDir, rel)
		stat := walker.Stat()

		if stat.IsDir() {
			if err := os.MkdirAll(currentLocal, 0755); err != nil {
				return err
			}
		} else {
			if err := e.downloadSingleFile(currentRemote, currentLocal, stat); err != nil {
				return err
			}
		}
	}

	return nil
}

// countingReader wraps io.Reader and triggers progress callback on read.
type countingReader struct {
	reader      io.Reader
	transferred int64
	onProgress  func(int64)
}

func (r *countingReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 {
		r.transferred += int64(n)
		if r.onProgress != nil {
			r.onProgress(r.transferred)
		}
	}
	return n, err
}
