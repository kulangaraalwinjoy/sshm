package cli

import (
	"strings"

	"github.com/alwin/sshm/internal/cli/ui"
	"github.com/alwin/sshm/internal/knownhosts"
	"github.com/alwin/sshm/internal/sftp"
	"github.com/alwin/sshm/internal/ssh"
	"github.com/alwin/sshm/internal/transfer"
	"github.com/spf13/cobra"
)

func newUploadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upload <name> <local-path> <remote-path>",
		Short: "Upload a file or directory to a remote server",
		Long: `Transfers a local file or recursive directory tree to the remote server over SFTP.
Displays a live streaming progress bar with transfer rate and ETA.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			localPath := args[1]
			remotePath := args[2]

			profile, err := globalVault.GetProfile(name)
			if err != nil {
				return err
			}

			_ = globalVault.EnsureUnlocked(promptVaultPassphrase)
			creds, _ := globalVault.GetCredentials(name)

			verifier := knownhosts.NewHostKeyVerifier(profile.KnownHostsFile, profile.StrictHostKeyChecking, nil)

			ui.PrintSuccess("Connecting to %s...", profile.Name)
			sshClient, err := ssh.Connect(profile, creds, verifier)
			if err != nil {
				return err
			}
			defer sshClient.Close()

			sftpClient, err := sftp.NewSFTPClient(sshClient.Client)
			if err != nil {
				return err
			}
			defer sftpClient.Close()

			engine := transfer.NewEngine(sftpClient.Client)
			if err := engine.Upload(localPath, remotePath); err != nil {
				return err
			}

			ui.PrintSuccess("Uploaded %s to %s:%s successfully.", localPath, profile.Name, remotePath)
			return nil
		},
	}

	return cmd
}

func newDownloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "download <name> <remote-path> <local-path>",
		Short: "Download a file or directory from a remote server",
		Long: `Downloads a remote file or recursive directory tree from the remote server over SFTP.
Displays a live streaming progress bar with transfer rate and ETA.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			remotePath := args[1]
			localPath := args[2]

			profile, err := globalVault.GetProfile(name)
			if err != nil {
				return err
			}

			_ = globalVault.EnsureUnlocked(promptVaultPassphrase)
			creds, _ := globalVault.GetCredentials(name)

			verifier := knownhosts.NewHostKeyVerifier(profile.KnownHostsFile, profile.StrictHostKeyChecking, nil)

			ui.PrintSuccess("Connecting to %s...", profile.Name)
			sshClient, err := ssh.Connect(profile, creds, verifier)
			if err != nil {
				return err
			}
			defer sshClient.Close()

			sftpClient, err := sftp.NewSFTPClient(sshClient.Client)
			if err != nil {
				return err
			}
			defer sftpClient.Close()

			engine := transfer.NewEngine(sftpClient.Client)
			if err := engine.Download(remotePath, localPath); err != nil {
				return err
			}

			ui.PrintSuccess("Downloaded %s:%s to %s successfully.", profile.Name, remotePath, localPath)
			return nil
		},
	}

	return cmd
}
