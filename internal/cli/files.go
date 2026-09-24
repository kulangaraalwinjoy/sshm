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

func newFilesCmd() *cobra.Command {
	var initialPath string

	cmd := &cobra.Command{
		Use:   "files <name> [initial-path]",
		Short: "Launch interactive SFTP remote file browser",
		Long: `Connects via SFTP and launches an interactive remote terminal file manager.
Navigate directories, upload, download, delete, rename, and manage files on the remote server.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if len(args) == 2 {
				initialPath = args[1]
			}

			profile, err := globalVault.GetProfile(name)
			if err != nil {
				return err
			}

			_ = globalVault.EnsureUnlocked(promptVaultPassphrase)
			creds, _ := globalVault.GetCredentials(name)

			verifier := knownhosts.NewHostKeyVerifier(profile.KnownHostsFile, profile.StrictHostKeyChecking, nil)

			ui.PrintSuccess("Connecting to %s via SSH/SFTP...", profile.Name)
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

			browser, err := sftp.NewFileBrowser(profile.Name, sftpClient, initialPath)
			if err != nil {
				return err
			}

			transferEngine := transfer.NewEngine(sftpClient.Client)

			// Handlers for upload and download initiated from the browser
			uploadHandler := func(localFile, remoteDest string) error {
				return transferEngine.Upload(localFile, remoteDest)
			}
			downloadHandler := func(remoteFile, localDest string) error {
				return transferEngine.Download(remoteFile, localDest)
			}

			return browser.RunInteractive(uploadHandler, downloadHandler)
		},
	}

	return cmd
}
