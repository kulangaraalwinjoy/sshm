package cli

import (
	"os"
	"strings"

	"github.com/alwin/sshm/internal/cli/ui"
	"github.com/alwin/sshm/internal/knownhosts"
	"github.com/alwin/sshm/internal/ssh"
	"github.com/spf13/cobra"
)

func newOpenCmd() *cobra.Command {
	var (
		localForwards  []string
		remoteForwards []string
	)

	cmd := &cobra.Command{
		Use:   "open <name>",
		Short: "Open an interactive SSH session to a server",
		Long: `Connects to the specified SSH server using stored credentials, allocates an interactive terminal (PTY), 
and connects your current terminal session. Also supports on-the-fly port forwarding.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			exitCode, err := runConnect(name, localForwards, remoteForwards)
			if err != nil {
				return err
			}
			if exitCode != 0 {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&localForwards, "local-forward", "L", nil, "Local port forward: [bind:]local_port:remote_host:remote_port")
	cmd.Flags().StringSliceVarP(&remoteForwards, "remote-forward", "R", nil, "Remote port forward: [bind:]remote_port:local_host:local_port")

	return cmd
}

func newShellCmd() *cobra.Command {
	var (
		localForwards  []string
		remoteForwards []string
	)

	cmd := &cobra.Command{
		Use:   "shell <name>",
		Short: "Explicitly open an interactive shell session (alias for 'open')",
		Long:  "Explicit alias for 'sshm open <name>' to start an interactive SSH shell session.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			exitCode, err := runConnect(name, localForwards, remoteForwards)
			if err != nil {
				return err
			}
			if exitCode != 0 {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&localForwards, "local-forward", "L", nil, "Local port forward: [bind:]local_port:remote_host:remote_port")
	cmd.Flags().StringSliceVarP(&remoteForwards, "remote-forward", "R", nil, "Remote port forward: [bind:]remote_port:local_host:local_port")

	return cmd
}

func runConnect(name string, localForwards, remoteForwards []string) (int, error) {
	profile, err := globalVault.GetProfile(name)
	if err != nil {
		return 1, err
	}

	// Retrieve credentials from vault
	_ = globalVault.EnsureUnlocked(promptVaultPassphrase)
	creds, _ := globalVault.GetCredentials(name)

	// Prepare known_hosts verifier
	verifier := knownhosts.NewHostKeyVerifier(profile.KnownHostsFile, profile.StrictHostKeyChecking, nil)

	// Connect SSH client
	client, err := ssh.Connect(profile, creds, verifier)
	if err != nil {
		return 1, err
	}
	defer client.Close()

	// Combine profile-configured forwards with CLI command flags
	allLocal := append([]string{}, profile.LocalForwards...)
	allLocal = append(allLocal, localForwards...)

	allRemote := append([]string{}, profile.RemoteForwards...)
	allRemote = append(allRemote, remoteForwards...)

	// Start tunnels if any specified
	if len(allLocal) > 0 || len(allRemote) > 0 || profile.DynamicForward != "" {
		tm := ssh.NewTunnelManager(client)
		defer tm.Stop()

		if err := tm.StartAll(allLocal, allRemote, profile.DynamicForward); err != nil {
			ui.PrintWarning("Failed to establish some port forwards: %v", err)
		}
	}

	// Start interactive PTY session
	return client.InteractiveSession()
}
