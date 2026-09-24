package cli

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kulangaraalwinjoy/sshm/internal/cli/ui"
	"github.com/kulangaraalwinjoy/sshm/internal/knownhosts"
	"github.com/kulangaraalwinjoy/sshm/internal/ssh"
	"github.com/spf13/cobra"
)

func newTunnelCmd() *cobra.Command {
	var (
		localForwards  []string
		remoteForwards []string
		dynamicPort    string
	)

	cmd := &cobra.Command{
		Use:   "tunnel <name>",
		Short: "Establish an SSH port forwarding tunnel",
		Long: `Establish local, remote, or dynamic (SOCKS5) port forwarding tunnels through an SSH connection.
Example to connect remote port 80 to local port 8080:
  sshm tunnel production -L 8080:localhost:80
or simply:
  sshm tunnel production -L 8080:80`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])

			profile, err := globalVault.GetProfile(name)
			if err != nil {
				return err
			}

			// If no flags specified, check if profile has configured forwards
			allLocal := append([]string{}, profile.LocalForwards...)
			allLocal = append(allLocal, localForwards...)

			allRemote := append([]string{}, profile.RemoteForwards...)
			allRemote = append(allRemote, remoteForwards...)

			dynamic := dynamicPort
			if dynamic == "" {
				dynamic = profile.DynamicForward
			}

			if len(allLocal) == 0 && len(allRemote) == 0 && dynamic == "" {
				return fmt.Errorf("no port forwarding rules specified. Use -L local_port:remote_host:remote_port (e.g. -L 8080:localhost:80)")
			}

			// Retrieve credentials
			_ = globalVault.EnsureUnlocked(promptVaultPassphrase)
			creds, _ := globalVault.GetCredentials(name)

			verifier := knownhosts.NewHostKeyVerifier(profile.KnownHostsFile, profile.StrictHostKeyChecking, nil)

			ui.PrintSuccess("Connecting to %s...", profile.Name)
			client, err := ssh.Connect(profile, creds, verifier)
			if err != nil {
				return err
			}
			defer client.Close()

			tm := ssh.NewTunnelManager(client)
			defer tm.Stop()

			if err := tm.StartAll(allLocal, allRemote, dynamic); err != nil {
				return fmt.Errorf("failed to start tunnels: %w", err)
			}

			fmt.Println()
			fmt.Println(ui.Green("✓ SSH Tunnel is active and running."))
			fmt.Println("Press Ctrl+C to stop tunnel.")

			// Wait for termination signal
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
			<-sigChan

			fmt.Println("\nStopping tunnels and disconnecting...")
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&localForwards, "local", "L", nil, "Local forward: [bind:]local_port:remote_host:remote_port (e.g. 8080:localhost:80)")
	cmd.Flags().StringSliceVarP(&remoteForwards, "remote", "R", nil, "Remote forward: [bind:]remote_port:local_host:local_port")
	cmd.Flags().StringVarP(&dynamicPort, "dynamic", "D", "", "Dynamic SOCKS5 port forward (e.g. 1080)")

	return cmd
}
