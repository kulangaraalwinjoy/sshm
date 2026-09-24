package cli

import (
	"fmt"

	"github.com/alwin/sshm/internal/cli/ui"
	"github.com/alwin/sshm/internal/config"
	"github.com/alwin/sshm/internal/logging"
	"github.com/alwin/sshm/internal/vault"
	"github.com/spf13/cobra"
)

var (
	// Version is populated at compile time via -ldflags
	Version   = "1.0.0"
	Commit    = "none"
	BuildDate = "unknown"

	debugFlag  bool
	configFlag string
	plainFlag  bool

	globalVault *vault.Vault
)

// NewRootCmd creates the root Cobra command for SSHM.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "sshm",
		Short: "SSHM - Secure Cross-Platform SSH & SFTP Manager",
		Long: `SSHM is a secure, production-ready SSH and SFTP manager for Windows, macOS, and Linux.
It provides encrypted credential storage, interactive terminal shells, 
resilient streaming file transfers, port forwarding tunnels, and OpenSSH config import.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if debugFlag {
				logging.SetDebug(true)
				logging.Debugf("Debug logging enabled (version %s)", Version)
			}
			if plainFlag {
				ui.SetPlain(true)
			}
			if configFlag != "" {
				config.SetCustomConfigDir(configFlag)
			}

			// Don't require vault for help, version, or completion
			cmdName := cmd.Name()
			if cmdName == "version" || cmdName == "help" || cmdName == "completion" || cmdName == "sshm" {
				return nil
			}

			_, err := getVault()
			if err != nil {
				return err
			}
			return nil
		},
	}

	rootCmd.PersistentFlags().BoolVar(&debugFlag, "debug", false, "Enable verbose diagnostic logging (credentials redacted)")
	rootCmd.PersistentFlags().StringVar(&configFlag, "config", "", "Custom configuration directory (default: ~/.sshm)")
	rootCmd.PersistentFlags().BoolVar(&plainFlag, "plain", false, "Disable ANSI colors and Unicode symbols for plain output")

	// Version flag
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, date: %s)", Version, Commit, BuildDate)
	rootCmd.SetVersionTemplate("sshm version {{.Version}}\n")

	// Register subcommands
	rootCmd.AddCommand(newListCmd())
	rootCmd.AddCommand(newAddCmd())
	rootCmd.AddCommand(newEditCmd())
	rootCmd.AddCommand(newRenameCmd())
	rootCmd.AddCommand(newDeleteCmd())
	rootCmd.AddCommand(newOpenCmd())
	rootCmd.AddCommand(newShellCmd())
	rootCmd.AddCommand(newTunnelCmd())
	rootCmd.AddCommand(newFilesCmd())
	rootCmd.AddCommand(newUploadCmd())
	rootCmd.AddCommand(newDownloadCmd())
	rootCmd.AddCommand(newVaultCmd())
	rootCmd.AddCommand(newImportCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

// Execute runs the root command and returns the exit code.
func Execute() int {
	rootCmd := NewRootCmd()
	if err := rootCmd.Execute(); err != nil {
		ui.PrintError("%v", err)
		return 1
	}
	return 0
}

// getVault returns the lazily initialized global vault instance.
func getVault() (*vault.Vault, error) {
	if globalVault != nil {
		return globalVault, nil
	}
	v, err := vault.NewVault(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize vault subsystem: %w", err)
	}
	globalVault = v
	return globalVault, nil
}

// promptVaultPassphrase prompts the user for the vault master passphrase when locked.
func promptVaultPassphrase() (string, error) {
	fmt.Println(ui.Yellow("Vault is locked."))
	return ui.PromptPassword("Enter Master Vault Passphrase")
}
