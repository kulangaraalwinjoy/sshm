package cli

import (
	"fmt"

	"github.com/alwin/sshm/internal/cli/ui"
	"github.com/spf13/cobra"
)

func newVaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage the secure credentials vault",
		Long:  "Commands to check vault status, lock, unlock, export encrypted backups, and import encrypted backups.",
	}

	cmd.AddCommand(newVaultStatusCmd())
	cmd.AddCommand(newVaultLockCmd())
	cmd.AddCommand(newVaultUnlockCmd())
	cmd.AddCommand(newVaultExportCmd())
	cmd.AddCommand(newVaultImportCmd())

	return cmd
}

func newVaultStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Display current security and lock status of the credential vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			status, err := globalVault.Status()
			if err != nil {
				return err
			}

			fmt.Println(ui.Bold("=== SSHM Vault Status ==="))
			if status.IsLocked {
				fmt.Printf("Lock Status:        %s\n", ui.Red("LOCKED"))
			} else {
				fmt.Printf("Lock Status:        %s\n", ui.Green("UNLOCKED"))
			}

			fmt.Printf("Profiles Stored:    %d\n", status.ProfileCount)

			keyringDesc := "Unavailable (passphrase prompt fallback active)"
			if status.KeyringAvailable {
				if status.KeyringActive {
					keyringDesc = ui.Green("Active (OS Keyring has master key)")
				} else {
					keyringDesc = ui.Yellow("Available (OS Keyring unlocked on demand)")
				}
			}
			fmt.Printf("OS Keyring:         %s\n", keyringDesc)
			fmt.Printf("Profiles Location:  %s\n", status.ProfilesPath)
			fmt.Printf("Encrypted Vault:    %s\n", status.VaultPath)

			return nil
		},
	}
}

func newVaultLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Lock the vault and clear credentials from memory and OS keyring",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := globalVault.Lock(); err != nil {
				return fmt.Errorf("failed to lock vault: %w", err)
			}
			ui.PrintSuccess("Vault locked. Master key cleared from memory and OS keyring.")
			return nil
		},
	}
}

func newVaultUnlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault using your master passphrase",
		RunE: func(cmd *cobra.Command, args []string) error {
			pass, err := ui.PromptPassword("Enter Master Vault Passphrase")
			if err != nil {
				return err
			}

			if err := globalVault.Unlock(pass); err != nil {
				return err
			}

			ui.PrintSuccess("Vault unlocked successfully.")
			return nil
		},
	}
}

func newVaultExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export <output-file.sshm>",
		Short: "Export an encrypted backup of profiles and credentials",
		Long:  "Creates an encrypted backup file using a dedicated export passphrase. The exported file remains strictly AES-256-GCM encrypted.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			destFile := args[0]

			// Ensure vault is unlocked
			if err := globalVault.EnsureUnlocked(promptVaultPassphrase); err != nil {
				return err
			}

			pass, err := ui.PromptPassword("Create a Passphrase for the Export Backup")
			if err != nil {
				return err
			}
			confirmPass, err := ui.PromptPassword("Confirm Backup Passphrase")
			if err != nil {
				return err
			}
			if pass != confirmPass {
				return fmt.Errorf("passphrases do not match")
			}

			if err := globalVault.ExportVault(destFile, pass); err != nil {
				return err
			}

			ui.PrintSuccess("Encrypted vault backup successfully exported to %s", destFile)
			return nil
		},
	}
}

func newVaultImportCmd() *cobra.Command {
	var overwrite bool

	cmd := &cobra.Command{
		Use:   "import <backup-file.sshm>",
		Short: "Import profiles and credentials from an encrypted backup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcFile := args[0]

			// Ensure vault is unlocked to receive credentials
			if err := globalVault.EnsureUnlocked(promptVaultPassphrase); err != nil {
				return err
			}

			pass, err := ui.PromptPassword("Enter Backup Decryption Passphrase")
			if err != nil {
				return err
			}

			imported, err := globalVault.ImportVault(srcFile, pass, overwrite)
			if err != nil {
				return err
			}

			ui.PrintSuccess("Successfully imported %d profiles from backup %s", imported, srcFile)
			return nil
		},
	}

	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing profiles with matching names")
	return cmd
}
