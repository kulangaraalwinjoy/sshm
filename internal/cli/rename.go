package cli

import (
	"fmt"
	"strings"

	"github.com/alwin/sshm/internal/cli/ui"
	"github.com/spf13/cobra"
)

func newRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <old-name> <new-name>",
		Short: "Rename an existing SSH profile",
		Long:  "Rename an SSH configuration profile while preserving its stored configuration and encrypted credentials.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldName := strings.TrimSpace(args[0])
			newName := strings.TrimSpace(args[1])

			if oldName == newName {
				return fmt.Errorf("old name and new name are identical")
			}

			// Ensure vault is unlocked if credentials exist so they are cleanly renamed in the vault
			_ = globalVault.EnsureUnlocked(promptVaultPassphrase)

			if err := globalVault.RenameProfile(oldName, newName); err != nil {
				return err
			}

			ui.PrintSuccess("Renamed SSH profile %q to %q (credentials preserved).", oldName, newName)
			return nil
		},
	}

	return cmd
}
