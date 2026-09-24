package cli

import (
	"fmt"
	"strings"

	"github.com/kulangaraalwinjoy/sshm/internal/cli/ui"
	"github.com/spf13/cobra"
)

func newDeleteCmd() *cobra.Command {
	var skipConfirm bool

	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete an SSH profile and remove its stored credentials",
		Long:  "Delete an SSH profile. By default, requires typing the profile name to confirm deletion.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])

			// Verify profile exists
			_, err := globalVault.GetProfile(name)
			if err != nil {
				return err
			}

			if !skipConfirm {
				fmt.Printf("\n%s\n", ui.Yellow(fmt.Sprintf("Delete SSH profile %q?", name)))
				fmt.Println("This will permanently remove the profile and its stored credentials.")
				fmt.Println()
				enteredName, err := ui.PromptText("Type the profile name to confirm", "")
				if err != nil {
					return err
				}

				if strings.TrimSpace(enteredName) != name {
					fmt.Println("Confirmation name did not match. Deletion aborted.")
					return nil
				}
			}

			// Ensure vault is unlocked if credentials exist so they are wiped cleanly
			_ = globalVault.EnsureUnlocked(promptVaultPassphrase)

			if err := globalVault.DeleteProfile(name); err != nil {
				return err
			}

			ui.PrintSuccess("SSH profile %q deleted successfully.", name)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&skipConfirm, "yes", "y", false, "Skip interactive deletion confirmation")
	return cmd
}
