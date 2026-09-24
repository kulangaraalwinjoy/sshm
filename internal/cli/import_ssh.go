package cli

import (
	"fmt"

	"github.com/alwin/sshm/internal/cli/ui"
	"github.com/alwin/sshm/internal/sshconfig"
	"github.com/spf13/cobra"
)

func newImportCmd() *cobra.Command {
	var (
		skipConfirm bool
		overwrite   bool
	)

	cmd := &cobra.Command{
		Use:   "import [path-to-ssh-config]",
		Short: "Import existing hosts from an OpenSSH configuration file",
		Long: `Parses an OpenSSH ~/.ssh/config file, displays a preview of discovered hosts, 
and imports the configurations into SSHM profiles without modifying the original file.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := ""
			if len(args) == 1 {
				configPath = args[0]
			}

			profiles, err := sshconfig.ParseSSHConfig(configPath)
			if err != nil {
				return err
			}

			if len(profiles) == 0 {
				fmt.Println("No valid SSH hosts found in configuration file.")
				return nil
			}

			fmt.Printf("Found %d SSH hosts:\n\n", len(profiles))
			for i, p := range profiles {
				fmt.Printf("%d. %-18s (%s:%d, user: %s)\n", i+1, ui.Bold(p.Name), p.Host, p.Port, p.Username)
			}
			fmt.Println()

			if !skipConfirm {
				confirm, err := ui.PromptConfirm("Import discovered profiles?", true)
				if err != nil || !confirm {
					fmt.Println("Import aborted.")
					return nil
				}
			}

			imported := 0
			skipped := 0
			for _, p := range profiles {
				existing, _ := globalVault.GetProfile(p.Name)
				if existing != nil && !overwrite {
					skipped++
					continue
				}

				if err := globalVault.SaveProfile(p); err != nil {
					ui.PrintWarning("Failed to import %q: %v", p.Name, err)
					continue
				}
				imported++
			}

			ui.PrintSuccess("Import complete: %d imported, %d skipped.", imported, skipped)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&skipConfirm, "yes", "y", false, "Skip interactive confirmation prompt")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing profiles with identical names")

	return cmd
}
