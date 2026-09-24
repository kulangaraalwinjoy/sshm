package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kulangaraalwinjoy/sshm/internal/cli/ui"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all configured SSH server profiles",
		Long:  "Display all configured SSH profiles with host, port, username, and authentication type. Secrets are never shown.",
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := getVault()
			if err != nil {
				return err
			}
			profiles, err := v.ListProfiles()
			if err != nil {
				return err
			}

			if jsonOutput {
				// Clean JSON output without secrets
				data, err := json.MarshalIndent(profiles, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to format JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			if len(profiles) == 0 {
				fmt.Println("No SSH profiles configured yet. Add one with 'sshm add <name>' or import with 'sshm import'.")
				return nil
			}

			headers := []string{"NAME", "HOST", "PORT", "USER", "AUTH", "PROXY"}
			rows := make([][]string, len(profiles))

			for i, p := range profiles {
				authStr := strings.ToUpper(string(p.AuthMethod))
				if p.AuthMethod == "key" && p.KeyInVault {
					authStr = "KEY (VAULT)"
				}

				proxyStr := "-"
				if p.ProxyJump != "" {
					proxyStr = "jump:" + p.ProxyJump
				} else if p.ProxyCommand != "" {
					proxyStr = "command"
				}

				rows[i] = []string{
					p.Name,
					p.Host,
					strconv.Itoa(p.Port),
					p.Username,
					authStr,
					proxyStr,
				}
			}

			ui.PrintTable(os.Stdout, headers, rows)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output profile list in JSON format (excluding secrets)")
	return cmd
}
