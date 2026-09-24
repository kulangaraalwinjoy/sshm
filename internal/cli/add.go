package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/alwin/sshm/internal/cli/ui"
	"github.com/alwin/sshm/pkg/models"
	"github.com/spf13/cobra"
)

func newAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a new SSH server configuration profile",
		Long:  "Interactive configuration wizard to create and securely save a new SSH server profile.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])

			v, err := getVault()
			if err != nil {
				return err
			}

			// Check if profile name already exists
			existing, _ := v.GetProfile(name)
			if existing != nil {
				return fmt.Errorf("profile %q already exists. Use 'sshm edit %s' to modify it", name, name)
			}

			fmt.Printf("%s %s\n\n", ui.Bold("SSH Profile:"), ui.Cyan(name))

			// Host
			host, err := ui.PromptText("Host/IP", "")
			if err != nil {
				return err
			}
			if host == "" {
				return fmt.Errorf("host/IP cannot be empty")
			}

			// Port
			portStr, err := ui.PromptText("Port", "22")
			if err != nil {
				return err
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port <= 0 || port > 65535 {
				return fmt.Errorf("invalid port: %s", portStr)
			}

			// Username
			defaultUser := "root"
			if u := os.Getenv("USER"); u != "" {
				defaultUser = u
			}
			username, err := ui.PromptText("Username", defaultUser)
			if err != nil {
				return err
			}

			// Auth method selection
			authOptions := []string{
				"Private Key",
				"Password",
				"SSH Agent",
			}
			authIdx, err := ui.PromptSelect("\nAuthentication:", authOptions, 0)
			if err != nil {
				return err
			}

			profile := models.NewSSHProfile(name, host, port, username)
			creds := &models.ProfileCredentials{}

			switch authIdx {
			case 0: // Private Key
				profile.AuthMethod = models.AuthMethodKey
				keyPath, err := ui.PromptText("Private Key Path", "~/.ssh/id_ed25519")
				if err != nil {
					return err
				}
				profile.KeyPath = keyPath

				storeInVault, _ := ui.PromptConfirm("Store key copy encrypted inside vault?", false)
				if storeInVault {
					expanded := models.ExpandHome(keyPath)
					keyData, err := os.ReadFile(expanded)
					if err != nil {
						return fmt.Errorf("failed to read private key at %q: %w", keyPath, err)
					}
					profile.KeyInVault = true
					creds.PrivateKey = keyData
				}

				hasPassphrase, _ := ui.PromptConfirm("Does this private key require a passphrase?", false)
				if hasPassphrase {
					passphrase, err := ui.PromptPassword("Key Passphrase")
					if err != nil {
						return err
					}
					creds.Passphrase = passphrase
				}

			case 1: // Password
				profile.AuthMethod = models.AuthMethodPassword
				savePassword, _ := ui.PromptConfirm("Save password in encrypted vault?", true)
				if savePassword {
					password, err := ui.PromptPassword("Password")
					if err != nil {
						return err
					}
					creds.Password = password
				}

			case 2: // SSH Agent
				profile.AuthMethod = models.AuthMethodAgent
			}

			// Save confirmation
			fmt.Println()
			confirm, err := ui.PromptConfirm("Save configuration?", true)
			if err != nil || !confirm {
				fmt.Println("Aborted.")
				return nil
			}

			// Ensure vault is initialized/unlocked to save credentials
			if !creds.IsEmpty() {
				if err := v.EnsureInitialized(promptVaultPassphrase); err != nil {
					return fmt.Errorf("failed to unlock vault: %w", err)
				}
			}

			// Save profile metadata
			if err := v.SaveProfile(profile); err != nil {
				return fmt.Errorf("failed to save profile: %w", err)
			}

			// Save credentials if any
			if !creds.IsEmpty() {
				if err := v.SetCredentials(name, creds); err != nil {
					return fmt.Errorf("failed to save credentials: %w", err)
				}
			}

			ui.PrintSuccess("SSH configuration %q saved securely.", name)
			return nil
		},
	}

	return cmd
}
