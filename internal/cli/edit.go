package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/kulangaraalwinjoy/sshm/internal/cli/ui"
	"github.com/kulangaraalwinjoy/sshm/pkg/models"
	"github.com/spf13/cobra"
)

func newEditCmd() *cobra.Command {
	var (
		flagHost       string
		flagPort       int
		flagUser       string
		flagAuth       string
		flagKeyPath    string
		flagProxyJump  string
		flagTimeout    int
		flagPassword   bool // boolean flag that triggers secure hidden prompt!
		flagPassphrase bool // boolean flag that triggers secure hidden prompt!
	)

	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit an existing SSH server configuration profile",
		Long: `Edit an existing SSH server profile either interactively or via command-line flags.
Sensitive credentials like --password or --passphrase are securely prompted and never accepted as plain arguments.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])

			profile, err := globalVault.GetProfile(name)
			if err != nil {
				return err
			}

			// Check if any non-interactive flags were supplied
			hasFlags := cmd.Flags().Changed("host") ||
				cmd.Flags().Changed("port") ||
				cmd.Flags().Changed("user") ||
				cmd.Flags().Changed("auth") ||
				cmd.Flags().Changed("key-path") ||
				cmd.Flags().Changed("proxy-jump") ||
				cmd.Flags().Changed("timeout") ||
				flagPassword || flagPassphrase

			if hasFlags {
				return applyFlagsAndSave(profile, flagHost, flagPort, flagUser, flagAuth, flagKeyPath, flagProxyJump, flagTimeout, flagPassword, flagPassphrase, cmd)
			}

			// Interactive editor menu
			return runInteractiveEditor(profile)
		},
	}

	cmd.Flags().StringVar(&flagHost, "host", "", "New host or IP address")
	cmd.Flags().IntVar(&flagPort, "port", 0, "New SSH port number")
	cmd.Flags().StringVar(&flagUser, "user", "", "New SSH username")
	cmd.Flags().StringVar(&flagAuth, "auth", "", "Authentication method ('key', 'password', 'agent')")
	cmd.Flags().StringVar(&flagKeyPath, "key-path", "", "Path to private key file")
	cmd.Flags().StringVar(&flagProxyJump, "proxy-jump", "", "ProxyJump specification")
	cmd.Flags().IntVar(&flagTimeout, "timeout", 0, "Connection timeout in seconds")
	cmd.Flags().BoolVar(&flagPassword, "password", false, "Securely prompt for a new password without displaying it")
	cmd.Flags().BoolVar(&flagPassphrase, "passphrase", false, "Securely prompt for a new private key passphrase without displaying it")

	return cmd
}

func applyFlagsAndSave(
	p *models.SSHProfile,
	host string,
	port int,
	user string,
	auth string,
	keyPath string,
	proxyJump string,
	timeout int,
	promptPass bool,
	promptPassphrase bool,
	cmd *cobra.Command,
) error {
	if cmd.Flags().Changed("host") {
		p.Host = host
	}
	if cmd.Flags().Changed("port") {
		p.Port = port
	}
	if cmd.Flags().Changed("user") {
		p.Username = user
	}
	if cmd.Flags().Changed("auth") {
		p.AuthMethod = models.AuthMethod(strings.ToLower(auth))
	}
	if cmd.Flags().Changed("key-path") {
		p.KeyPath = keyPath
	}
	if cmd.Flags().Changed("proxy-jump") {
		p.ProxyJump = proxyJump
	}
	if cmd.Flags().Changed("timeout") {
		p.ConnectTimeout = timeout
	}

	if err := p.Validate(); err != nil {
		return err
	}

	if err := globalVault.SaveProfile(p); err != nil {
		return fmt.Errorf("failed to save profile: %w", err)
	}

	// Update credentials if requested
	if promptPass || promptPassphrase {
		if err := globalVault.EnsureUnlocked(promptVaultPassphrase); err != nil {
			return err
		}
		creds, _ := globalVault.GetCredentials(p.Name)
		if creds == nil {
			creds = &models.ProfileCredentials{}
		}

		if promptPass {
			newPass, err := ui.PromptPassword(fmt.Sprintf("Enter new password for %s", p.Name))
			if err != nil {
				return err
			}
			creds.Password = newPass
		}

		if promptPassphrase {
			newPp, err := ui.PromptPassword(fmt.Sprintf("Enter new passphrase for %s", p.Name))
			if err != nil {
				return err
			}
			creds.Passphrase = newPp
		}

		if err := globalVault.SetCredentials(p.Name, creds); err != nil {
			return fmt.Errorf("failed to save updated credentials: %w", err)
		}
	}

	ui.PrintSuccess("SSH configuration %q updated successfully.", p.Name)
	return nil
}

func runInteractiveEditor(p *models.SSHProfile) error {
	for {
		fmt.Printf("\n%s %s\n\n", ui.Bold("SSH Configuration:"), ui.Cyan(p.Name))
		fmt.Printf("1.  Name:                  %s\n", p.Name)
		fmt.Printf("2.  Host:                  %s\n", p.Host)
		fmt.Printf("3.  Port:                  %d\n", p.Port)
		fmt.Printf("4.  Username:              %s\n", p.Username)
		fmt.Printf("5.  Authentication:        %s\n", p.AuthMethod)
		fmt.Printf("6.  Private Key:           %s\n", p.KeyPath)
		fmt.Printf("7.  Passphrase:            [PROTECTED IN VAULT]\n")
		fmt.Printf("8.  Password:              [PROTECTED IN VAULT]\n")
		fmt.Printf("9.  ProxyJump:             %s\n", p.ProxyJump)
		fmt.Printf("10. Connection Timeout:    %ds\n", p.ConnectTimeout)
		fmt.Printf("11. Keep Alive Interval:   %ds\n", p.ServerAliveInterval)
		fmt.Printf("12. Forward Agent:         %v\n", p.ForwardAgent)
		fmt.Printf("13. Strict Host Checking:  %s\n", p.StrictHostKeyChecking)
		fmt.Println()
		fmt.Println("Select field [1-13]")
		fmt.Println("S = Save and Exit")
		fmt.Println("Q = Quit without Saving")

		choice, err := ui.PromptText("Choice", "")
		if err != nil {
			return err
		}

		choice = strings.ToUpper(strings.TrimSpace(choice))
		if choice == "Q" {
			fmt.Println("Quit without saving.")
			return nil
		}
		if choice == "S" {
			if err := p.Validate(); err != nil {
				ui.PrintError("Validation error: %v", err)
				continue
			}
			if err := globalVault.SaveProfile(p); err != nil {
				return fmt.Errorf("failed to save profile: %w", err)
			}
			ui.PrintSuccess("Profile %q saved.", p.Name)
			return nil
		}

		switch choice {
		case "1":
			newName, _ := ui.PromptText("Name", p.Name)
			if newName != "" && newName != p.Name {
				if err := globalVault.RenameProfile(p.Name, newName); err != nil {
					ui.PrintError("Rename failed: %v", err)
				} else {
					p.Name = newName
					ui.PrintSuccess("Renamed to %s", newName)
				}
			}
		case "2":
			p.Host, _ = ui.PromptText("Host", p.Host)
		case "3":
			portStr, _ := ui.PromptText("Port", strconv.Itoa(p.Port))
			if port, err := strconv.Atoi(portStr); err == nil && port > 0 {
				p.Port = port
			}
		case "4":
			p.Username, _ = ui.PromptText("Username", p.Username)
		case "5":
			idx, _ := ui.PromptSelect("Authentication:", []string{"Private Key", "Password", "SSH Agent"}, 0)
			switch idx {
			case 0:
				p.AuthMethod = models.AuthMethodKey
			case 1:
				p.AuthMethod = models.AuthMethodPassword
			case 2:
				p.AuthMethod = models.AuthMethodAgent
			}
		case "6":
			p.KeyPath, _ = ui.PromptText("Private Key Path", p.KeyPath)
		case "7":
			if err := globalVault.EnsureUnlocked(promptVaultPassphrase); err == nil {
				newPassphrase, _ := ui.PromptPassword("New Key Passphrase")
				creds, _ := globalVault.GetCredentials(p.Name)
				if creds == nil {
					creds = &models.ProfileCredentials{}
				}
				creds.Passphrase = newPassphrase
				_ = globalVault.SetCredentials(p.Name, creds)
				ui.PrintSuccess("Key passphrase updated.")
			}
		case "8":
			if err := globalVault.EnsureUnlocked(promptVaultPassphrase); err == nil {
				newPass, _ := ui.PromptPassword("New Password")
				creds, _ := globalVault.GetCredentials(p.Name)
				if creds == nil {
					creds = &models.ProfileCredentials{}
				}
				creds.Password = newPass
				_ = globalVault.SetCredentials(p.Name, creds)
				ui.PrintSuccess("Password updated.")
			}
		case "9":
			p.ProxyJump, _ = ui.PromptText("ProxyJump", p.ProxyJump)
		case "10":
			tStr, _ := ui.PromptText("Connect Timeout (s)", strconv.Itoa(p.ConnectTimeout))
			if t, err := strconv.Atoi(tStr); err == nil {
				p.ConnectTimeout = t
			}
		case "11":
			kStr, _ := ui.PromptText("Server Alive Interval (s)", strconv.Itoa(p.ServerAliveInterval))
			if k, err := strconv.Atoi(kStr); err == nil {
				p.ServerAliveInterval = k
			}
		case "12":
			p.ForwardAgent, _ = ui.PromptConfirm("Forward Agent?", p.ForwardAgent)
		case "13":
			idx, _ := ui.PromptSelect("Strict Host Key Checking:", []string{"ask", "yes", "no", "accept-new"}, 0)
			opts := []string{"ask", "yes", "no", "accept-new"}
			p.StrictHostKeyChecking = opts[idx]
		}
	}
}
