package cli

import (
	"fmt"
	"runtime"

	"github.com/kulangaraalwinjoy/sshm/internal/cli/ui"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display SSHM application version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%s %s\n", ui.Bold("SSHM - SSH/SFTP Manager"), Version)
			fmt.Printf("Commit:      %s\n", Commit)
			fmt.Printf("Build Date:  %s\n", BuildDate)
			fmt.Printf("Go Version:  %s\n", runtime.Version())
			fmt.Printf("OS/Arch:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}
