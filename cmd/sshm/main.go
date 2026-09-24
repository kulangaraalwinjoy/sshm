package main

import (
	"os"

	"github.com/kulangaraalwinjoy/sshm/internal/cli"
)

func main() {
	exitCode := cli.Execute()
	os.Exit(exitCode)
}
