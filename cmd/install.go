package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/craigderington/trml-daemon/internal/service"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install trml daemon as a system service",
	RunE: func(cmd *cobra.Command, args []string) error {
		executable, err := os.Executable()
		if err != nil {
			return fmt.Errorf("find executable: %w", err)
		}

		switch runtime.GOOS {
		case "darwin":
			return service.InstallLaunchd(executable)
		case "linux":
			return service.InstallSystemd(executable)
		default:
			return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
		}
	},
}
