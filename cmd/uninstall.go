package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/craigderington/trml-daemon/internal/service"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the trml daemon service",
	RunE: func(cmd *cobra.Command, args []string) error {
		switch runtime.GOOS {
		case "darwin":
			return service.UninstallLaunchd()
		case "linux":
			return service.UninstallSystemd()
		default:
			return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
		}
	},
}
