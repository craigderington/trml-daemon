package cmd

import (
	"github.com/spf13/cobra"

	"github.com/craigderington/trml-daemon/internal/service"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the trml daemon in the foreground",
	RunE: func(cmd *cobra.Command, args []string) error {
		return service.Run(cfg, log)
	},
}
