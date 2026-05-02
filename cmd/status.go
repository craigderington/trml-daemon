package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/craigderington/trml-daemon/internal/config"
	"github.com/craigderington/trml-daemon/internal/service"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show trml daemon status",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(config.StatusPath())
		if os.IsNotExist(err) {
			fmt.Println("trml daemon: not running")
			return nil
		}
		if err != nil {
			return fmt.Errorf("read status: %w", err)
		}

		var s service.StatusJSON
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("parse status: %w", err)
		}

		connStr := "disconnected"
		if s.Connected {
			connStr = "connected"
		}

		// Check if PID file exists (daemon actually running)
		_, pidErr := os.ReadFile(config.PIDPath())
		runStr := "stopped"
		if pidErr == nil {
			runStr = "running"
		}

		fmt.Println(strings.Repeat("─", 40))
		fmt.Printf("  trml daemon status\n")
		fmt.Println(strings.Repeat("─", 40))
		fmt.Printf("  Process:      %s\n", runStr)
		fmt.Printf("  Relay:        %s\n", connStr)
		fmt.Printf("  Uptime:       %s\n", s.Uptime)
		fmt.Printf("  Paired:       %d device(s)\n", s.PairedCount)
		fmt.Printf("  Started:      %s\n", s.StartedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Last update:  %s\n", s.UpdatedAt.Format("2006-01-02 15:04:05"))
		fmt.Println(strings.Repeat("─", 40))
		return nil
	},
}
