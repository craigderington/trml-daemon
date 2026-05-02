package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/craigderington/trml-daemon/internal/config"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running trml daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(config.PIDPath())
		if os.IsNotExist(err) {
			fmt.Println("trml daemon is not running (no PID file)")
			return nil
		}
		if err != nil {
			return fmt.Errorf("read PID file: %w", err)
		}
		pidStr := strings.TrimSpace(string(data))
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return fmt.Errorf("invalid PID: %s", pidStr)
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("find process %d: %w", pid, err)
		}
		if err := proc.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("send SIGTERM to %d: %w", pid, err)
		}
		fmt.Printf("Sent SIGTERM to trml daemon (PID %d)\n", pid)
		return nil
	},
}
