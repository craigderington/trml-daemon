package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/craigderington/trml-daemon/internal/config"
	"github.com/craigderington/trml-daemon/internal/crypto"
)

var (
	cfg     *config.Config
	log     *zap.Logger
	version = "dev"
)

var rootCmd = &cobra.Command{
	Use:     "trml-daemon",
	Short:   "trml — terminal over iPhone relay daemon",
	Long:    "trml-daemon connects your Mac/Linux machine to the trml iOS app via an E2E-encrypted relay.",
	Version: version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		cfg, _, err = config.Load(crypto.GenerateKeypairB64)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		level := zapcore.InfoLevel
		if cfg.LogLevel == "debug" {
			level = zapcore.DebugLevel
		}

		zapCfg := zap.NewProductionConfig()
		zapCfg.Level = zap.NewAtomicLevelAt(level)
		zapCfg.OutputPaths = []string{"stderr"}
		log, err = zapCfg.Build()
		if err != nil {
			return fmt.Errorf("build logger: %w", err)
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(pairCmd)
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
}
