package config

import (
	"os"
	"path/filepath"
)

const (
	DefaultRelayURL = "wss://relay.trml.app"
	DefaultLogLevel = "info"
	AppName         = "trml"
	ConfigFileName  = "config.yaml"
	PIDFileName     = "daemon.pid"
	StatusFileName  = "status.json"
	LaunchdLabel    = "com.trml.daemon"
	SystemdUnitName = "trml-daemon"
)

func ConfigDir() string {
	if dir := os.Getenv("TRML_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join("/tmp", ".config", AppName)
	}
	return filepath.Join(home, ".config", AppName)
}

func ConfigPath() string {
	return filepath.Join(ConfigDir(), ConfigFileName)
}

func PIDPath() string {
	return filepath.Join(ConfigDir(), PIDFileName)
}

func StatusPath() string {
	return filepath.Join(ConfigDir(), StatusFileName)
}
