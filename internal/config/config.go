package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type Device struct {
	DeviceID   string `yaml:"device_id"`
	PublicKey  string `yaml:"public_key"` // base64 X25519
	DeviceName string `yaml:"device_name"`
	APNsToken  string `yaml:"apns_token,omitempty"` // hex APNs device token, set after pairing
}

// APNsConfig holds Apple Push Notification credentials for the daemon.
// All fields must be non-empty to enable push notifications.
// KeyPath points to an Apple-issued .p8 auth key file.
type APNsConfig struct {
	KeyPath  string `yaml:"key_path"`  // path to AuthKey_XXXXXXXXXX.p8
	KeyID    string `yaml:"key_id"`    // 10-char key ID from Apple Developer portal
	TeamID   string `yaml:"team_id"`   // 10-char Apple Team ID
	Sandbox  bool   `yaml:"sandbox"`   // true = APNs sandbox (development), false = production
}

// IsConfigured returns true when all required APNs fields are present.
func (a APNsConfig) IsConfigured() bool {
	return a.KeyPath != "" && a.KeyID != "" && a.TeamID != ""
}

// Current config schema version. Bump this whenever the config struct changes.
const ConfigVersion = "1"

type Config struct {
	Version            string     `yaml:"version,omitempty"` // schema version, e.g. "1"
	DeviceID           string     `yaml:"device_id"`
	PrivateKey         string     `yaml:"private_key"` // base64 X25519
	RelayURL           string     `yaml:"relay_url"`
	PairedDevices      []Device   `yaml:"paired_devices"`
	LogLevel           string     `yaml:"log_level"`
	RawShellMode       bool       `yaml:"raw_shell_mode,omitempty"`       // when true, skip all validation
	CommandTimeoutSecs int        `yaml:"command_timeout_seconds,omitempty"`
	// AllowedCommands lists additional commands to permit beyond the built-in defaults.
	// Example: allowed_commands: [htop, btop, mycli, terraform]
	AllowedCommands    []string   `yaml:"allowed_commands,omitempty"`
	APNs               APNsConfig `yaml:"apns,omitempty"`
}

// Migrate upgrades older config versions to the current schema.
// It is backward-compatible: configs without a Version field are treated as v0.
func (c *Config) Migrate() {
	switch c.Version {
	case "":
		// v0 — no version field present; apply all migrations.
		c.CommandTimeoutSecs = 300 // default 5-minute command timeout
		fallthrough
	case "1":
		// v1 is current; nothing to do.
	default:
		// Unknown version — keep existing data, log a warning (caller decides).
	}
	c.Version = ConfigVersion
}

// IsMigrated returns true if the config has been migrated to the latest schema.
func (c *Config) IsMigrated() bool {
	return c.Version == ConfigVersion
}

// Load reads config from disk, calling InitFirstRun if absent.
// The caller must pass a keypair generator to avoid import cycles.
func Load(generateKeypair func() (privB64, pubB64 string, err error)) (*Config, bool, error) {
	path := ConfigPath()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		cfg, err := InitFirstRun(generateKeypair)
		if err != nil {
			return nil, false, fmt.Errorf("init first run: %w", err)
		}
		return cfg, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, false, fmt.Errorf("parse config: %w", err)
	}

	// Migrate old configs to the current schema (backward-compatible).
	cfg.Migrate()

	if cfg.RelayURL == "" {
		cfg.RelayURL = DefaultRelayURL
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = DefaultLogLevel
	}
	return &cfg, false, nil
}

// Save writes config to disk atomically.
func Save(cfg *Config) error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp := filepath.Join(dir, ".config.yaml.tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write tmp config: %w", err)
	}
	return os.Rename(tmp, ConfigPath())
}

// InitFirstRun generates a new identity and saves the initial config.
func InitFirstRun(generateKeypair func() (privB64, pubB64 string, err error)) (*Config, error) {
	privB64, _, err := generateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	cfg := &Config{
		Version:            ConfigVersion,
		DeviceID:           uuid.New().String(),
		PrivateKey:         privB64,
		RelayURL:           DefaultRelayURL,
		LogLevel:           DefaultLogLevel,
		CommandTimeoutSecs: 300, // default 5-minute command timeout
	}
	if err := Save(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// AddPairedDevice appends a device and saves.
func (c *Config) AddPairedDevice(d Device) error {
	for i, existing := range c.PairedDevices {
		if existing.DeviceID == d.DeviceID {
			c.PairedDevices[i] = d
			return Save(c)
		}
	}
	c.PairedDevices = append(c.PairedDevices, d)
	return Save(c)
}

// FindDevice returns the paired device by ID, or nil.
func (c *Config) FindDevice(deviceID string) *Device {
	for i := range c.PairedDevices {
		if c.PairedDevices[i].DeviceID == deviceID {
			return &c.PairedDevices[i]
		}
	}
	return nil
}
