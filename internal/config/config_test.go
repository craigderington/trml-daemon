package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/craigderington/trml-daemon/internal/config"
)

// stub keypair generator used throughout config tests
func stubKeypair() (string, string, error) {
	return "cHJpdmF0ZWtleXBhZGRlZHRvMzJieXRlc2hlcmVYWA==", "cHVibGlja2V5cGFkZGVkdG8zMmJ5dGVzaGVyZVhY", nil
}

func TestConfigDir_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)
	if got := config.ConfigDir(); got != dir {
		t.Errorf("expected %s, got %s", dir, got)
	}
}

func TestConfigDir_Default(t *testing.T) {
	t.Setenv("TRML_CONFIG_DIR", "")
	dir := config.ConfigDir()
	if dir == "" {
		t.Error("ConfigDir should not be empty")
	}
}

func TestConfigPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)
	want := filepath.Join(dir, "config.yaml")
	if got := config.ConfigPath(); got != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestPIDPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)
	want := filepath.Join(dir, "daemon.pid")
	if got := config.PIDPath(); got != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestStatusPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)
	want := filepath.Join(dir, "status.json")
	if got := config.StatusPath(); got != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestLoad_FirstRun(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	cfg, isNew, err := config.Load(stubKeypair)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !isNew {
		t.Error("expected isNew=true on first run")
	}
	if cfg.DeviceID == "" {
		t.Error("DeviceID should be set")
	}
	if cfg.PrivateKey == "" {
		t.Error("PrivateKey should be set")
	}
	if cfg.RelayURL != config.DefaultRelayURL {
		t.Errorf("want relay %s, got %s", config.DefaultRelayURL, cfg.RelayURL)
	}
	// Config file should now exist
	if _, err := os.Stat(config.ConfigPath()); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

func TestLoad_Existing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	// First run
	first, _, err := config.Load(stubKeypair)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}

	// Second load reads existing file
	second, isNew, err := config.Load(stubKeypair)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if isNew {
		t.Error("expected isNew=false on second load")
	}
	if second.DeviceID != first.DeviceID {
		t.Errorf("DeviceID changed between loads: %s → %s", first.DeviceID, second.DeviceID)
	}
}

func TestLoad_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	// Write garbage YAML
	if err := os.WriteFile(config.ConfigPath(), []byte("::not yaml::["), 0600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, _, err := config.Load(stubKeypair)
	if err == nil {
		t.Fatal("expected error loading corrupt config, got nil")
	}
}

func TestLoad_FillsDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	// Write minimal config missing relay_url and log_level
	yaml := "device_id: test-id\nprivate_key: c29tZWtleQ==\n"
	if err := os.WriteFile(config.ConfigPath(), []byte(yaml), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, _, err := config.Load(stubKeypair)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RelayURL != config.DefaultRelayURL {
		t.Errorf("expected default relay URL, got %s", cfg.RelayURL)
	}
	if cfg.LogLevel != config.DefaultLogLevel {
		t.Errorf("expected default log level, got %s", cfg.LogLevel)
	}
}

func TestSave_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "trml")
	t.Setenv("TRML_CONFIG_DIR", nested)

	cfg := &config.Config{
		DeviceID:   "test-id",
		PrivateKey: "key",
		RelayURL:   config.DefaultRelayURL,
		LogLevel:   "info",
	}
	if err := config.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(config.ConfigPath()); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

func TestSave_IsAtomic(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	cfg := &config.Config{DeviceID: "id1", PrivateKey: "k", RelayURL: config.DefaultRelayURL, LogLevel: "info"}
	if err := config.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// tmp file should not remain
	tmp := filepath.Join(dir, ".config.yaml.tmp")
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("tmp file should not exist after atomic save")
	}
}

func TestAddPairedDevice_New(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	cfg, _, _ := config.Load(stubKeypair)
	dev := config.Device{DeviceID: "ios-1", PublicKey: "pubkey1", DeviceName: "Alice's iPhone"}
	if err := cfg.AddPairedDevice(dev); err != nil {
		t.Fatalf("AddPairedDevice: %v", err)
	}
	if len(cfg.PairedDevices) != 1 {
		t.Errorf("expected 1 device, got %d", len(cfg.PairedDevices))
	}

	// Reload and verify persistence
	reloaded, _, _ := config.Load(stubKeypair)
	if len(reloaded.PairedDevices) != 1 {
		t.Errorf("device not persisted: got %d", len(reloaded.PairedDevices))
	}
	if reloaded.PairedDevices[0].DeviceName != "Alice's iPhone" {
		t.Errorf("unexpected device name: %s", reloaded.PairedDevices[0].DeviceName)
	}
}

func TestAddPairedDevice_Update(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	cfg, _, _ := config.Load(stubKeypair)
	dev := config.Device{DeviceID: "ios-1", PublicKey: "oldkey", DeviceName: "Old Name"}
	cfg.AddPairedDevice(dev)

	// Same DeviceID → update in place
	updated := config.Device{DeviceID: "ios-1", PublicKey: "newkey", DeviceName: "New Name"}
	if err := cfg.AddPairedDevice(updated); err != nil {
		t.Fatalf("AddPairedDevice update: %v", err)
	}
	if len(cfg.PairedDevices) != 1 {
		t.Errorf("expected 1 device after update, got %d", len(cfg.PairedDevices))
	}
	if cfg.PairedDevices[0].PublicKey != "newkey" {
		t.Errorf("public key not updated: %s", cfg.PairedDevices[0].PublicKey)
	}
}

func TestFindDevice_Found(t *testing.T) {
	cfg := &config.Config{
		PairedDevices: []config.Device{
			{DeviceID: "ios-1", PublicKey: "pk1", DeviceName: "iPhone"},
			{DeviceID: "ios-2", PublicKey: "pk2", DeviceName: "iPad"},
		},
	}
	dev := cfg.FindDevice("ios-2")
	if dev == nil {
		t.Fatal("expected device, got nil")
	}
	if dev.DeviceName != "iPad" {
		t.Errorf("unexpected device name: %s", dev.DeviceName)
	}
}

func TestFindDevice_NotFound(t *testing.T) {
	cfg := &config.Config{
		PairedDevices: []config.Device{
			{DeviceID: "ios-1", PublicKey: "pk1", DeviceName: "iPhone"},
		},
	}
	if dev := cfg.FindDevice("ios-99"); dev != nil {
		t.Errorf("expected nil, got %+v", dev)
	}
}

func TestInitFirstRun_KeypairError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	errKeypair := func() (string, string, error) {
		return "", "", os.ErrInvalid
	}
	_, err := config.InitFirstRun(errKeypair)
	if err == nil {
		t.Fatal("expected error from failing keypair generator")
	}
}

// ── Migration tests ───────────────────────────────────────────────────────────

func TestMigrate_V0ToV1(t *testing.T) {
	cfg := &config.Config{
		DeviceID:        "old-device",
		PrivateKey:      "old-key",
		RelayURL:        "wss://old.relay.app",
		LogLevel:        "debug",
		PairedDevices:   []config.Device{{DeviceID: "ios-1"}},
	}
	cfg.Migrate()

	if cfg.Version != config.ConfigVersion {
		t.Errorf("version = %q, want %q", cfg.Version, config.ConfigVersion)
	}
	if cfg.CommandTimeoutSecs != 300 {
		t.Errorf("command timeout = %d, want 300", cfg.CommandTimeoutSecs)
	}
	// Existing fields must be preserved.
	if cfg.DeviceID != "old-device" {
		t.Error("DeviceID was lost during migration")
	}
	if len(cfg.PairedDevices) != 1 {
		t.Errorf("PairedDevices count = %d, want 1", len(cfg.PairedDevices))
	}
}

func TestMigrate_V1NoChange(t *testing.T) {
	cfg := &config.Config{
		Version:            config.ConfigVersion,
		CommandTimeoutSecs: 600, // custom value should be preserved
	}
	cfg.Migrate()

	if cfg.Version != config.ConfigVersion {
		t.Errorf("version = %q, want %q", cfg.Version, config.ConfigVersion)
	}
	if cfg.CommandTimeoutSecs != 600 {
		t.Errorf("command timeout was overwritten: got %d, want 600", cfg.CommandTimeoutSecs)
	}
}

func TestMigrate_UnknownVersion(t *testing.T) {
	cfg := &config.Config{
		Version:            "99",
		CommandTimeoutSecs: 123,
	}
	cfg.Migrate()

	if cfg.Version != config.ConfigVersion {
		t.Errorf("version = %q, want %q", cfg.Version, config.ConfigVersion)
	}
	// Unknown versions should keep existing data.
	if cfg.CommandTimeoutSecs != 123 {
		t.Errorf("command timeout changed for unknown version: got %d, want 123", cfg.CommandTimeoutSecs)
	}
}

func TestIsMigrated(t *testing.T) {
	cfg := &config.Config{Version: config.ConfigVersion}
	if !cfg.IsMigrated() {
		t.Error("expected IsMigrated=true for current version")
	}

	cfg.Version = "0"
	if cfg.IsMigrated() {
		t.Error("expected IsMigrated=false for old version")
	}
}

func TestLoad_MigratesOldConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	// Write a v0 config (no version field).
	yaml := "device_id: migrated-device\nprivate_key: c29tZWtleQ==\n"
	if err := os.WriteFile(config.ConfigPath(), []byte(yaml), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, isNew, err := config.Load(stubKeypair)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if isNew {
		t.Error("expected isNew=false for existing config")
	}
	if cfg.Version != config.ConfigVersion {
		t.Errorf("version = %q, want %q after migration", cfg.Version, config.ConfigVersion)
	}
	if cfg.CommandTimeoutSecs != 300 {
		t.Errorf("command timeout = %d, want 300 after v0→v1 migration", cfg.CommandTimeoutSecs)
	}
	if cfg.DeviceID != "migrated-device" {
		t.Error("DeviceID was lost during Load+Migrate")
	}

	// Verify the migrated config was saved back to disk.
	if err := config.Save(cfg); err != nil {
		t.Fatalf("save migrated config: %v", err)
	}
	data, err := os.ReadFile(config.ConfigPath())
	if err != nil {
		t.Fatalf("read migrated config: %v", err)
	}
	if !strings.Contains(string(data), "version:") {
		t.Error("migrated version field not persisted to disk")
	}
}

func TestInitFirstRun_SetsVersion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	cfg, _, err := config.Load(stubKeypair)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != config.ConfigVersion {
		t.Errorf("version = %q, want %q on first run", cfg.Version, config.ConfigVersion)
	}
	if cfg.CommandTimeoutSecs != 300 {
		t.Errorf("command timeout = %d, want 300 on first run", cfg.CommandTimeoutSecs)
	}
}
