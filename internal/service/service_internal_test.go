// Internal tests for service package (same package, can access unexported symbols).
package service

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/craigderington/trml-daemon/internal/config"
	"github.com/craigderington/trml-daemon/internal/crypto"
)

func TestWriteStatus_Connected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	cfg, _, err := config.Load(crypto.GenerateKeypairB64)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	startedAt := time.Now().Add(-30 * time.Second)
	writeStatus(cfg, true, startedAt, 3)

	data, err := os.ReadFile(config.StatusPath())
	if err != nil {
		t.Fatalf("read status file: %v", err)
	}

	var s StatusJSON
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !s.Connected {
		t.Error("expected Connected=true")
	}
	if s.PairedCount != 3 {
		t.Errorf("expected 3 paired devices, got %d", s.PairedCount)
	}
	if s.Uptime == "" {
		t.Error("Uptime should not be empty")
	}
}

func TestWriteStatus_Disconnected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	cfg, _, _ := config.Load(crypto.GenerateKeypairB64)
	writeStatus(cfg, false, time.Now(), 0)

	data, err := os.ReadFile(config.StatusPath())
	if err != nil {
		t.Fatalf("read status file: %v", err)
	}

	var s StatusJSON
	json.Unmarshal(data, &s)

	if s.Connected {
		t.Error("expected Connected=false")
	}
	if s.PairedCount != 0 {
		t.Errorf("expected 0 paired devices, got %d", s.PairedCount)
	}
}

func TestWriteStatus_UptimeIncreases(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)
	cfg, _, _ := config.Load(crypto.GenerateKeypairB64)

	startedAt := time.Now().Add(-5 * time.Minute)
	writeStatus(cfg, false, startedAt, 0)

	data, _ := os.ReadFile(config.StatusPath())
	var s StatusJSON
	json.Unmarshal(data, &s)

	// Should be ~5m uptime
	if s.Uptime == "0s" {
		t.Errorf("expected non-zero uptime, got %q", s.Uptime)
	}
}

func TestWriteStatus_StartedAtPresent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)
	cfg, _, _ := config.Load(crypto.GenerateKeypairB64)

	start := time.Now().Add(-1 * time.Minute)
	writeStatus(cfg, true, start, 1)

	data, _ := os.ReadFile(config.StatusPath())
	var s StatusJSON
	json.Unmarshal(data, &s)

	if s.StartedAt.IsZero() {
		t.Error("StartedAt should not be zero")
	}
	if s.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should not be zero")
	}
}
