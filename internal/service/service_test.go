package service_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/craigderington/trml-daemon/internal/config"
	"github.com/craigderington/trml-daemon/internal/service"
)

func TestWriteStatus_FileContents(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)

	// Invoke writeStatus indirectly via exported helper or test the JSON file
	// since writeStatus is unexported we test via the StatusJSON struct
	s := service.StatusJSON{
		Connected:   true,
		Uptime:      "1m30s",
		PairedCount: 2,
		StartedAt:   time.Now().Add(-90 * time.Second),
		UpdatedAt:   time.Now(),
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	statusPath := config.StatusPath()
	if err := os.WriteFile(statusPath, data, 0644); err != nil {
		t.Fatalf("write status: %v", err)
	}

	// Read back and verify
	raw, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}

	var got service.StatusJSON
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Connected {
		t.Error("expected Connected=true")
	}
	if got.Uptime != "1m30s" {
		t.Errorf("expected uptime '1m30s', got %q", got.Uptime)
	}
	if got.PairedCount != 2 {
		t.Errorf("expected 2 paired devices, got %d", got.PairedCount)
	}
}

func TestStatusJSON_MarshalRoundTrip(t *testing.T) {
	now := time.Now().Round(time.Second)
	s := service.StatusJSON{
		Connected:   false,
		Uptime:      "5m0s",
		PairedCount: 0,
		StartedAt:   now,
		UpdatedAt:   now,
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got service.StatusJSON
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Connected != s.Connected {
		t.Errorf("Connected: want %v, got %v", s.Connected, got.Connected)
	}
	if got.Uptime != s.Uptime {
		t.Errorf("Uptime: want %q, got %q", s.Uptime, got.Uptime)
	}
	if got.PairedCount != s.PairedCount {
		t.Errorf("PairedCount: want %d, got %d", s.PairedCount, got.PairedCount)
	}
}
