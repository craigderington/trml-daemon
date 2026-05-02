package pairing_test

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/craigderington/trml-daemon/internal/config"
	"github.com/craigderington/trml-daemon/internal/crypto"
	"github.com/craigderington/trml-daemon/internal/pairing"
	"github.com/craigderington/trml-daemon/internal/protocol"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func newTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)
	cfg, _, err := config.Load(crypto.GenerateKeypairB64)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

func nopSend(deviceID string, key []byte, payload []byte) error { return nil }

// buildPairEnvelope creates a realistic pair envelope as iOS would send it.
func buildPairEnvelope(t *testing.T, daemonPrivB64 string, iosDeviceID, iosDeviceName string) (protocol.Envelope, string) {
	t.Helper()

	// iOS generates its own keypair
	iosPrivB64, iosPubB64, err := crypto.GenerateKeypairB64()
	if err != nil {
		t.Fatalf("ios generate keypair: %v", err)
	}

	// Derive daemon public key from private key
	daemonPubB64, err := crypto.PublicKeyFromPrivateB64(daemonPrivB64)
	if err != nil {
		t.Fatalf("daemon pub key: %v", err)
	}
	_ = daemonPubB64

	// iOS derives shared secret using daemon public key
	iosKey, err := crypto.DeriveSharedSecretB64(iosPrivB64, daemonPubB64)
	if err != nil {
		t.Fatalf("ios derive key: %v", err)
	}

	// iOS builds PairPayload
	pair := protocol.PairPayload{
		Type:       protocol.TypePair,
		PublicKey:  iosPubB64,
		DeviceName: iosDeviceName,
		DeviceID:   iosDeviceID,
	}
	plain, _ := json.Marshal(pair)

	// iOS encrypts with shared key
	nonce, ct, err := crypto.Seal(iosKey, plain)
	if err != nil {
		t.Fatalf("ios seal: %v", err)
	}

	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   iosDeviceID,
		Nonce:      nonce,
		Ciphertext: ct,
		PairPubKey: iosPubB64,
	}
	return env, iosPubB64
}

// ── SessionCache ──────────────────────────────────────────────────────────────

// SessionCache is unexported; test via Manager.GetSessionKey.

// ── Manager ───────────────────────────────────────────────────────────────────

func TestManager_GetSessionKey_NotFound(t *testing.T) {
	cfg := newTestConfig(t)
	mgr := pairing.NewManager(cfg, zap.NewNop(), nopSend)

	_, err := mgr.GetSessionKey("unknown-device-id")
	if err == nil {
		t.Fatal("expected error for unknown device")
	}
}

func TestManager_GetSessionKey_Cached(t *testing.T) {
	cfg := newTestConfig(t)

	_, iosPubB64, _ := crypto.GenerateKeypairB64()
	cfg.PairedDevices = append(cfg.PairedDevices, config.Device{
		DeviceID:   "ios-cached",
		PublicKey:  iosPubB64,
		DeviceName: "Test iPhone",
	})

	mgr := pairing.NewManager(cfg, zap.NewNop(), nopSend)

	// First call derives key
	key1, err := mgr.GetSessionKey("ios-cached")
	if err != nil {
		t.Fatalf("first GetSessionKey: %v", err)
	}
	// Second call returns cached key (same pointer content)
	key2, err := mgr.GetSessionKey("ios-cached")
	if err != nil {
		t.Fatalf("second GetSessionKey: %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("cached key differs from original")
	}
}

func TestManager_HandlePairRequest_MissingPubKey(t *testing.T) {
	cfg := newTestConfig(t)
	mgr := pairing.NewManager(cfg, zap.NewNop(), nopSend)

	env := protocol.Envelope{
		Version:  protocol.Version,
		DeviceID: "ios-1",
		// PairPubKey intentionally empty
	}
	if err := mgr.HandlePairRequest(env); err == nil {
		t.Fatal("expected error for missing PairPubKey")
	}
}

func TestManager_HandlePairRequest_BadCiphertext(t *testing.T) {
	cfg := newTestConfig(t)
	mgr := pairing.NewManager(cfg, zap.NewNop(), nopSend)

	_, iosPubB64, _ := crypto.GenerateKeypairB64()
	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   "ios-1",
		PairPubKey: iosPubB64,
		Nonce:      make([]byte, 12),
		Ciphertext: []byte("garbage-not-valid-ciphertext"),
	}
	if err := mgr.HandlePairRequest(env); err == nil {
		t.Fatal("expected error for invalid ciphertext")
	}
}

func TestManager_HandlePairRequest_Success(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)
	cfg, _, err := config.Load(crypto.GenerateKeypairB64)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	var sentPayloads [][]byte
	sendFn := func(deviceID string, key []byte, payload []byte) error {
		sentPayloads = append(sentPayloads, payload)
		return nil
	}

	mgr := pairing.NewManager(cfg, zap.NewNop(), sendFn)

	env, iosPubB64 := buildPairEnvelope(t, cfg.PrivateKey, "ios-abc", "My iPhone")
	if err := mgr.HandlePairRequest(env); err != nil {
		t.Fatalf("HandlePairRequest: %v", err)
	}

	// Device should be saved
	if !mgr.IsPaired() {
		t.Error("expected IsPaired=true after pairing")
	}
	if mgr.PairedCount() != 1 {
		t.Errorf("expected 1 paired device, got %d", mgr.PairedCount())
	}

	// Pair ack should have been sent
	if len(sentPayloads) != 1 {
		t.Fatalf("expected 1 sent payload, got %d", len(sentPayloads))
	}
	var ack protocol.PairAckPayload
	if err := json.Unmarshal(sentPayloads[0], &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Type != protocol.TypePairAck {
		t.Errorf("expected pair_ack, got %s", ack.Type)
	}

	// Session key should now be resolvable
	key, err := mgr.GetSessionKey("ios-abc")
	if err != nil {
		t.Fatalf("GetSessionKey after pair: %v", err)
	}

	// Verify key is the correct ECDH shared secret
	expected, err := crypto.DeriveSharedSecretB64(cfg.PrivateKey, iosPubB64)
	if err != nil {
		t.Fatalf("derive expected key: %v", err)
	}
	if string(key) != string(expected) {
		t.Error("session key after pairing doesn't match expected ECDH key")
	}
}

func TestManager_IsPaired_Empty(t *testing.T) {
	cfg := newTestConfig(t)
	mgr := pairing.NewManager(cfg, zap.NewNop(), nopSend)
	if mgr.IsPaired() {
		t.Error("expected IsPaired=false with no devices")
	}
	if mgr.PairedCount() != 0 {
		t.Errorf("expected 0 paired devices, got %d", mgr.PairedCount())
	}
}

func TestManager_QRInfo(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)
	cfg, _, _ := config.Load(crypto.GenerateKeypairB64)

	mgr := pairing.NewManager(cfg, zap.NewNop(), nopSend)
	pubB64, deviceID, relayHost, err := mgr.QRInfo()
	if err != nil {
		t.Fatalf("QRInfo: %v", err)
	}
	if pubB64 == "" {
		t.Error("pubB64 should not be empty")
	}
	if deviceID != cfg.DeviceID {
		t.Errorf("deviceID mismatch: want %s, got %s", cfg.DeviceID, deviceID)
	}
	if relayHost == "" {
		t.Error("relayHost should not be empty")
	}
}

func TestManager_GetSessionKey_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRML_CONFIG_DIR", dir)
	cfg, _, _ := config.Load(crypto.GenerateKeypairB64)

	_, iosPub, _ := crypto.GenerateKeypairB64()
	cfg.PairedDevices = []config.Device{{
		DeviceID: "ios-race", PublicKey: iosPub, DeviceName: "Race iPhone",
	}}

	mgr := pairing.NewManager(cfg, zap.NewNop(), nopSend)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := mgr.GetSessionKey("ios-race")
			if err != nil {
				t.Errorf("concurrent GetSessionKey: %v", err)
			}
		}()
	}
	wg.Wait()
}

// ── PairURI ───────────────────────────────────────────────────────────────────

func TestPairURI(t *testing.T) {
	uri := pairing.PairURI("pubkey123", "device-abc", "relay.trml.app")
	if !strings.HasPrefix(uri, "trml://pair?") {
		t.Errorf("unexpected URI: %s", uri)
	}
	if !strings.Contains(uri, "pub=") {
		t.Error("URI missing pub param")
	}
	if !strings.Contains(uri, "id=device-abc") {
		t.Error("URI missing id param")
	}
	if !strings.Contains(uri, "relay=relay.trml.app") {
		t.Error("URI missing relay param")
	}
}

// ── PrintQR ───────────────────────────────────────────────────────────────────

func TestPrintQR_NoError(t *testing.T) {
	// Just ensure it doesn't panic or return an error
	if err := pairing.PrintQR("cHVia2V5", "device-1", "relay.trml.app"); err != nil {
		t.Fatalf("PrintQR: %v", err)
	}
}
