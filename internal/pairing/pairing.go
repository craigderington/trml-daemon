package pairing

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/craigderington/trml-daemon/internal/config"
	"github.com/craigderington/trml-daemon/internal/crypto"
	"github.com/craigderington/trml-daemon/internal/protocol"
	"go.uber.org/zap"
)

// SessionCache caches derived shared secrets keyed by remote device ID.
type SessionCache struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func NewSessionCache() *SessionCache {
	return &SessionCache{keys: make(map[string][]byte)}
}

func (sc *SessionCache) Get(deviceID string) ([]byte, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	k, ok := sc.keys[deviceID]
	return k, ok
}

func (sc *SessionCache) Set(deviceID string, key []byte) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.keys[deviceID] = key
}

// Manager handles pairing requests and session key derivation.
type Manager struct {
	cfg     *config.Config
	cache   *SessionCache
	log     *zap.Logger
	// sendFn sends an encrypted reply back to the relay; injected to avoid cycles.
	sendFn  func(deviceID string, key []byte, payload []byte) error
	onPaired func(deviceID string, key []byte)
}

func NewManager(cfg *config.Config, log *zap.Logger, sendFn func(string, []byte, []byte) error) *Manager {
	return &Manager{
		cfg:    cfg,
		cache:  NewSessionCache(),
		log:    log,
		sendFn: sendFn,
	}
}

// GetSessionKey returns the shared secret for a paired device, deriving and caching it lazily.
func (m *Manager) GetSessionKey(deviceID string) ([]byte, error) {
	if key, ok := m.cache.Get(deviceID); ok {
		return key, nil
	}
	dev := m.cfg.FindDevice(deviceID)
	if dev == nil {
		return nil, fmt.Errorf("unknown device: %s", deviceID)
	}
	key, err := crypto.DeriveSharedSecretB64(m.cfg.PrivateKey, dev.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive session key for %s: %w", deviceID, err)
	}
	m.cache.Set(deviceID, key)
	return key, nil
}

// HandlePairRequest processes a pairing envelope from an iOS device.
// pairPubKeyB64 is from Envelope.PairPubKey; ciphertext/nonce may be present for encrypted pair payload.
func (m *Manager) HandlePairRequest(env protocol.Envelope) error {
	if env.PairPubKey == "" {
		return fmt.Errorf("pair request missing pub key")
	}

	// Derive temporary shared secret using pair public key
	tempKey, err := crypto.DeriveSharedSecretB64(m.cfg.PrivateKey, env.PairPubKey)
	if err != nil {
		return fmt.Errorf("derive temp key: %w", err)
	}

	// Decrypt inner payload
	plaintext, err := crypto.Open(tempKey, env.Nonce, env.Ciphertext)
	if err != nil {
		return fmt.Errorf("decrypt pair payload: %w", err)
	}

	var pair protocol.PairPayload
	if err := json.Unmarshal(plaintext, &pair); err != nil {
		return fmt.Errorf("unmarshal pair payload: %w", err)
	}

	m.log.Info("pairing request received",
		zap.String("device_name", pair.DeviceName),
		zap.String("device_id", pair.DeviceID),
	)

	// Save paired device
	dev := config.Device{
		DeviceID:   pair.DeviceID,
		PublicKey:  pair.PublicKey,
		DeviceName: pair.DeviceName,
	}
	if err := m.cfg.AddPairedDevice(dev); err != nil {
		return fmt.Errorf("save paired device: %w", err)
	}

	// Cache the session key
	sessionKey, err := crypto.DeriveSharedSecretB64(m.cfg.PrivateKey, pair.PublicKey)
	if err != nil {
		return fmt.Errorf("derive session key: %w", err)
	}
	m.cache.Set(pair.DeviceID, sessionKey)

	// Send pair_ack encrypted with the new session key
	ack, err := protocol.MarshalInner(protocol.PairAckPayload{Type: protocol.TypePairAck})
	if err != nil {
		return fmt.Errorf("marshal pair ack: %w", err)
	}

	if err := m.sendFn(pair.DeviceID, sessionKey, ack); err != nil {
		return fmt.Errorf("send pair ack: %w", err)
	}

	if m.onPaired != nil {
		m.onPaired(pair.DeviceID, sessionKey)
	}
	m.log.Info("pairing complete", zap.String("device_name", pair.DeviceName))
	return nil
}

// SetOnPaired registers a callback invoked immediately after a successful pairing
// (pair_ack sent). The callback receives the device ID and the fresh session key
// so the caller can send follow-up messages (e.g. hello) on the same connection.
func (m *Manager) SetOnPaired(fn func(deviceID string, key []byte)) {
	m.onPaired = fn
}

// QRInfo returns the data needed to print the pairing QR code.
func (m *Manager) QRInfo() (pubKeyB64, deviceID, relayHost string, err error) {
	pubKeyB64, err = crypto.PublicKeyFromPrivateB64(m.cfg.PrivateKey)
	if err != nil {
		return "", "", "", err
	}
	relayURL := m.cfg.RelayURL
	// Extract host from wss:// URL
	host := relayURL
	for _, prefix := range []string{"wss://", "ws://", "https://", "http://"} {
		if len(host) > len(prefix) && host[:len(prefix)] == prefix {
			host = host[len(prefix):]
			break
		}
	}
	return pubKeyB64, m.cfg.DeviceID, host, nil
}

// IsPaired reports whether there are any paired devices.
func (m *Manager) IsPaired() bool {
	return len(m.cfg.PairedDevices) > 0
}

// PairedCount returns the number of paired devices.
func (m *Manager) PairedCount() int {
	return len(m.cfg.PairedDevices)
}

// base64Decode is a helper to keep import in scope.
var _ = base64.StdEncoding
