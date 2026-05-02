package relay

import (
	"encoding/json"
	"fmt"

	"go.uber.org/zap"

	"github.com/craigderington/trml-daemon/internal/protocol"
)

// SessionKeyFn resolves a shared session key for a given device ID.
type SessionKeyFn func(deviceID string) ([]byte, error)

// DecryptFn decrypts a relay envelope using a session key.
type DecryptFn func(key, nonce, ciphertext []byte) ([]byte, error)

// EncryptSendFn encrypts and sends a payload to a device.
type EncryptSendFn func(deviceID string, key []byte, payload []byte) error

// PairHandlerFn handles a pairing envelope.
type PairHandlerFn func(env protocol.Envelope) error

// ExecHandlerFn dispatches a decrypted exec payload.
type ExecHandlerFn func(deviceID string, payload protocol.ExecPayload)

// CancelHandlerFn dispatches a cancel request.
type CancelHandlerFn func(deviceID string, payload protocol.CancelPayload)

// PushRegHandlerFn handles an APNs token registration from the iOS app.
type PushRegHandlerFn func(deviceID string, payload protocol.PushRegisterPayload)

// CompleteHandlerFn handles a tab-completion request from the iOS app.
type CompleteHandlerFn func(deviceID string, payload protocol.CompletePayload)

// MessageHandler decrypts and dispatches relay messages.
type MessageHandler struct {
	getKey     SessionKeyFn
	decrypt    DecryptFn
	onPair     PairHandlerFn
	onExec     ExecHandlerFn
	onCancel   CancelHandlerFn
	onPushReg  PushRegHandlerFn
	onComplete CompleteHandlerFn
	log        *zap.Logger
}

func NewMessageHandler(
	getKey SessionKeyFn,
	decrypt DecryptFn,
	onPair PairHandlerFn,
	onExec ExecHandlerFn,
	onCancel CancelHandlerFn,
	log *zap.Logger,
) *MessageHandler {
	return &MessageHandler{
		getKey:   getKey,
		decrypt:  decrypt,
		onPair:   onPair,
		onExec:   onExec,
		onCancel: onCancel,
		log:      log,
	}
}

// SetPushRegHandler registers the handler for push_register messages.
func (h *MessageHandler) SetPushRegHandler(fn PushRegHandlerFn) {
	h.onPushReg = fn
}

// SetCompleteHandler registers the handler for tab-completion requests.
func (h *MessageHandler) SetCompleteHandler(fn CompleteHandlerFn) {
	h.onComplete = fn
}

// Handle processes a raw WebSocket message from the relay.
func (h *MessageHandler) Handle(data []byte) {
	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		h.log.Warn("invalid envelope", zap.Error(err))
		return
	}

	// Unencrypted control messages
	if env.Type == protocol.TypePong {
		return
	}

	// Pairing: has PairPubKey field
	if env.PairPubKey != "" {
		if h.onPair != nil {
			if err := h.onPair(env); err != nil {
				h.log.Error("pair handler error", zap.Error(err))
			}
		}
		return
	}

	// Encrypted messages require nonce + ciphertext
	if len(env.Nonce) == 0 || len(env.Ciphertext) == 0 {
		h.log.Warn("envelope missing nonce/ciphertext", zap.String("device_id", env.DeviceID))
		return
	}

	key, err := h.getKey(env.DeviceID)
	if err != nil {
		h.log.Warn("no session key", zap.String("device_id", env.DeviceID), zap.Error(err))
		return
	}

	plaintext, err := h.decrypt(key, env.Nonce, env.Ciphertext)
	if err != nil {
		h.log.Error("decrypt failed", zap.String("device_id", env.DeviceID), zap.Error(err))
		return
	}

	msgType, err := protocol.UnmarshalType(plaintext)
	if err != nil {
		h.log.Warn("unmarshal type failed", zap.Error(err))
		return
	}

	switch msgType {
	case protocol.TypeExec:
		var p protocol.ExecPayload
		if err := json.Unmarshal(plaintext, &p); err != nil {
			h.log.Error("unmarshal exec payload", zap.Error(err))
			return
		}
		if h.onExec != nil {
			h.onExec(env.DeviceID, p)
		}

	case protocol.TypeCancel:
		var p protocol.CancelPayload
		if err := json.Unmarshal(plaintext, &p); err != nil {
			h.log.Error("unmarshal cancel payload", zap.Error(err))
			return
		}
		if h.onCancel != nil {
			h.onCancel(env.DeviceID, p)
		}

	case protocol.TypePushRegister:
		var p protocol.PushRegisterPayload
		if err := json.Unmarshal(plaintext, &p); err != nil {
			h.log.Error("unmarshal push_register payload", zap.Error(err))
			return
		}
		if h.onPushReg != nil {
			h.onPushReg(env.DeviceID, p)
		}

	case protocol.TypeComplete:
		var p protocol.CompletePayload
		if err := json.Unmarshal(plaintext, &p); err != nil {
			h.log.Error("unmarshal complete payload", zap.Error(err))
			return
		}
		if h.onComplete != nil {
			h.onComplete(env.DeviceID, p)
		}

	case protocol.TypePing:
		// Pong handled separately if needed

	default:
		h.log.Debug("unknown inner message type", zap.String("type", msgType))
	}
}

// BuildEncryptedEnvelope creates a relay envelope with encrypted payload.
func BuildEncryptedEnvelope(
	daemonDeviceID string,
	key []byte,
	payload []byte,
	sealFn func(key, plaintext []byte) (nonce, ciphertext []byte, err error),
) ([]byte, error) {
	nonce, ciphertext, err := sealFn(key, payload)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   daemonDeviceID,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	return json.Marshal(env)
}
