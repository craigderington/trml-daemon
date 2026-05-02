package relay_test

import (
	"encoding/json"
	"testing"

	"go.uber.org/zap"

	"github.com/craigderington/trml-daemon/internal/crypto"
	"github.com/craigderington/trml-daemon/internal/protocol"
	"github.com/craigderington/trml-daemon/internal/relay"
)

func TestMessageHandler_PingInnerType(t *testing.T) {
	_, _, key := makeTestKey(t)

	// Should not panic or call any handler
	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return key, nil },
		crypto.Open,
		nil, nil, nil,
		zap.NewNop(),
	)

	inner := protocol.PingPayload{Type: protocol.TypePing}
	data := buildEncryptedEnvelope(t, "ios-1", key, inner)
	h.Handle(data) // should not panic
}

func TestMessageHandler_PairHandlerError(t *testing.T) {
	// pair handler returns error — should log but not panic
	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return nil, nil },
		crypto.Open,
		func(env protocol.Envelope) error { return &unknownDeviceError{} },
		nil, nil,
		zap.NewNop(),
	)

	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   "ios-1",
		PairPubKey: "somepubkey",
		Nonce:      make([]byte, 12),
		Ciphertext: []byte("payload"),
	}
	data, _ := json.Marshal(env)
	h.Handle(data) // should not panic
}

func TestBuildEncryptedEnvelope_SealError(t *testing.T) {
	// Inject a seal function that returns an error
	_, err := relay.BuildEncryptedEnvelope("daemon", make([]byte, 32), []byte("data"),
		func(k, p []byte) ([]byte, []byte, error) {
			return nil, nil, &unknownDeviceError{}
		},
	)
	if err == nil {
		t.Fatal("expected error from failing seal function")
	}
}

func TestMessageHandler_ExecUnmarshalError(t *testing.T) {
	_, _, key := makeTestKey(t)

	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return key, nil },
		// decrypt returns valid JSON but not an exec payload
		func(k, n, ct []byte) ([]byte, error) {
			// Return JSON with type=exec but bad structure that fails unmarshal
			return []byte(`{"type":"exec","id":123}`), nil // id is int not string
		},
		nil,
		func(id string, p protocol.ExecPayload) {},
		nil,
		zap.NewNop(),
	)

	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   "ios-1",
		Nonce:      make([]byte, 12),
		Ciphertext: []byte("anything"),
	}
	data, _ := json.Marshal(env)
	h.Handle(data)
	// id mismatch won't cause error since JSON unmarshals int into string loosely
	// Just verify no panic
}

func TestMessageHandler_CancelUnmarshalError(t *testing.T) {
	_, _, key := makeTestKey(t)

	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return key, nil },
		func(k, n, ct []byte) ([]byte, error) {
			return []byte(`{"type":"cancel","id":{"not":"string"}}`), nil
		},
		nil, nil,
		func(id string, p protocol.CancelPayload) {},
		zap.NewNop(),
	)

	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   "ios-1",
		Nonce:      make([]byte, 12),
		Ciphertext: []byte("anything"),
	}
	data, _ := json.Marshal(env)
	h.Handle(data) // should not panic
}
