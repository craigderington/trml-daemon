package relay_test

import (
	"encoding/json"
	"testing"

	"go.uber.org/zap"

	"github.com/craigderington/trml-daemon/internal/crypto"
	"github.com/craigderington/trml-daemon/internal/protocol"
	"github.com/craigderington/trml-daemon/internal/relay"
)

func TestMessageHandler_PushRegister(t *testing.T) {
	_, _, key := makeTestKey(t)

	var gotDeviceID string
	var gotPayload protocol.PushRegisterPayload
	called := false

	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return key, nil },
		crypto.Open,
		nil, nil, nil,
		zap.NewNop(),
	)
	h.SetPushRegHandler(func(deviceID string, p protocol.PushRegisterPayload) {
		gotDeviceID = deviceID
		gotPayload = p
		called = true
	})

	inner := protocol.PushRegisterPayload{
		Type:      protocol.TypePushRegister,
		APNsToken: "deadbeef1234",
		BundleID:  "app.trml",
	}
	data := buildEncryptedEnvelope(t, "ios-device-uuid", key, inner)
	h.Handle(data)

	if !called {
		t.Fatal("push register handler was not called")
	}
	if gotDeviceID != "ios-device-uuid" {
		t.Errorf("device ID = %q, want 'ios-device-uuid'", gotDeviceID)
	}
	if gotPayload.APNsToken != "deadbeef1234" {
		t.Errorf("APNs token = %q, want 'deadbeef1234'", gotPayload.APNsToken)
	}
	if gotPayload.BundleID != "app.trml" {
		t.Errorf("bundle ID = %q, want 'app.trml'", gotPayload.BundleID)
	}
}

func TestMessageHandler_PushRegister_NoHandler(t *testing.T) {
	// When no push register handler is set, the message should be silently ignored.
	_, _, key := makeTestKey(t)

	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return key, nil },
		crypto.Open,
		nil, nil, nil,
		zap.NewNop(),
	)
	// deliberately do NOT call h.SetPushRegHandler

	inner := protocol.PushRegisterPayload{
		Type:      protocol.TypePushRegister,
		APNsToken: "abc",
		BundleID:  "app.trml",
	}
	data := buildEncryptedEnvelope(t, "ios-1", key, inner)
	h.Handle(data) // must not panic
}

func TestMessageHandler_PushRegister_BadPayload(t *testing.T) {
	_, _, key := makeTestKey(t)
	called := false

	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return key, nil },
		// decrypt returns type=push_register but id is a number (strict unmarshal would fail;
		// json.Unmarshal is lenient, so we test the malformed-type case differently)
		func(k, n, ct []byte) ([]byte, error) {
			return []byte(`{"type":"push_register","apns_token":["not","a","string"]}`), nil
		},
		nil, nil, nil,
		zap.NewNop(),
	)
	h.SetPushRegHandler(func(deviceID string, p protocol.PushRegisterPayload) {
		called = true
	})

	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   "ios-1",
		Nonce:      make([]byte, 12),
		Ciphertext: []byte("anything"),
	}
	data, _ := json.Marshal(env)
	h.Handle(data) // apns_token is an array — unmarshal fails → handler not called
	if called {
		t.Error("handler should not be called when payload cannot be unmarshalled")
	}
}
