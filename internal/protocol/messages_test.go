package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/craigderington/trml-daemon/internal/protocol"
)

func TestMarshalInner_ExecPayload(t *testing.T) {
	p := protocol.ExecPayload{Type: protocol.TypeExec, ID: "abc", Command: "ls -la"}
	data, err := protocol.MarshalInner(p)
	if err != nil {
		t.Fatalf("MarshalInner: %v", err)
	}

	var got protocol.ExecPayload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ID != "abc" || got.Command != "ls -la" || got.Type != protocol.TypeExec {
		t.Errorf("unexpected payload: %+v", got)
	}
}

func TestMarshalInner_OutputPayload(t *testing.T) {
	code := 0
	p := protocol.OutputPayload{
		Type:     protocol.TypeOutput,
		ID:       "xyz",
		Chunk:    "hello\n",
		Done:     true,
		ExitCode: &code,
	}
	data, err := protocol.MarshalInner(p)
	if err != nil {
		t.Fatalf("MarshalInner: %v", err)
	}

	var got protocol.OutputPayload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ID != "xyz" || got.Chunk != "hello\n" || !got.Done || *got.ExitCode != 0 {
		t.Errorf("unexpected payload: %+v", got)
	}
}

func TestMarshalInner_PairPayload(t *testing.T) {
	p := protocol.PairPayload{
		Type:       protocol.TypePair,
		PublicKey:  "pubkey123",
		DeviceName: "Alice's iPhone",
		DeviceID:   "ios-abc",
	}
	data, err := protocol.MarshalInner(p)
	if err != nil {
		t.Fatalf("MarshalInner: %v", err)
	}
	var got protocol.PairPayload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.DeviceName != "Alice's iPhone" || got.DeviceID != "ios-abc" {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestUnmarshalType_KnownTypes(t *testing.T) {
	cases := []struct {
		json     string
		wantType string
	}{
		{`{"type":"exec","id":"1","command":"ls"}`, protocol.TypeExec},
		{`{"type":"output","id":"1","done":false}`, protocol.TypeOutput},
		{`{"type":"ping"}`, protocol.TypePing},
		{`{"type":"pong"}`, protocol.TypePong},
		{`{"type":"pair","public_key":"k"}`, protocol.TypePair},
		{`{"type":"pair_ack"}`, protocol.TypePairAck},
		{`{"type":"cancel","id":"1"}`, protocol.TypeCancel},
		{`{"type":"register"}`, protocol.TypeRegister},
	}
	for _, tc := range cases {
		got, err := protocol.UnmarshalType([]byte(tc.json))
		if err != nil {
			t.Errorf("UnmarshalType(%s): %v", tc.json, err)
			continue
		}
		if got != tc.wantType {
			t.Errorf("UnmarshalType(%s): want %q, got %q", tc.json, tc.wantType, got)
		}
	}
}

func TestUnmarshalType_InvalidJSON(t *testing.T) {
	_, err := protocol.UnmarshalType([]byte("{not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestEnvelope_JSONRoundTrip(t *testing.T) {
	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   "daemon-123",
		Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Ciphertext: []byte("encrypted-payload"),
		PairPubKey: "pairkey",
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got protocol.Envelope
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.DeviceID != env.DeviceID {
		t.Errorf("DeviceID: want %s, got %s", env.DeviceID, got.DeviceID)
	}
	if string(got.Nonce) != string(env.Nonce) {
		t.Error("Nonce mismatch")
	}
	if got.PairPubKey != env.PairPubKey {
		t.Errorf("PairPubKey: want %s, got %s", env.PairPubKey, got.PairPubKey)
	}
}

func TestRegisterMessage_JSON(t *testing.T) {
	msg := protocol.RegisterMessage{
		Type:     protocol.TypeRegister,
		DeviceID: "d1",
		PubKey:   "pk",
		Version:  protocol.Version,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got protocol.RegisterMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Type != protocol.TypeRegister || got.DeviceID != "d1" {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestOutputPayload_NilExitCode(t *testing.T) {
	// ExitCode should be omitted when nil (not in-progress output)
	p := protocol.OutputPayload{Type: protocol.TypeOutput, ID: "1", Chunk: "data", Done: false}
	data, _ := protocol.MarshalInner(p)

	var m map[string]any
	json.Unmarshal(data, &m)
	if _, ok := m["exit_code"]; ok {
		t.Error("exit_code should be omitted when nil")
	}
}

func TestCancelPayload_JSON(t *testing.T) {
	p := protocol.CancelPayload{Type: protocol.TypeCancel, ID: "cmd-99"}
	data, _ := protocol.MarshalInner(p)
	got, _ := protocol.UnmarshalType(data)
	if got != protocol.TypeCancel {
		t.Errorf("want %s, got %s", protocol.TypeCancel, got)
	}
}
