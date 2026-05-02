package relay_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/craigderington/trml-daemon/internal/crypto"
	"github.com/craigderington/trml-daemon/internal/protocol"
	"github.com/craigderington/trml-daemon/internal/relay"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

// mockServer creates a test WebSocket server. handler receives each message
// sent by the client and can reply back.
func mockServer(t *testing.T, handler func(conn *websocket.Conn, data []byte)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if handler != nil {
				handler(conn, data)
			}
		}
	}))
	return srv
}

func wsURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

// ── MessageHandler ────────────────────────────────────────────────────────────

func makeTestKey(t *testing.T) (daemonPriv, iosPub []byte, sharedKey []byte) {
	t.Helper()
	daemonKP, _ := crypto.GenerateKeypair()
	iosKP, _ := crypto.GenerateKeypair()
	key, err := crypto.DeriveSharedSecret(daemonKP.Private[:], iosKP.Public[:])
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	return daemonKP.Private[:], iosKP.Public[:], key
}

func buildEncryptedEnvelope(t *testing.T, deviceID string, key []byte, inner any) []byte {
	t.Helper()
	payload, err := json.Marshal(inner)
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	nonce, ct, err := crypto.Seal(key, payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   deviceID,
		Nonce:      nonce,
		Ciphertext: ct,
	}
	data, _ := json.Marshal(env)
	return data
}

func TestMessageHandler_Pong(t *testing.T) {
	called := false
	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return nil, nil },
		func(k, n, ct []byte) ([]byte, error) { return nil, nil },
		func(env protocol.Envelope) error { called = true; return nil },
		func(id string, p protocol.ExecPayload) { called = true },
		func(id string, p protocol.CancelPayload) { called = true },
		zap.NewNop(),
	)

	pong, _ := json.Marshal(protocol.Envelope{Type: protocol.TypePong})
	h.Handle(pong)
	if called {
		t.Error("pong should not trigger any handler")
	}
}

func TestMessageHandler_MalformedJSON(t *testing.T) {
	// Should not panic
	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return nil, nil },
		crypto.Open,
		nil, nil, nil,
		zap.NewNop(),
	)
	h.Handle([]byte("{not json"))
}

func TestMessageHandler_PairRequest(t *testing.T) {
	pairCalled := false

	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return nil, nil },
		crypto.Open,
		func(env protocol.Envelope) error {
			pairCalled = true
			return nil
		},
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
	h.Handle(data)

	if !pairCalled {
		t.Error("expected pair handler to be called")
	}
}

func TestMessageHandler_ExecPayload(t *testing.T) {
	_, _, key := makeTestKey(t)

	var gotExec protocol.ExecPayload
	execCalled := false

	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return key, nil },
		crypto.Open,
		nil,
		func(id string, p protocol.ExecPayload) {
			gotExec = p
			execCalled = true
		},
		nil,
		zap.NewNop(),
	)

	inner := protocol.ExecPayload{Type: protocol.TypeExec, ID: "cmd-1", Command: "ls -la"}
	data := buildEncryptedEnvelope(t, "ios-1", key, inner)
	h.Handle(data)

	if !execCalled {
		t.Fatal("exec handler was not called")
	}
	if gotExec.Command != "ls -la" || gotExec.ID != "cmd-1" {
		t.Errorf("unexpected exec payload: %+v", gotExec)
	}
}

func TestMessageHandler_CancelPayload(t *testing.T) {
	_, _, key := makeTestKey(t)

	var gotCancel protocol.CancelPayload
	cancelCalled := false

	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return key, nil },
		crypto.Open,
		nil, nil,
		func(id string, p protocol.CancelPayload) {
			gotCancel = p
			cancelCalled = true
		},
		zap.NewNop(),
	)

	inner := protocol.CancelPayload{Type: protocol.TypeCancel, ID: "cmd-to-cancel"}
	data := buildEncryptedEnvelope(t, "ios-1", key, inner)
	h.Handle(data)

	if !cancelCalled {
		t.Fatal("cancel handler was not called")
	}
	if gotCancel.ID != "cmd-to-cancel" {
		t.Errorf("unexpected cancel ID: %s", gotCancel.ID)
	}
}

func TestMessageHandler_MissingNonce(t *testing.T) {
	called := false
	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return make([]byte, 32), nil },
		crypto.Open,
		nil,
		func(id string, p protocol.ExecPayload) { called = true },
		nil,
		zap.NewNop(),
	)

	// Envelope with ciphertext but no nonce
	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   "ios-1",
		Ciphertext: []byte("some-ciphertext"),
	}
	data, _ := json.Marshal(env)
	h.Handle(data)

	if called {
		t.Error("handler should not be called when nonce is missing")
	}
}

func TestMessageHandler_UnknownDevice(t *testing.T) {
	called := false
	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return nil, &unknownDeviceError{} },
		crypto.Open,
		nil,
		func(id string, p protocol.ExecPayload) { called = true },
		nil,
		zap.NewNop(),
	)

	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   "unknown",
		Nonce:      make([]byte, 12),
		Ciphertext: []byte("data"),
	}
	data, _ := json.Marshal(env)
	h.Handle(data)

	if called {
		t.Error("handler should not be called for unknown device")
	}
}

type unknownDeviceError struct{}

func (e *unknownDeviceError) Error() string { return "unknown device" }

func TestMessageHandler_BadDecrypt(t *testing.T) {
	_, _, key := makeTestKey(t)
	called := false

	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return key, nil },
		crypto.Open,
		nil,
		func(id string, p protocol.ExecPayload) { called = true },
		nil,
		zap.NewNop(),
	)

	// Valid structure but ciphertext is garbage
	env := protocol.Envelope{
		Version:    protocol.Version,
		DeviceID:   "ios-1",
		Nonce:      make([]byte, 12),
		Ciphertext: []byte("this-is-not-valid-ciphertext"),
	}
	data, _ := json.Marshal(env)
	h.Handle(data)

	if called {
		t.Error("handler should not be called on decrypt failure")
	}
}

func TestMessageHandler_UnknownInnerType(t *testing.T) {
	_, _, key := makeTestKey(t)

	h := relay.NewMessageHandler(
		func(id string) ([]byte, error) { return key, nil },
		crypto.Open,
		nil, nil, nil,
		zap.NewNop(),
	)

	inner := map[string]string{"type": "definitely_unknown_type_xyz"}
	data := buildEncryptedEnvelope(t, "ios-1", key, inner)
	// Should not panic
	h.Handle(data)
}

// ── BuildEncryptedEnvelope ────────────────────────────────────────────────────

func TestBuildEncryptedEnvelope(t *testing.T) {
	kp, _ := crypto.GenerateKeypair()
	key := kp.Private[:]

	payload := []byte(`{"type":"output","id":"1","done":true}`)
	data, err := relay.BuildEncryptedEnvelope("daemon-id", key, payload, func(k, p []byte) ([]byte, []byte, error) {
		return crypto.Seal(k, p)
	})
	if err != nil {
		t.Fatalf("BuildEncryptedEnvelope: %v", err)
	}

	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.DeviceID != "daemon-id" {
		t.Errorf("expected device_id 'daemon-id', got %s", env.DeviceID)
	}
	if len(env.Nonce) == 0 || len(env.Ciphertext) == 0 {
		t.Error("envelope missing nonce or ciphertext")
	}

	// Decrypt and verify
	plain, err := crypto.Open(key, env.Nonce, env.Ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != string(payload) {
		t.Errorf("decrypted mismatch: got %q, want %q", plain, payload)
	}
}

// ── RunWithReconnect ──────────────────────────────────────────────────────────

func TestRunWithReconnect_CancelledImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	done := make(chan struct{})
	go func() {
		relay.RunWithReconnect(ctx, zap.NewNop(), func(ctx context.Context) error {
			return ctx.Err()
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunWithReconnect did not stop on cancelled context")
	}
}

func TestRunWithReconnect_RetriesToConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	attempts := 0
	var mu sync.Mutex

	relay.RunWithReconnect(ctx, zap.NewNop(), func(ctx context.Context) error {
		mu.Lock()
		attempts++
		mu.Unlock()
		// fail immediately to trigger retry
		return context.DeadlineExceeded
	})

	mu.Lock()
	n := attempts
	mu.Unlock()

	// Should have attempted at least 2 times in 3 seconds
	if n < 2 {
		t.Errorf("expected at least 2 connection attempts, got %d", n)
	}
}

func TestRunWithReconnect_StopsWhenContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var mu sync.Mutex
	attempts := 0

	done := make(chan struct{})
	go func() {
		relay.RunWithReconnect(ctx, zap.NewNop(), func(ctx context.Context) error {
			mu.Lock()
			attempts++
			mu.Unlock()
			if attempts >= 2 {
				cancel()
			}
			return nil
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunWithReconnect did not stop after context cancel")
	}
}

// ── Client (integration with mock WebSocket server) ───────────────────────────

func TestClient_Connect_ReceivesRegister(t *testing.T) {
	var mu sync.Mutex
	var received [][]byte

	srv := mockServer(t, func(conn *websocket.Conn, data []byte) {
		mu.Lock()
		received = append(received, data)
		mu.Unlock()
	})
	defer srv.Close()

	kp, _ := crypto.GenerateKeypair()
	_, pubB64, _ := crypto.GenerateKeypairB64()
	_ = kp

	client := relay.NewClient(wsURL(srv), "daemon-1", pubB64, zap.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go client.Connect(ctx)

	// Wait for register message
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(received) == 0 {
		t.Fatal("no messages received by server")
	}

	var reg protocol.RegisterMessage
	if err := json.Unmarshal(received[0], &reg); err != nil {
		t.Fatalf("unmarshal register: %v", err)
	}
	if reg.Type != protocol.TypeRegister {
		t.Errorf("expected register message, got type %s", reg.Type)
	}
	if reg.DeviceID != "daemon-1" {
		t.Errorf("expected device_id 'daemon-1', got %s", reg.DeviceID)
	}
}

func TestClient_OnMessage_Called(t *testing.T) {
	var mu sync.Mutex
	var serverConn *websocket.Conn

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		mu.Lock()
		serverConn = conn
		mu.Unlock()
		// read the register message then block
		conn.ReadMessage()
		// Send a test message to the client
		msg, _ := json.Marshal(map[string]string{"type": "pong"})
		conn.WriteMessage(websocket.TextMessage, msg)
		// Keep alive
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	_, pubB64, _ := crypto.GenerateKeypairB64()
	client := relay.NewClient(wsURL(srv), "daemon-1", pubB64, zap.NewNop())

	var received []byte
	receivedCh := make(chan struct{}, 1)
	client.OnMessage(func(data []byte) {
		received = data
		select {
		case receivedCh <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go client.Connect(ctx)

	select {
	case <-receivedCh:
	case <-ctx.Done():
		t.Fatal("did not receive message from server")
	}

	if len(received) == 0 {
		t.Error("received message was empty")
	}
	_ = serverConn
}

func TestClient_Send_BufferFull(t *testing.T) {
	// Create client without connecting — send buffer should fill and return false
	_, pubB64, _ := crypto.GenerateKeypairB64()
	client := relay.NewClient("ws://127.0.0.1:1", "d1", pubB64, zap.NewNop())

	// Fill the buffer (size 256) without draining
	for i := 0; i < relay.SendBufferSize; i++ {
		client.Send([]byte(`{"type":"ping"}`))
	}
	// Next send should be dropped (triggers backpressure notification)
	dropped := !client.Send([]byte(`{"type":"ping"}`))
	if !dropped {
		t.Error("expected Send to return false when buffer is full")
	}
}

func TestClient_Send_BufferSize(t *testing.T) {
	// Verify the send buffer size is at least 256 (P0-3 fix).
	if relay.SendBufferSize < 256 {
		t.Errorf("send buffer size %d is below minimum 256 (P0-3)", relay.SendBufferSize)
	}

	_, pubB64, _ := crypto.GenerateKeypairB64()
	client := relay.NewClient("ws://127.0.0.1:1", "d1", pubB64, zap.NewNop())

	// Fill the buffer completely — all sends should succeed.
	for i := 0; i < relay.SendBufferSize; i++ {
		if !client.Send([]byte(`{"type":"ping"}`)) {
			t.Fatalf("Send #%d failed: buffer not large enough", i+1)
		}
	}

	// The next send should fail (buffer full), confirming backpressure kicks in.
	if client.Send([]byte(`{"type":"ping"}`)) {
		t.Error("expected Send to return false when buffer is full")
	}
}

func TestClient_OnConnect_OnDisconnect_Called(t *testing.T) {
	srv := mockServer(t, nil)
	defer srv.Close()

	_, pubB64, _ := crypto.GenerateKeypairB64()
	client := relay.NewClient(wsURL(srv), "d1", pubB64, zap.NewNop())

	connectCh := make(chan struct{}, 1)
	disconnectCh := make(chan struct{}, 1)

	client.OnConnect(func() {
		select {
		case connectCh <- struct{}{}:
		default:
		}
	})
	client.OnDisconnect(func() {
		select {
		case disconnectCh <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go client.Connect(ctx)

	select {
	case <-connectCh:
	case <-time.After(2 * time.Second):
		t.Fatal("OnConnect not called")
	}

	// Cancel context to trigger disconnect
	cancel()

	select {
	case <-disconnectCh:
	case <-time.After(2 * time.Second):
		t.Fatal("OnDisconnect not called")
	}
}

func TestClient_FailedDial(t *testing.T) {
	_, pubB64, _ := crypto.GenerateKeypairB64()
	client := relay.NewClient("ws://127.0.0.1:1", "d1", pubB64, zap.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := client.Connect(ctx)
	if err == nil {
		t.Error("expected error connecting to non-existent server")
	}
}
