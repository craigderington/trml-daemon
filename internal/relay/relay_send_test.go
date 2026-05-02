package relay_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/craigderington/trml-daemon/internal/crypto"
	"github.com/craigderington/trml-daemon/internal/protocol"
	"github.com/craigderington/trml-daemon/internal/relay"
)

// TestClient_Send_DeliveredToServer verifies that calling Send() while connected
// routes the message through writePump out to the server.
func TestClient_Send_DeliveredToServer(t *testing.T) {
	var mu sync.Mutex
	gotCustom := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			mu.Lock()
			var msg map[string]any
			if json.Unmarshal(data, &msg) == nil {
				if msg["type"] != protocol.TypeRegister {
					select {
					case gotCustom <- struct{}{}:
					default:
					}
				}
			}
			mu.Unlock()
		}
	}))
	defer srv.Close()

	_, pubB64, _ := crypto.GenerateKeypairB64()
	client := relay.NewClient(wsURL(srv), "d1", pubB64, zap.NewNop())

	connectCh := make(chan struct{}, 1)
	client.OnConnect(func() {
		select {
		case connectCh <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go client.Connect(ctx)

	select {
	case <-connectCh:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not connect")
	}

	// Send a custom message through the send channel (exercises writePump send case)
	customMsg, _ := json.Marshal(map[string]string{"type": "custom_test_message"})
	if !client.Send(customMsg) {
		t.Fatal("Send returned false while connected")
	}

	select {
	case <-gotCustom:
		// Server received it via writePump — success
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive sent message within 2s")
	}
}
