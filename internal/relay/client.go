package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/craigderington/trml-daemon/internal/protocol"
)

const (
	SendBufferSize  = 256 // increased from 64 to handle high-output commands without overflow
	pingInterval    = 30 * time.Second
	pongTimeout     = 10 * time.Second
	writeTimeout    = 10 * time.Second
)

// sendBufferSize is an alias for SendBufferSize, used internally.
const sendBufferSize = SendBufferSize

// Client manages a single WebSocket connection to the relay.
type Client struct {
	url      string
	deviceID string
	pubKeyB64 string

	conn   *websocket.Conn
	send   chan []byte
	mu     sync.Mutex
	log    *zap.Logger

	onMessage func([]byte)
	onConnect func()
	onDisconnect func()
}

func NewClient(url, deviceID, pubKeyB64 string, log *zap.Logger) *Client {
	return &Client{
		url:       url,
		deviceID:  deviceID,
		pubKeyB64: pubKeyB64,
		send:      make(chan []byte, sendBufferSize),
		log:       log,
	}
}

func (c *Client) OnMessage(fn func([]byte))    { c.onMessage = fn }
func (c *Client) OnConnect(fn func())         { c.onConnect = fn }
func (c *Client) OnDisconnect(fn func())      { c.onDisconnect = fn }

// Connect establishes the WebSocket connection and starts pumps.
// Returns when the connection closes or ctx is cancelled.
func (c *Client) Connect(ctx context.Context) error {
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.DialContext(ctx, c.url, nil)
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.url, err)
	}

	// P0-2: Limit WebSocket read size to 1 MB to prevent memory exhaustion
	// from arbitrarily large messages sent by the relay server.
	conn.SetReadLimit(1 << 20) // 1 MiB max message size

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	c.log.Info("connected to relay", zap.String("url", c.url))

	// Send register message
	reg := protocol.RegisterMessage{
		Type:     protocol.TypeRegister,
		DeviceID: c.deviceID,
		PubKey:   c.pubKeyB64,
		Version:  protocol.Version,
	}
	regData, _ := json.Marshal(reg)
	if err := c.writeRaw(regData); err != nil {
		conn.Close()
		return fmt.Errorf("send register: %w", err)
	}

	if c.onConnect != nil {
		c.onConnect()
	}

	done := make(chan struct{})
	go c.writePump(ctx, done)
	c.readPump(ctx)

	close(done)
	conn.Close()

	if c.onDisconnect != nil {
		c.onDisconnect()
	}
	return nil
}

// Send enqueues a message for delivery. If the buffer is full, sends a
// truncation notification via writeRaw (bypassing the channel) so the client
// knows output was dropped instead of silently losing data.
func (c *Client) Send(data []byte) bool {
	select {
	case c.send <- data:
		return true
	default:
		c.log.Warn("send buffer full, dropping message — sending truncation notification")
		// Buffer is full; send a truncation notice directly via writeRaw
		// to bypass the saturated channel. This gives the client visibility
		// into dropped output rather than silent loss.
		trunc := protocol.TruncatedPayload{
			Type:    protocol.TypeTruncated,
			Message: "Output truncated — some chunks were dropped",
		}
		truncData, err := json.Marshal(trunc)
		if err == nil {
			c.mu.Lock()
			conn := c.conn
			c.mu.Unlock()
			if conn != nil {
				conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				if writeErr := conn.WriteMessage(websocket.TextMessage, truncData); writeErr != nil {
					c.log.Error("failed to send truncation notification", zap.Error(writeErr))
				}
			}
		}
		return false
	}
}

func (c *Client) writeRaw(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}
	c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return c.conn.WriteMessage(websocket.TextMessage, data)
}

func (c *Client) writePump(ctx context.Context, done <-chan struct{}) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			// Close the connection so readPump unblocks
			c.mu.Lock()
			if c.conn != nil {
				c.conn.Close()
			}
			c.mu.Unlock()
			return
		case data := <-c.send:
			if err := c.writeRaw(data); err != nil {
				c.log.Error("write error", zap.Error(err))
				return
			}
		case <-ticker.C:
			if err := c.sendPing(); err != nil {
				c.log.Error("ping error", zap.Error(err))
				return
			}
		}
	}
}

func (c *Client) sendPing() error {
	ping, _ := json.Marshal(protocol.Envelope{
		Version:  protocol.Version,
		DeviceID: c.deviceID,
		Type:     protocol.TypePing,
	})
	return c.writeRaw(ping)
}

func (c *Client) readPump(ctx context.Context) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	conn.SetReadDeadline(time.Now().Add(pingInterval + pongTimeout))

	// Reset deadline on PONG (response to our outgoing pings, if any).
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pingInterval + pongTimeout))
		return nil
	})

	// Reset deadline on PING from the relay, and send PONG back.
	// Critical: the relay sends WebSocket PINGs every 50 seconds; our read
	// deadline is 40 seconds, so without this handler the daemon times out
	// before the first PING arrives and the connection drops right after pairing.
	conn.SetPingHandler(func(data string) error {
		conn.SetReadDeadline(time.Now().Add(pingInterval + pongTimeout))
		c.mu.Lock()
		err := conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(writeTimeout))
		c.mu.Unlock()
		return err
	})

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() == nil {
				c.log.Info("connection closed", zap.Error(err))
			}
			return
		}
		conn.SetReadDeadline(time.Now().Add(pingInterval + pongTimeout))

		if c.onMessage != nil {
			c.onMessage(data)
		}
	}
}
