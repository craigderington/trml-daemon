package protocol

import "encoding/json"

const (
	Version = "1"

	TypeRegister    = "register"
	TypePair        = "pair"
	TypePairAck     = "pair_ack"
	TypeExec        = "exec"
	TypeOutput      = "output"
	TypePing        = "ping"
	TypePong        = "pong"
	TypeCancel      = "cancel"
	TypePushRegister  = "push_register"
	TypeHello        = "hello"
	TypeTruncated     = "truncated"  // output was truncated due to send buffer overflow
	TypeComplete     = "complete"    // iOS → daemon: request tab completions
	TypeCompleteAck  = "complete_ack" // daemon → iOS: completion candidates
)

// Envelope is the outer (unencrypted) message sent over WebSocket.
type Envelope struct {
	Version    string `json:"version"`
	DeviceID   string `json:"device_id"`
	Nonce      []byte `json:"nonce,omitempty"`
	Ciphertext []byte `json:"ciphertext,omitempty"`
	PairPubKey string `json:"pair_pubkey,omitempty"` // base64, only during pairing
	Type       string `json:"type,omitempty"`        // only for unencrypted control msgs
}

// RegisterMessage is sent unencrypted on connect.
type RegisterMessage struct {
	Type     string `json:"type"`
	DeviceID string `json:"device_id"`
	PubKey   string `json:"pub_key"`
	Version  string `json:"version"`
}

// Inner payload types (JSON inside Envelope.Ciphertext after decryption)

// InnerMessage carries the type discriminant.
type InnerMessage struct {
	Type string `json:"type"`
}

// ExecPayload is sent by the iOS app to request command execution.
type ExecPayload struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Command string `json:"command"`
}

// OutputPayload is sent by the daemon back to the iOS app.
type OutputPayload struct {
	Type       string          `json:"type"`
	ID         string          `json:"id"`
	Chunk      string          `json:"chunk,omitempty"`
	Done       bool            `json:"done"`
	ExitCode   *int            `json:"exit_code,omitempty"`
	Structured json.RawMessage `json:"structured,omitempty"`
}

// PingPayload is a liveness check.
type PingPayload struct {
	Type string `json:"type"`
}

// PongPayload is a liveness response.
type PongPayload struct {
	Type string `json:"type"`
}

// PairPayload is sent by iOS during pairing handshake.
type PairPayload struct {
	Type       string `json:"type"`
	PublicKey  string `json:"public_key"`
	DeviceName string `json:"device_name"`
	DeviceID   string `json:"device_id"`
}

// PairAckPayload confirms pairing success.
type PairAckPayload struct {
	Type string `json:"type"`
}

// CancelPayload requests cancellation of an in-flight command.
type CancelPayload struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// PushRegisterPayload delivers an APNs device token from iOS to the daemon.
// The daemon stores it and uses it to send notifications when commands complete.
type PushRegisterPayload struct {
	Type      string `json:"type"`
	APNsToken string `json:"apns_token"`
	BundleID  string `json:"bundle_id"`
}

// TruncatedPayload is sent by the daemon to notify iOS that output chunks were
// dropped due to send buffer overflow. The client can display this as a warning.
type TruncatedPayload struct {
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"` // command ID, if applicable
	Message string `json:"message"`        // human-readable message for the UI
}

// CompletePayload is sent by iOS to request tab-completion candidates.
type CompletePayload struct {
	Type   string `json:"type"`
	ID     string `json:"id"`     // correlation ID echoed back in CompleteAckPayload
	Prefix string `json:"prefix"` // the word being completed (last token on the line)
	Line   string `json:"line"`   // the full command line (context for smarter completion)
}

// CompleteAckPayload is sent by the daemon with completion candidates.
type CompleteAckPayload struct {
	Type        string   `json:"type"`
	ID          string   `json:"id"`
	Completions []string `json:"completions"`
	Prefix      string   `json:"prefix"` // echoed back so iOS can correlate
}

// MarshalInner marshals an inner payload to JSON.
func MarshalInner(v any) ([]byte, error) {
	return json.Marshal(v)
}

// UnmarshalInner peeks at the type field, then unmarshals into the appropriate type.
func UnmarshalType(data []byte) (string, error) {
	var inner InnerMessage
	if err := json.Unmarshal(data, &inner); err != nil {
		return "", err
	}
	return inner.Type, nil
}

// HelloPayload is sent by the daemon to iOS immediately after a session is
// established (pair_ack or reconnect). It delivers machine context so the iOS
// NL mode generates OS-appropriate commands.
type HelloPayload struct {
	Type     string `json:"type"`      // TypeHello
	OSName   string `json:"os_name"`   // e.g. "macOS 14.5" or "Ubuntu 24.04"
	Shell    string `json:"shell"`     // e.g. "zsh", "bash", "fish"
	Hostname string `json:"hostname"`  // machine hostname
}
