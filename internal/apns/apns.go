// Package apns sends Apple Push Notifications via the APNs HTTP/2 API using
// JWT-based authentication (ES256 private key from an Apple .p8 auth key file).
//
// Usage:
//
//	client, err := apns.NewClient(apns.Config{
//	    KeyPath:  "/path/to/AuthKey_ABCDE12345.p8",
//	    KeyID:    "ABCDE12345",
//	    TeamID:   "TEAM12345A",
//	    BundleID: "app.trml",
//	    Sandbox:  false,
//	})
//	err = client.Notify(deviceToken, "Command done", "ls -la", serverID)
package apns

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	productionHost = "https://api.push.apple.com/3/device/"
	sandboxHost    = "https://api.sandbox.push.apple.com/3/device/"

	// Apple JWT tokens expire after 60 minutes; refresh at 45 to stay safe.
	jwtTTL = 45 * time.Minute

	// clockSkewBuffer is subtracted from the JWT iat claim to tolerate server
	// time drift (APNs rejects tokens issued in the future).
	clockSkewBuffer = 30 * time.Second

	// maxRetries is the maximum number of retry attempts for transient APNs errors.
	maxRetries = 3

	// backoffBase is the base delay for exponential backoff between retries.
	backoffBase = 1 * time.Second
)

// Config holds the APNs credentials and settings.
type Config struct {
	KeyPath  string // path to Apple-issued .p8 auth key file
	KeyID    string // 10-char key ID shown in Apple Developer portal
	TeamID   string // 10-char Apple Team ID
	BundleID string // e.g. "app.trml" — used as apns-topic header
	Sandbox  bool   // true = sandbox (development), false = production
}

// Client sends APNs notifications. Safe for concurrent use.
type Client struct {
	cfg     Config
	key     *ecdsa.PrivateKey
	baseURL string
	http    *http.Client

	mu      sync.Mutex
	jwt     string
	jwtExp  time.Time
}

// NewClient loads the .p8 key and prepares the HTTP/2 client.
// Returns an error if the key file cannot be read or parsed.
func NewClient(cfg Config) (*Client, error) {
	return NewClientWithHTTP(cfg, &http.Client{Timeout: 15 * time.Second}, "")
}

// NewClientWithHTTP is like NewClient but accepts a custom HTTP client and base URL.
// Pass baseURL="" to use the default (production or sandbox based on cfg.Sandbox).
// Intended for testing only.
func NewClientWithHTTP(cfg Config, httpClient *http.Client, baseURL string) (*Client, error) {
	data, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read APNs key %q: %w", cfg.KeyPath, err)
	}
	key, err := parseP8Key(data)
	if err != nil {
		return nil, fmt.Errorf("parse APNs key: %w", err)
	}

	if baseURL == "" {
		if cfg.Sandbox {
			baseURL = sandboxHost
		} else {
			baseURL = productionHost
		}
	}

	return &Client{
		cfg:     cfg,
		key:     key,
		baseURL: baseURL,
		http:    httpClient,
	}, nil
}

// Payload is the JSON body sent to APNs.
type Payload struct {
	APS      aps    `json:"aps"`
	ServerID string `json:"server_id,omitempty"` // deep-link: daemon device UUID
}

type aps struct {
	Alert apsAlert `json:"alert"`
	Sound string   `json:"sound"`
}

type apsAlert struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// Notify sends a push notification to the given APNs device token.
// serverID is included in the payload so the iOS app can deep-link to the
// correct server when the user taps the notification.
// Retries up to maxRetries times with exponential backoff on transient errors.
// Permanent errors (410 Unregistered, 400 BadDeviceToken, etc.) are not retried.
func (c *Client) Notify(deviceToken, title, body, serverID string) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := c.sendOne(deviceToken, title, body, serverID); err != nil {
			lastErr = err
			if !isPermanentAPNsError(err) {
				// Transient error — retry with exponential backoff.
				if attempt < maxRetries {
					delay := time.Duration(attempt) * backoffBase
					time.Sleep(delay)
				}
				continue
			}
			// Permanent error — return immediately, no retry.
			return err
		}
		return nil // success
	}
	return fmt.Errorf("apns notify failed after %d attempts: %w", maxRetries+1, lastErr)
}

// sendOne performs a single APNs HTTP request (no retry logic).
func (c *Client) sendOne(deviceToken, title, body, serverID string) error {
	jwt, err := c.getJWT()
	if err != nil {
		return fmt.Errorf("apns jwt: %w", err)
	}

	p := Payload{
		APS:      aps{Alert: apsAlert{Title: title, Body: body}, Sound: "default"},
		ServerID: serverID,
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+deviceToken, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "bearer "+jwt)
	req.Header.Set("apns-topic", c.cfg.BundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("content-type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("apns request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	// APNs returns a JSON reason on non-200
	var apnsErr struct {
		Reason string `json:"reason"`
	}
	errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	json.Unmarshal(errBody, &apnsErr) // harmless if it fails
	return fmt.Errorf("apns %d: %s", resp.StatusCode, apnsErr.Reason)
}

// isPermanentAPNsError returns true for APNs errors that should not be retried.
// These are client-side errors (bad token, bad request, etc.) where retrying
// will never succeed without external intervention.
func isPermanentAPNsError(err error) bool {
	errStr := err.Error()
	// 410 Unregistered — device token is no longer valid.
	if strings.Contains(errStr, " 410 ") || strings.Contains(errStr, "Unregistered") {
		return true
	}
	// 400 BadDeviceToken — invalid device token format.
	if strings.Contains(errStr, " 400 ") && strings.Contains(errStr, "BadDeviceToken") {
		return true
	}
	// 400 BadRequest — malformed request (e.g., missing topic).
	if strings.Contains(errStr, " 400 ") && strings.Contains(errStr, "BadRequest") {
		return true
	}
	// 403 MissingProviderToken — no auth token provided.
	if strings.Contains(errStr, " 403 ") && strings.Contains(errStr, "MissingProviderToken") {
		return true
	}
	// 413 BadPayload — notification payload too large.
	if strings.Contains(errStr, " 413 ") && strings.Contains(errStr, "BadPayload") {
		return true
	}
	return false
}

// ── helpers ───────────────────────────────────────────────────────────────────

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func (c *Client) getJWT() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.jwtExp) {
		return c.jwt, nil
	}
	t, err := generateJWT(c.key, c.cfg.KeyID, c.cfg.TeamID)
	if err != nil {
		return "", err
	}
	c.jwt = t
	c.jwtExp = time.Now().Add(jwtTTL)
	return t, nil
}

// generateJWT produces a signed ES256 JWT for APNs provider authentication.
// Format: base64url(header).base64url(claims).base64url(sig)
func generateJWT(key *ecdsa.PrivateKey, keyID, teamID string) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID})
	// Subtract clockSkewBuffer from iat to tolerate server time drift.
	iat := time.Now().Add(-clockSkewBuffer).Unix()
	claims, _ := json.Marshal(map[string]any{"iss": teamID, "iat": iat})

	msg := b64url(header) + "." + b64url(claims)

	h := sha256.New()
	h.Write([]byte(msg))
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return "", err
	}
	sig := append(pad32(r.Bytes()), pad32(s.Bytes())...)
	return msg + "." + b64url(sig), nil
}

// ── key parsing ───────────────────────────────────────────────────────────────

// parseP8Key decodes an Apple .p8 auth key file (PKCS#8 PEM, EC P-256).
func parseP8Key(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	ecKey, ok := raw.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not EC (got %T)", raw)
	}
	return ecKey, nil
}

// pad32 left-pads b to exactly 32 bytes (required for P-256 r/s values in JWT).
func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
