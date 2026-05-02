package apns_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/craigderington/trml-daemon/internal/apns"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// genP8File generates a P-256 EC key and writes it as a PKCS#8 PEM file.
// Returns the file path; the file is cleaned up via t.TempDir().
func genP8File(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "AuthKey_TEST1234.p8")
	if err := os.WriteFile(path, block, 0600); err != nil {
		t.Fatalf("write p8: %v", err)
	}
	return path
}

func testConfig(t *testing.T, srv *httptest.Server) apns.Config {
	t.Helper()
	return apns.Config{
		KeyPath:  genP8File(t),
		KeyID:    "TESTKEY001",
		TeamID:   "TESTTEAM01",
		BundleID: "app.trml",
		Sandbox:  true,
	}
}

// ── NewClient ─────────────────────────────────────────────────────────────────

func TestNewClient_ValidKey(t *testing.T) {
	cfg := testConfig(t, nil)
	_, err := apns.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
}

func TestNewClient_MissingKeyFile(t *testing.T) {
	cfg := apns.Config{
		KeyPath:  "/no/such/file.p8",
		KeyID:    "ABCDE12345",
		TeamID:   "TEAM123456",
		BundleID: "app.trml",
	}
	_, err := apns.NewClient(cfg)
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestNewClient_BadPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.p8")
	os.WriteFile(path, []byte("not a pem file"), 0600)

	_, err := apns.NewClient(apns.Config{KeyPath: path, KeyID: "X", TeamID: "Y", BundleID: "z"})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestNewClient_WrongKeyType(t *testing.T) {
	// Generate an RSA key (wrong type) and write as PKCS8 PEM
	// We'll just use a garbage DER payload inside a valid PEM header
	path := filepath.Join(t.TempDir(), "wrong.p8")
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage der bytes")})
	os.WriteFile(path, block, 0600)

	_, err := apns.NewClient(apns.Config{KeyPath: path, KeyID: "X", TeamID: "Y", BundleID: "z"})
	if err == nil {
		t.Fatal("expected error for malformed PKCS8")
	}
}

// ── Notify (against a mock HTTP server) ──────────────────────────────────────

func TestNotify_Success(t *testing.T) {
	var gotAuth, gotTopic string
	var gotBody map[string]any

	mockAPNs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("authorization")
		gotTopic = r.Header.Get("apns-topic")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAPNs.Close()

	keyPath := genP8File(t)
	client, err := apns.NewClientWithHTTP(apns.Config{
		KeyPath:  keyPath,
		KeyID:    "TESTKEY001",
		TeamID:   "TESTTEAM01",
		BundleID: "app.trml",
		Sandbox:  true,
	}, mockAPNs.Client(), mockAPNs.URL+"/3/device/")
	if err != nil {
		t.Fatalf("NewClientWithHTTP: %v", err)
	}

	err = client.Notify("abc123token", "Done", "ls -la finished", "server-uuid")
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if !strings.HasPrefix(gotAuth, "bearer ") {
		t.Errorf("auth header missing 'bearer ': %q", gotAuth)
	}
	if gotTopic != "app.trml" {
		t.Errorf("apns-topic = %q, want 'app.trml'", gotTopic)
	}
	if gotBody["server_id"] != "server-uuid" {
		t.Errorf("server_id in payload = %v", gotBody["server_id"])
	}
	aps, _ := gotBody["aps"].(map[string]any)
	if aps == nil {
		t.Fatal("aps field missing from payload")
	}
	alert, _ := aps["alert"].(map[string]any)
	if alert["title"] != "Done" {
		t.Errorf("title = %v, want 'Done'", alert["title"])
	}
}

func TestNotify_APNsError(t *testing.T) {
	mockAPNs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusGone) // 410 = token no longer valid
		json.NewEncoder(w).Encode(map[string]string{"reason": "Unregistered"})
	}))
	defer mockAPNs.Close()

	keyPath := genP8File(t)
	client, err := apns.NewClientWithHTTP(apns.Config{
		KeyPath:  keyPath,
		KeyID:    "TESTKEY001",
		TeamID:   "TESTTEAM01",
		BundleID: "app.trml",
	}, mockAPNs.Client(), mockAPNs.URL+"/3/device/")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	err = client.Notify("stale-token", "Done", "body", "srv")
	if err == nil {
		t.Fatal("expected error for 410 response")
	}
	if !strings.Contains(err.Error(), "410") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestNotify_JWTCached(t *testing.T) {
	var jwtTokens []string
	mockAPNs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtTokens = append(jwtTokens, r.Header.Get("authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAPNs.Close()

	keyPath := genP8File(t)
	client, err := apns.NewClientWithHTTP(apns.Config{
		KeyPath:  keyPath,
		KeyID:    "TESTKEY001",
		TeamID:   "TESTTEAM01",
		BundleID: "app.trml",
	}, mockAPNs.Client(), mockAPNs.URL+"/3/device/")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Two notifications should reuse the same JWT (it hasn't expired)
	client.Notify("tok1", "T1", "B1", "s1")
	client.Notify("tok2", "T2", "B2", "s2")

	if len(jwtTokens) < 2 {
		t.Fatalf("expected 2 calls, got %d", len(jwtTokens))
	}
	if jwtTokens[0] != jwtTokens[1] {
		t.Errorf("JWT should be cached and reused:\n  first:  %s\n  second: %s",
			jwtTokens[0], jwtTokens[1])
	}
}
