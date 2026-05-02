package crypto_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/craigderington/trml-daemon/internal/crypto"
)

// ── Keypair ──────────────────────────────────────────────────────────────────

func TestGenerateKeypair(t *testing.T) {
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	// Keys must be non-zero
	var zero [32]byte
	if kp.Private == zero {
		t.Error("private key is all zeros")
	}
	if kp.Public == zero {
		t.Error("public key is all zeros")
	}
	// Two keypairs must differ
	kp2, _ := crypto.GenerateKeypair()
	if kp.Private == kp2.Private {
		t.Error("two keypairs should not be identical")
	}
}

func TestGenerateKeypairB64(t *testing.T) {
	privB64, pubB64, err := crypto.GenerateKeypairB64()
	if err != nil {
		t.Fatalf("GenerateKeypairB64: %v", err)
	}
	if privB64 == "" || pubB64 == "" {
		t.Fatal("empty key(s)")
	}

	// Derived public key must match
	derived, err := crypto.PublicKeyFromPrivateB64(privB64)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivateB64: %v", err)
	}
	if derived != pubB64 {
		t.Errorf("derived public key mismatch:\n  got  %s\n  want %s", derived, pubB64)
	}
}

func TestPublicKeyFromPrivateB64_InvalidBase64(t *testing.T) {
	_, err := crypto.PublicKeyFromPrivateB64("not!valid!base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestPublicKeyFromPrivateB64_WrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	_, err := crypto.PublicKeyFromPrivateB64(short)
	if err == nil {
		t.Fatal("expected error for wrong length key")
	}
}

func TestDecodePrivateKey_Valid(t *testing.T) {
	b := make([]byte, 32)
	b[0] = 0xAB
	encoded := base64.StdEncoding.EncodeToString(b)
	got, err := crypto.DecodePrivateKey(encoded)
	if err != nil {
		t.Fatalf("DecodePrivateKey: %v", err)
	}
	if len(got) != 32 || got[0] != 0xAB {
		t.Errorf("unexpected decoded key: %v", got)
	}
}

func TestDecodePrivateKey_BadBase64(t *testing.T) {
	_, err := crypto.DecodePrivateKey("$$not-base64$$")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodePrivateKey_WrongLength(t *testing.T) {
	_, err := crypto.DecodePrivateKey(base64.StdEncoding.EncodeToString([]byte("16bytes-short!!!")))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestDecodePublicKey_Valid(t *testing.T) {
	b := make([]byte, 32)
	b[31] = 0xFF
	encoded := base64.StdEncoding.EncodeToString(b)
	got, err := crypto.DecodePublicKey(encoded)
	if err != nil {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	if got[31] != 0xFF {
		t.Error("decoded key byte mismatch")
	}
}

func TestDecodePublicKey_WrongLength(t *testing.T) {
	_, err := crypto.DecodePublicKey(base64.StdEncoding.EncodeToString([]byte("too-short")))
	if err == nil {
		t.Fatal("expected error")
	}
}

// ── Session ───────────────────────────────────────────────────────────────────

func TestDeriveSharedSecretSymmetric(t *testing.T) {
	kpA, _ := crypto.GenerateKeypair()
	kpB, _ := crypto.GenerateKeypair()

	keyAB, err := crypto.DeriveSharedSecret(kpA.Private[:], kpB.Public[:])
	if err != nil {
		t.Fatalf("A→B: %v", err)
	}
	keyBA, err := crypto.DeriveSharedSecret(kpB.Private[:], kpA.Public[:])
	if err != nil {
		t.Fatalf("B→A: %v", err)
	}
	if string(keyAB) != string(keyBA) {
		t.Error("ECDH shared secrets do not match")
	}
}

func TestDeriveSharedSecret_WrongPrivLen(t *testing.T) {
	_, err := crypto.DeriveSharedSecret([]byte("short"), make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for short private key")
	}
}

func TestDeriveSharedSecret_WrongPubLen(t *testing.T) {
	_, err := crypto.DeriveSharedSecret(make([]byte, 32), []byte("short"))
	if err == nil {
		t.Fatal("expected error for short public key")
	}
}

func TestDeriveSharedSecretB64(t *testing.T) {
	kpA, _ := crypto.GenerateKeypair()
	kpB, _ := crypto.GenerateKeypair()

	privB64 := base64.StdEncoding.EncodeToString(kpA.Private[:])
	pubB64 := base64.StdEncoding.EncodeToString(kpB.Public[:])

	key, err := crypto.DeriveSharedSecretB64(privB64, pubB64)
	if err != nil {
		t.Fatalf("DeriveSharedSecretB64: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key))
	}
}

func TestDeriveSharedSecretB64_BadPriv(t *testing.T) {
	kpB, _ := crypto.GenerateKeypair()
	pubB64 := base64.StdEncoding.EncodeToString(kpB.Public[:])
	_, err := crypto.DeriveSharedSecretB64("notbase64", pubB64)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDeriveSharedSecretB64_BadPub(t *testing.T) {
	kpA, _ := crypto.GenerateKeypair()
	privB64 := base64.StdEncoding.EncodeToString(kpA.Private[:])
	_, err := crypto.DeriveSharedSecretB64(privB64, "notbase64")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ── Envelope ─────────────────────────────────────────────────────────────────

func TestSealOpenRoundTrip(t *testing.T) {
	kp, _ := crypto.GenerateKeypair()
	plaintext := []byte("hello trml — secure channel")

	nonce, ciphertext, err := crypto.Seal(kp.Private[:], plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := crypto.Open(kp.Private[:], nonce, ciphertext)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestSealOpenEmptyPlaintext(t *testing.T) {
	kp, _ := crypto.GenerateKeypair()
	nonce, ciphertext, err := crypto.Seal(kp.Private[:], []byte{})
	if err != nil {
		t.Fatalf("Seal empty: %v", err)
	}
	got, err := crypto.Open(kp.Private[:], nonce, ciphertext)
	if err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %q", got)
	}
}

func TestSealOpenWrongKey(t *testing.T) {
	kp1, _ := crypto.GenerateKeypair()
	kp2, _ := crypto.GenerateKeypair()

	nonce, ciphertext, _ := crypto.Seal(kp1.Private[:], []byte("secret"))
	_, err := crypto.Open(kp2.Private[:], nonce, ciphertext)
	if err == nil {
		t.Fatal("expected error opening with wrong key")
	}
}

func TestOpen_TamperedCiphertext(t *testing.T) {
	kp, _ := crypto.GenerateKeypair()
	nonce, ciphertext, _ := crypto.Seal(kp.Private[:], []byte("data"))
	ciphertext[0] ^= 0xFF // flip bits
	_, err := crypto.Open(kp.Private[:], nonce, ciphertext)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestOpen_TamperedNonce(t *testing.T) {
	kp, _ := crypto.GenerateKeypair()
	nonce, ciphertext, _ := crypto.Seal(kp.Private[:], []byte("data"))
	nonce[0] ^= 0xFF
	_, err := crypto.Open(kp.Private[:], nonce, ciphertext)
	if err == nil {
		t.Fatal("expected error for tampered nonce")
	}
}

func TestSeal_InvalidKeyLength(t *testing.T) {
	_, _, err := crypto.Seal([]byte("tooshort"), []byte("plaintext"))
	if err == nil {
		t.Fatal("expected error for short key in Seal")
	}
}

func TestOpen_InvalidKeyLength(t *testing.T) {
	_, err := crypto.Open([]byte("tooshort"), make([]byte, 12), []byte("ciphertext"))
	if err == nil {
		t.Fatal("expected error for short key in Open")
	}
}

func TestSeal_NonceIsRandom(t *testing.T) {
	kp, _ := crypto.GenerateKeypair()
	nonce1, _, _ := crypto.Seal(kp.Private[:], []byte("data"))
	nonce2, _, _ := crypto.Seal(kp.Private[:], []byte("data"))
	if string(nonce1) == string(nonce2) {
		t.Error("nonces should not be identical across calls")
	}
}

func TestFullE2EEncryptedExchange(t *testing.T) {
	// Simulate daemon and iOS deriving the same shared key and exchanging a message
	daemonKP, _ := crypto.GenerateKeypair()
	iosKP, _ := crypto.GenerateKeypair()

	daemonKey, err := crypto.DeriveSharedSecret(daemonKP.Private[:], iosKP.Public[:])
	if err != nil {
		t.Fatalf("daemon derive: %v", err)
	}
	iosKey, err := crypto.DeriveSharedSecret(iosKP.Private[:], daemonKP.Public[:])
	if err != nil {
		t.Fatalf("ios derive: %v", err)
	}

	msg := []byte(`{"type":"exec","id":"123","command":"ls -la"}`)

	nonce, ct, err := crypto.Seal(iosKey, msg)
	if err != nil {
		t.Fatalf("iOS Seal: %v", err)
	}
	plain, err := crypto.Open(daemonKey, nonce, ct)
	if err != nil {
		t.Fatalf("daemon Open: %v", err)
	}
	if !strings.Contains(string(plain), "exec") {
		t.Errorf("decrypted payload looks wrong: %s", plain)
	}
}
