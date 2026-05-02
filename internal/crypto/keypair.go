package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

type Keypair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateKeypair creates a new random X25519 keypair.
func GenerateKeypair() (*Keypair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	// Clamp per RFC 7748
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	kp := &Keypair{}
	copy(kp.Private[:], priv[:])
	copy(kp.Public[:], pub)
	return kp, nil
}

// GenerateKeypairB64 returns base64-encoded private and public keys.
// Satisfies the signature expected by config.Load.
func GenerateKeypairB64() (privB64, pubB64 string, err error) {
	kp, err := GenerateKeypair()
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(kp.Private[:]),
		base64.StdEncoding.EncodeToString(kp.Public[:]),
		nil
}

// PublicKeyFromPrivateB64 derives the public key from a base64 private key.
func PublicKeyFromPrivateB64(privB64 string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	if len(privBytes) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes, got %d", len(privBytes))
	}
	pub, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// DecodePrivateKey decodes a base64 private key to raw bytes.
func DecodePrivateKey(privB64 string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes")
	}
	return b, nil
}

// DecodePublicKey decodes a base64 public key to raw bytes.
func DecodePublicKey(pubB64 string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("public key must be 32 bytes")
	}
	return b, nil
}
