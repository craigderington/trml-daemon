package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Seal encrypts plaintext with the given 32-byte key using ChaCha20-Poly1305.
// Returns (nonce || ciphertext).
func Seal(key, plaintext []byte) (nonce []byte, ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("key must be 32 bytes")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, fmt.Errorf("new chacha20poly1305: %w", err)
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return nonce, ct, nil
}

// Open decrypts ciphertext with the given 32-byte key and nonce.
func Open(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("new chacha20poly1305: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
