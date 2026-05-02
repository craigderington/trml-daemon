package crypto

import (
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
)

const hkdfInfo = "trml-session-v1"

// DeriveSharedSecret performs X25519 ECDH and derives a 32-byte ChaCha20 key
// via HKDF-SHA256 with info "trml-session-v1".
func DeriveSharedSecret(localPriv, remotePub []byte) ([]byte, error) {
	if len(localPriv) != 32 {
		return nil, fmt.Errorf("localPriv must be 32 bytes")
	}
	if len(remotePub) != 32 {
		return nil, fmt.Errorf("remotePub must be 32 bytes")
	}

	sharedPoint, err := curve25519.X25519(localPriv, remotePub)
	if err != nil {
		return nil, fmt.Errorf("X25519: %w", err)
	}

	r := hkdf.New(sha256.New, sharedPoint, nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return key, nil
}

// DeriveSharedSecretB64 accepts base64-encoded keys.
func DeriveSharedSecretB64(localPrivB64, remotePubB64 string) ([]byte, error) {
	priv, err := DecodePrivateKey(localPrivB64)
	if err != nil {
		return nil, err
	}
	pub, err := DecodePublicKey(remotePubB64)
	if err != nil {
		return nil, err
	}
	return DeriveSharedSecret(priv, pub)
}
