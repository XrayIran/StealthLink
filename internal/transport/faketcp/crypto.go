package faketcp

import (
	"crypto/sha256"
	"fmt"
	"io"
	"stealthlink/internal/metrics"

	"golang.org/x/crypto/hkdf"
)

// CryptoConfig defines FakeTCP crypto parameters.
type CryptoConfig struct {
	SharedSecret string
	AEADMode     string // "off" | "chacha20poly1305" | "aesgcm"
}

// DirectionalKeys holds separate keys for each direction.
type DirectionalKeys struct {
	ClientToServer []byte
	ServerToClient []byte
}

// NewKeyDerivation creates a new key deriver from a shared secret.
func NewKeyDerivation(sharedSecret string) *KeyDerivation {
	h := sha256.New()
	h.Write([]byte(sharedSecret))
	return &KeyDerivation{ikm: h.Sum(nil)}
}

// KeyDerivation handles HKDF-based key derivation.
type KeyDerivation struct {
	ikm []byte // input keying material (shared secret)
}

// DeriveDirectionalKeys derives separate keys for each direction.
func (kd *KeyDerivation) DeriveDirectionalKeys(keyLen int) (*DirectionalKeys, error) {
	c2s, err := kd.deriveKey("faketcp-c2s", keyLen)
	if err != nil {
		return nil, err
	}
	s2c, err := kd.deriveKey("faketcp-s2c", keyLen)
	if err != nil {
		return nil, err
	}
	metrics.IncFakeTCPKeyDerivations()
	return &DirectionalKeys{
		ClientToServer: c2s,
		ServerToClient: s2c,
	}, nil
}

func (kd *KeyDerivation) deriveKey(info string, keyLen int) ([]byte, error) {
	k := make([]byte, keyLen)
	r := hkdf.New(sha256.New, kd.ikm, nil, []byte(info))
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, fmt.Errorf("hkdf derive %s: %w", info, err)
	}
	return k, nil
}
