package faketcp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"stealthlink/internal/metrics"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEADEncryptor handles authenticated encryption for FakeTCP.
type AEADEncryptor struct {
	aead cipher.AEAD
	mode string
}

// NewAEADEncryptor creates a new AEAD encryptor.
func NewAEADEncryptor(mode string, key []byte) (*AEADEncryptor, error) {
	var aead cipher.AEAD
	var err error

	switch mode {
	case "chacha20poly1305":
		aead, err = chacha20poly1305.New(key)
	case "aesgcm":
		block, err2 := aes.NewCipher(key)
		if err2 != nil {
			return nil, err2
		}
		aead, err = cipher.NewGCM(block)
	case "off":
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported AEAD mode: %s", mode)
	}

	if err != nil {
		return nil, err
	}

	return &AEADEncryptor{
		aead: aead,
		mode: mode,
	}, nil
}

// Seal encrypts and authenticates plaintext.
func (e *AEADEncryptor) Seal(plaintext []byte, pkt *packet) []byte {
	nonce := constructNonce(pkt)
	aad := constructAAD(pkt)
	return e.aead.Seal(nil, nonce, plaintext, aad)
}

// Open decrypts and verifies ciphertext.
func (e *AEADEncryptor) Open(ciphertext []byte, pkt *packet) ([]byte, error) {
	nonce := constructNonce(pkt)
	aad := constructAAD(pkt)
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		metrics.IncFakeTCPAEADAuthFailures()
		return nil, err
	}
	return plaintext, nil
}

// constructAAD constructs AAD (12 bytes):
// [0:1]   packet type
// [1:2]   flags
// [2:6]   sequence (big-endian)
// [6:10]  ack (big-endian)
// [10:12] window (big-endian)
func constructAAD(pkt *packet) []byte {
	aad := make([]byte, 12)
	aad[0] = pkt.Type
	aad[1] = pkt.Flags
	binary.BigEndian.PutUint32(aad[2:6], pkt.Seq)
	binary.BigEndian.PutUint32(aad[6:10], pkt.Ack)
	binary.BigEndian.PutUint16(aad[10:12], pkt.Window)
	return aad
}

// constructNonce constructs Nonce (12 bytes):
// [0:4]   sequence (big-endian)
// [4:8]   ack (big-endian)
// [8:9]   packet type
// [9:10]  flags
// [10:12] zero padding
func constructNonce(pkt *packet) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[0:4], pkt.Seq)
	binary.BigEndian.PutUint32(nonce[4:8], pkt.Ack)
	nonce[8] = pkt.Type
	nonce[9] = pkt.Flags
	// nonce[10:12] are zeros
	return nonce
}
