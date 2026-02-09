//go:build !cgo || !rustcrypto

package ffi

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Enabled reports whether Rust FFI is active.
func Enabled() bool { return false }

// XChaChaEncrypt uses the Go fallback when Rust FFI is disabled.
func XChaChaEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("invalid key size")
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid nonce size")
	}
	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return c.Seal(nil, nonce, plaintext, aad), nil
}

// XChaChaDecrypt uses the Go fallback when Rust FFI is disabled.
func XChaChaDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("invalid key size")
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid nonce size")
	}
	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return c.Open(nil, nonce, ciphertext, aad)
}

// SalamanderXOR performs a keyed XOR obfuscation fallback.
func SalamanderXOR(input, key []byte, nonce uint64) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("empty key")
	}
	out := make([]byte, len(input))
	for i := range input {
		k := key[(i+int(nonce)%len(key))%len(key)]
		s := byte((nonce >> uint((i%8)*8)) & 0xff)
		out[i] = input[i] ^ k ^ s
	}
	return out, nil
}

// BuildPacket serializes a simple packet envelope.
func BuildPacket(version, flags uint8, flowID, seq uint32, payload []byte) ([]byte, error) {
	if len(payload) > 65535 {
		return nil, errors.New("payload too large")
	}
	out := make([]byte, 12+len(payload))
	out[0] = version
	out[1] = flags
	out[2] = byte(flowID >> 24)
	out[3] = byte(flowID >> 16)
	out[4] = byte(flowID >> 8)
	out[5] = byte(flowID)
	out[6] = byte(seq >> 24)
	out[7] = byte(seq >> 16)
	out[8] = byte(seq >> 8)
	out[9] = byte(seq)
	out[10] = byte(len(payload) >> 8)
	out[11] = byte(len(payload))
	copy(out[12:], payload)
	return out, nil
}

// ParsePacketHeader parses the envelope and returns payload offset and length.
func ParsePacketHeader(pkt []byte) (version, flags uint8, flowID, seq uint32, payloadOffset, payloadLen uint32, err error) {
	if len(pkt) < 12 {
		return 0, 0, 0, 0, 0, 0, errors.New("packet too short")
	}
	version = pkt[0]
	flags = pkt[1]
	flowID = uint32(pkt[2])<<24 | uint32(pkt[3])<<16 | uint32(pkt[4])<<8 | uint32(pkt[5])
	seq = uint32(pkt[6])<<24 | uint32(pkt[7])<<16 | uint32(pkt[8])<<8 | uint32(pkt[9])
	payloadLen = uint32(pkt[10])<<8 | uint32(pkt[11])
	payloadOffset = 12
	if int(payloadOffset+payloadLen) > len(pkt) {
		return 0, 0, 0, 0, 0, 0, errors.New("packet payload incomplete")
	}
	return
}

// RandomXNonce creates a random XChaCha nonce.
func RandomXNonce() ([]byte, error) {
	n := make([]byte, chacha20poly1305.NonceSizeX)
	_, err := rand.Read(n)
	return n, err
}
