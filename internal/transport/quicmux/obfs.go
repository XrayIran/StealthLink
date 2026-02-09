package quicmux

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// salamanderObfuscator implements the Salamander obfuscation scheme.
// It uses BLAKE2b to derive a keystream and XORs it with the data.
type salamanderObfuscator struct {
	password []byte
	hash     hash.Hash
}

// newSalamanderObfuscator creates a new Salamander obfuscator.
func newSalamanderObfuscator(password string) *salamanderObfuscator {
	h, _ := blake2b.New256(nil)
	return &salamanderObfuscator{
		password: []byte(password),
		hash:     h,
	}
}

// Obfuscate obfuscates the input data.
func (s *salamanderObfuscator) Obfuscate(data []byte, nonce uint64) []byte {
	// Derive keystream using BLAKE2b
	keystream := s.deriveKeystream(len(data), nonce)

	// XOR with data
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ keystream[i]
	}

	return result
}

// Deobfuscate reverses the obfuscation.
func (s *salamanderObfuscator) Deobfuscate(data []byte, nonce uint64) []byte {
	// XOR is symmetric
	return s.Obfuscate(data, nonce)
}

// deriveKeystream generates a keystream of the specified length.
func (s *salamanderObfuscator) deriveKeystream(length int, nonce uint64) []byte {
	keystream := make([]byte, 0, length)
	counter := uint64(0)

	for len(keystream) < length {
		// Hash password + nonce + counter
		s.hash.Reset()
		s.hash.Write(s.password)

		nonceBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(nonceBytes, nonce)
		s.hash.Write(nonceBytes)

		counterBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(counterBytes, counter)
		s.hash.Write(counterBytes)

		block := s.hash.Sum(nil)
		keystream = append(keystream, block...)
		counter++
	}

	return keystream[:length]
}

// simpleXORObfuscator is a simpler XOR obfuscator for testing.
type simpleXORObfuscator struct {
	key []byte
}

// newSimpleXORObfuscator creates a simple XOR obfuscator.
func newSimpleXORObfuscator(password string) *simpleXORObfuscator {
	// Derive key from password
	hash := sha256.Sum256([]byte(password))
	return &simpleXORObfuscator{
		key: hash[:],
	}
}

// Obfuscate XORs data with the key.
func (s *simpleXORObfuscator) Obfuscate(data []byte, _ uint64) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ s.key[i%len(s.key)]
	}
	return result
}

// Deobfuscate is the same as Obfuscate for XOR.
func (s *simpleXORObfuscator) Deobfuscate(data []byte, nonce uint64) []byte {
	return s.Obfuscate(data, nonce)
}
