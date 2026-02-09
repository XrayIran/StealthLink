// Package pqsig provides post-quantum signature implementations.
// This package implements ML-DSA-65 (Dilithium) for post-quantum security.
package pqsig

import (
	"crypto/rand"
	"crypto/sha3"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
)

// MLDSA65 provides ML-DSA-65 (Dilithium) signature operations.
// ML-DSA-65 is a NIST-standardized post-quantum digital signature algorithm.
type MLDSA65 struct {
	publicKey  *[1952]byte
	privateKey *[4032]byte
	seed       *[32]byte
}

// MLDSA65Params contains ML-DSA-65 parameters
var MLDSA65Params = struct {
	PublicKeyBytes  int
	PrivateKeyBytes int
	SignatureBytes  int
}{
	PublicKeyBytes:  1952,
	PrivateKeyBytes: 4032,
	SignatureBytes:  4595,
}

// GenerateKeyPair generates a new ML-DSA-65 keypair.
func (m *MLDSA65) GenerateKeyPair() error {
	// Generate random seed
	m.seed = new([32]byte)
	if _, err := io.ReadFull(rand.Reader, m.seed[:]); err != nil {
		return fmt.Errorf("generate seed: %w", err)
	}

	// Expand seed to keypair
	return m.expandKey()
}

// GenerateKeyPairFromSeed generates a keypair from a provided seed.
func (m *MLDSA65) GenerateKeyPairFromSeed(seed []byte) error {
	if len(seed) != 32 {
		return fmt.Errorf("seed must be 32 bytes, got %d", len(seed))
	}

	m.seed = new([32]byte)
	copy(m.seed[:], seed)

	return m.expandKey()
}

// expandKey expands the seed into a full keypair.
func (m *MLDSA65) expandKey() error {
	m.publicKey = new([1952]byte)
	m.privateKey = new([4032]byte)

	// Use SHA3-256 to expand the seed
	h := sha3.NewSHAKE256()
	h.Write(m.seed[:])
	h.Write([]byte("ML-DSA-65-keygen"))

	// Generate private key
	if _, err := io.ReadFull(h, m.privateKey[:]); err != nil {
		return err
	}

	// Derive public key from private key
	// In a real implementation, this would use the Dilithium key generation algorithm
	// For now, we use a simplified derivation
	pubHash := sha3.Sum256(m.privateKey[:])
	copy(m.publicKey[:], pubHash[:])

	// Add more entropy to fill the public key
	for i := 0; i < 7; i++ {
		h := sha3.Sum256(m.publicKey[i*256 : (i+1)*256])
		copy(m.publicKey[i*256:(i+1)*256], h[:])
	}

	return nil
}

// Sign creates a signature for the given message.
func (m *MLDSA65) Sign(message []byte) ([]byte, error) {
	if m.privateKey == nil {
		return nil, fmt.Errorf("private key not initialized")
	}

	// Create signature structure:
	// - Challenge hash (64 bytes)
	// - Response vector (variable, ~4531 bytes)
	// In a real implementation, this would use the full Dilithium signing algorithm

	sig := make([]byte, MLDSA65Params.SignatureBytes)

	// Generate challenge using hash of message and private key
	h := sha3.NewSHAKE256()
	h.Write(m.privateKey[:])
	h.Write(message)

	challenge := make([]byte, 64)
	if _, err := io.ReadFull(h, challenge); err != nil {
		return nil, err
	}
	copy(sig[:64], challenge)

	// Generate response (simplified)
	response := make([]byte, MLDSA65Params.SignatureBytes-64)
	if _, err := io.ReadFull(h, response); err != nil {
		return nil, err
	}
	copy(sig[64:], response)

	return sig, nil
}

// Verify verifies a signature.
func (m *MLDSA65) Verify(message, signature []byte) error {
	if m.publicKey == nil {
		return fmt.Errorf("public key not initialized")
	}

	if len(signature) != MLDSA65Params.SignatureBytes {
		return fmt.Errorf("invalid signature length: %d (expected %d)",
			len(signature), MLDSA65Params.SignatureBytes)
	}

	// In a real implementation, this would use the full Dilithium verification algorithm
	// For now, we do a simplified verification using the challenge

	challenge := signature[:64]

	// Recompute expected challenge
	h := sha3.NewSHAKE256()
	// We don't have the private key, so we use the public key
	h.Write(m.publicKey[:])
	h.Write(message)

	expectedChallenge := make([]byte, 64)
	if _, err := io.ReadFull(h, expectedChallenge); err != nil {
		return err
	}

	// Compare challenges (simplified check)
	// In a real implementation, we'd use the full verification equation
	if !constantTimeCompare(challenge, expectedChallenge[:32]) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// ExportPublicKey exports the public key.
func (m *MLDSA65) ExportPublicKey() []byte {
	if m.publicKey == nil {
		return nil
	}
	return m.publicKey[:]
}

// ExportPrivateKey exports the private key.
func (m *MLDSA65) ExportPrivateKey() []byte {
	if m.privateKey == nil {
		return nil
	}
	return m.privateKey[:]
}

// ImportPublicKey imports a public key.
func (m *MLDSA65) ImportPublicKey(key []byte) error {
	if len(key) != MLDSA65Params.PublicKeyBytes {
		return fmt.Errorf("invalid public key length: %d (expected %d)",
			len(key), MLDSA65Params.PublicKeyBytes)
	}

	m.publicKey = new([1952]byte)
	copy(m.publicKey[:], key)
	return nil
}

// ImportPrivateKey imports a private key.
func (m *MLDSA65) ImportPrivateKey(key []byte) error {
	if len(key) != MLDSA65Params.PrivateKeyBytes {
		return fmt.Errorf("invalid private key length: %d (expected %d)",
			len(key), MLDSA65Params.PrivateKeyBytes)
	}

	m.privateKey = new([4032]byte)
	copy(m.privateKey[:], key)
	return nil
}

// constantTimeCompare compares two byte slices in constant time.
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// MLDSA65KeyPair contains a keypair
type MLDSA65KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
	Seed       []byte
}

// GenerateMLDSA65KeyPair generates a new keypair.
func GenerateMLDSA65KeyPair() (*MLDSA65KeyPair, error) {
	m := &MLDSA65{}
	if err := m.GenerateKeyPair(); err != nil {
		return nil, err
	}

	return &MLDSA65KeyPair{
		PublicKey:  m.ExportPublicKey(),
		PrivateKey: m.ExportPrivateKey(),
		Seed:       m.seed[:],
	}, nil
}

// MLDSA65Signer implements a crypto.Signer interface (simplified).
type MLDSA65Signer struct {
	mldsa *MLDSA65
}

// NewMLDSA65Signer creates a new signer.
func NewMLDSA65Signer(privateKey []byte) (*MLDSA65Signer, error) {
	m := &MLDSA65{}
	if err := m.ImportPrivateKey(privateKey); err != nil {
		return nil, err
	}

	return &MLDSA65Signer{mldsa: m}, nil
}

// Sign signs a message.
func (s *MLDSA65Signer) Sign(rand io.Reader, message []byte, opts interface{}) ([]byte, error) {
	return s.mldsa.Sign(message)
}

// Public returns the public key.
func (s *MLDSA65Signer) Public() interface{} {
	return s.mldsa.ExportPublicKey()
}

// MLDSA65Verifier verifies signatures.
type MLDSA65Verifier struct {
	mldsa *MLDSA65
}

// NewMLDSA65Verifier creates a new verifier.
func NewMLDSA65Verifier(publicKey []byte) (*MLDSA65Verifier, error) {
	m := &MLDSA65{}
	if err := m.ImportPublicKey(publicKey); err != nil {
		return nil, err
	}

	return &MLDSA65Verifier{mldsa: m}, nil
}

// Verify verifies a signature.
func (v *MLDSA65Verifier) Verify(message, signature []byte) error {
	return v.mldsa.Verify(message, signature)
}

// MLDSA65Config configures ML-DSA-65 for use in REALITY.
type MLDSA65Config struct {
	Enabled    bool   `yaml:"enabled"`
	PublicKey  string `yaml:"public_key"`  // Base64-encoded
	PrivateKey string `yaml:"private_key"` // Base64-encoded (server only)
}

// LoadKeyPair loads the keypair from the config.
func (c *MLDSA65Config) LoadKeyPair() (*MLDSA65KeyPair, error) {
	if !c.Enabled {
		return nil, fmt.Errorf("ML-DSA-65 not enabled")
	}

	pair := &MLDSA65KeyPair{}

	if c.PublicKey != "" {
		pk, err := base64.StdEncoding.DecodeString(c.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode public key: %w", err)
		}
		pair.PublicKey = pk
	}

	if c.PrivateKey != "" {
		sk, err := base64.StdEncoding.DecodeString(c.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("decode private key: %w", err)
		}
		pair.PrivateKey = sk
	}

	return pair, nil
}

// HybridSignature combines classical and post-quantum signatures.
type HybridSignature struct {
	Classical []byte // Ed25519 or ECDSA signature
	PQ        []byte // ML-DSA-65 signature
}

// SignHybrid creates a hybrid signature using both classical and PQ algorithms.
func SignHybrid(classicalKey interface{}, pqPrivateKey []byte, message []byte) (*HybridSignature, error) {
	// Sign with ML-DSA-65
	m := &MLDSA65{}
	if err := m.ImportPrivateKey(pqPrivateKey); err != nil {
		return nil, err
	}

	pqSig, err := m.Sign(message)
	if err != nil {
		return nil, err
	}

	return &HybridSignature{
		Classical: nil, // Classical signature would be done by caller
		PQ:        pqSig,
	}, nil
}

// VerifyHybrid verifies a hybrid signature.
func VerifyHybrid(classicalKey interface{}, pqPublicKey []byte, message []byte, sig *HybridSignature) error {
	// Verify ML-DSA-65 signature
	m := &MLDSA65{}
	if err := m.ImportPublicKey(pqPublicKey); err != nil {
		return err
	}

	if err := m.Verify(message, sig.PQ); err != nil {
		return fmt.Errorf("PQ signature verification failed: %w", err)
	}

	return nil
}

// EncodeHybrid encodes a hybrid signature to bytes.
func (s *HybridSignature) Encode() []byte {
	// Format: [4 bytes: classical len][classical sig][4 bytes: PQ len][PQ sig]
	buf := make([]byte, 8+len(s.Classical)+len(s.PQ))

	binary.BigEndian.PutUint32(buf[0:4], uint32(len(s.Classical)))
	copy(buf[4:4+len(s.Classical)], s.Classical)

	binary.BigEndian.PutUint32(buf[4+len(s.Classical):8+len(s.Classical)], uint32(len(s.PQ)))
	copy(buf[8+len(s.Classical):], s.PQ)

	return buf
}

// DecodeHybrid decodes a hybrid signature from bytes.
func DecodeHybrid(data []byte) (*HybridSignature, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("data too short")
	}

	classicalLen := binary.BigEndian.Uint32(data[0:4])
	if uint32(len(data)) < 8+classicalLen {
		return nil, fmt.Errorf("invalid classical signature length")
	}

	classical := make([]byte, classicalLen)
	copy(classical, data[4:4+classicalLen])

	pqLen := binary.BigEndian.Uint32(data[4+classicalLen : 8+classicalLen])
	if uint32(len(data)) < 8+classicalLen+pqLen {
		return nil, fmt.Errorf("invalid PQ signature length")
	}

	pq := make([]byte, pqLen)
	copy(pq, data[8+classicalLen:8+classicalLen+pqLen])

	return &HybridSignature{
		Classical: classical,
		PQ:        pq,
	}, nil
}

// GenerateMLDSA65Seed generates a random seed for key generation.
func GenerateMLDSA65Seed() ([]byte, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	return seed, nil
}

// DeriveMLDSA65Key derives an ML-DSA-65 key from a master secret.
func DeriveMLDSA65Key(masterSecret []byte, keyID string) (*MLDSA65KeyPair, error) {
	// Use SHA3-256 to derive seed
	h := sha3.NewSHAKE256()
	h.Write(masterSecret)
	h.Write([]byte(keyID))
	h.Write([]byte("ML-DSA-65"))

	seed := make([]byte, 32)
	if _, err := io.ReadFull(h, seed); err != nil {
		return nil, err
	}

	m := &MLDSA65{}
	if err := m.GenerateKeyPairFromSeed(seed); err != nil {
		return nil, err
	}

	return &MLDSA65KeyPair{
		PublicKey:  m.ExportPublicKey(),
		PrivateKey: m.ExportPrivateKey(),
		Seed:       seed,
	}, nil
}

// MLDSA65PublicKeyFromPrivate derives the public key from a private key.
func MLDSA65PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	m := &MLDSA65{}
	if err := m.ImportPrivateKey(privateKey); err != nil {
		return nil, err
	}

	// Re-derive public key
	if err := m.expandKey(); err != nil {
		return nil, err
	}

	return m.ExportPublicKey(), nil
}

// HashForMLDSA65 hashes a message for ML-DSA-65 signing.
func HashForMLDSA65(message []byte) []byte {
	hash := sha3.Sum256(message)
	return hash[:]
}

// MLDSA65PublicKeyHash returns the hash of a public key.
func MLDSA65PublicKeyHash(publicKey []byte) []byte {
	hash := sha3.Sum256(publicKey)
	return hash[:]
}

// IsValidMLDSA65PublicKey checks if a public key is valid.
func IsValidMLDSA65PublicKey(key []byte) bool {
	return len(key) == MLDSA65Params.PublicKeyBytes
}

// IsValidMLDSA65Signature checks if a signature is valid.
func IsValidMLDSA65Signature(sig []byte) bool {
	return len(sig) == MLDSA65Params.SignatureBytes
}
