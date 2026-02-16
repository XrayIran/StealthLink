// Package pqsig provides post-quantum signature implementations used by UQSP
// overlays. This implementation uses CIRCL's ML-DSA-65 (FIPS 204).
package pqsig

import (
	"crypto"
	"crypto/rand"
	"crypto/sha3"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// MLDSA65 provides ML-DSA-65 signature operations.
//
// Note: ML-DSA-65 corresponds to the standardized algorithm in FIPS 204.
type MLDSA65 struct {
	publicKey  *mldsa65.PublicKey
	privateKey *mldsa65.PrivateKey
	seed       *[mldsa65.SeedSize]byte
}

// MLDSA65Params exposes packed sizes for config validation / framing.
var MLDSA65Params = struct {
	PublicKeyBytes  int
	PrivateKeyBytes int
	SignatureBytes  int
	SeedBytes       int
}{
	PublicKeyBytes:  mldsa65.PublicKeySize,
	PrivateKeyBytes: mldsa65.PrivateKeySize,
	SignatureBytes:  mldsa65.SignatureSize,
	SeedBytes:       mldsa65.SeedSize,
}

// GenerateKeyPair generates a new ML-DSA-65 keypair.
func (m *MLDSA65) GenerateKeyPair() error {
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("mldsa65 generate key: %w", err)
	}
	m.publicKey = pk
	m.privateKey = sk

	seed := sk.Seed()
	if len(seed) == mldsa65.SeedSize {
		m.seed = new([mldsa65.SeedSize]byte)
		copy(m.seed[:], seed)
	}
	return nil
}

// GenerateKeyPairFromSeed deterministically derives a keypair from a 32-byte seed.
func (m *MLDSA65) GenerateKeyPairFromSeed(seed []byte) error {
	if len(seed) != mldsa65.SeedSize {
		return fmt.Errorf("seed must be %d bytes, got %d", mldsa65.SeedSize, len(seed))
	}
	s := new([mldsa65.SeedSize]byte)
	copy(s[:], seed)
	pk, sk := mldsa65.NewKeyFromSeed(s)
	m.publicKey = pk
	m.privateKey = sk
	m.seed = s
	return nil
}

// Sign creates a signature for the given message.
func (m *MLDSA65) Sign(message []byte) ([]byte, error) {
	if m.privateKey == nil {
		return nil, fmt.Errorf("private key not initialized")
	}
	// Implemented by CIRCL as crypto.Signer with HashFunc() == 0.
	sig, err := m.privateKey.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify verifies a signature over message.
func (m *MLDSA65) Verify(message, signature []byte) error {
	if m.publicKey == nil {
		return fmt.Errorf("public key not initialized")
	}
	if len(signature) != mldsa65.SignatureSize {
		return fmt.Errorf("invalid signature length: %d (expected %d)", len(signature), mldsa65.SignatureSize)
	}
	if !mldsa65.Verify(m.publicKey, message, nil, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// ExportPublicKey returns the packed public key bytes.
func (m *MLDSA65) ExportPublicKey() []byte {
	if m.publicKey == nil {
		return nil
	}
	return m.publicKey.Bytes()
}

// ExportPrivateKey returns the packed private key bytes.
func (m *MLDSA65) ExportPrivateKey() []byte {
	if m.privateKey == nil {
		return nil
	}
	return m.privateKey.Bytes()
}

// ImportPublicKey loads a packed public key.
func (m *MLDSA65) ImportPublicKey(key []byte) error {
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(key); err != nil {
		return err
	}
	m.publicKey = &pk
	return nil
}

// ImportPrivateKey loads a packed private key.
func (m *MLDSA65) ImportPrivateKey(key []byte) error {
	var sk mldsa65.PrivateKey
	if err := sk.UnmarshalBinary(key); err != nil {
		return err
	}
	m.privateKey = &sk
	// Best-effort: recover public key for convenience.
	if pub, ok := sk.Public().(*mldsa65.PublicKey); ok {
		m.publicKey = pub
	}
	return nil
}

// MLDSA65KeyPair contains a packed keypair.
type MLDSA65KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
	Seed       []byte
}

// GenerateMLDSA65KeyPair generates a new packed keypair.
func GenerateMLDSA65KeyPair() (*MLDSA65KeyPair, error) {
	m := &MLDSA65{}
	if err := m.GenerateKeyPair(); err != nil {
		return nil, err
	}
	var seed []byte
	if m.seed != nil {
		seed = append([]byte(nil), m.seed[:]...)
	}
	return &MLDSA65KeyPair{
		PublicKey:  m.ExportPublicKey(),
		PrivateKey: m.ExportPrivateKey(),
		Seed:       seed,
	}, nil
}

// MLDSA65Signer wraps ML-DSA-65 signing.
type MLDSA65Signer struct {
	mldsa *MLDSA65
}

// NewMLDSA65Signer creates a signer from a packed private key.
func NewMLDSA65Signer(privateKey []byte) (*MLDSA65Signer, error) {
	m := &MLDSA65{}
	if err := m.ImportPrivateKey(privateKey); err != nil {
		return nil, err
	}
	return &MLDSA65Signer{mldsa: m}, nil
}

// Sign signs message (implements crypto.Signer-style method signature used by callers).
func (s *MLDSA65Signer) Sign(_ io.Reader, message []byte, _ interface{}) ([]byte, error) {
	return s.mldsa.Sign(message)
}

// Public returns the packed public key bytes.
func (s *MLDSA65Signer) Public() interface{} {
	return s.mldsa.ExportPublicKey()
}

// MLDSA65Verifier verifies ML-DSA-65 signatures.
type MLDSA65Verifier struct {
	mldsa *MLDSA65
}

// NewMLDSA65Verifier creates a verifier from a packed public key.
func NewMLDSA65Verifier(publicKey []byte) (*MLDSA65Verifier, error) {
	m := &MLDSA65{}
	if err := m.ImportPublicKey(publicKey); err != nil {
		return nil, err
	}
	return &MLDSA65Verifier{mldsa: m}, nil
}

// Verify verifies signature over message.
func (v *MLDSA65Verifier) Verify(message, signature []byte) error {
	return v.mldsa.Verify(message, signature)
}

// MLDSA65Config configures ML-DSA-65 for overlays that support PQ signatures.
type MLDSA65Config struct {
	Enabled    bool   `yaml:"enabled"`
	PublicKey  string `yaml:"public_key"`  // Base64-encoded packed public key
	PrivateKey string `yaml:"private_key"` // Base64-encoded packed private key (server only)
}

// LoadKeyPair loads a packed keypair from config.
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
	Classical []byte // Ed25519 or ECDSA signature (optional)
	PQ        []byte // ML-DSA-65 signature
}

// Encode encodes a hybrid signature to bytes.
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
	return &HybridSignature{Classical: classical, PQ: pq}, nil
}

// GenerateMLDSA65Seed generates a random seed suitable for NewKeyFromSeed.
func GenerateMLDSA65Seed() ([]byte, error) {
	seed := make([]byte, mldsa65.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	return seed, nil
}

// DeriveMLDSA65Key derives a deterministic keypair from a master secret and key ID.
func DeriveMLDSA65Key(masterSecret []byte, keyID string) (*MLDSA65KeyPair, error) {
	// Derive seed with SHAKE256 for domain separation.
	h := sha3.NewSHAKE256()
	h.Write(masterSecret)
	h.Write([]byte{0})
	h.Write([]byte(keyID))
	h.Write([]byte("stealthlink-mldsa65-seed-v1"))
	seed := make([]byte, mldsa65.SeedSize)
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

// MLDSA65PublicKeyFromPrivate derives the packed public key from a packed private key.
func MLDSA65PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	m := &MLDSA65{}
	if err := m.ImportPrivateKey(privateKey); err != nil {
		return nil, err
	}
	return m.ExportPublicKey(), nil
}

func IsValidMLDSA65PublicKey(key []byte) bool {
	return len(key) == mldsa65.PublicKeySize
}

func IsValidMLDSA65Signature(sig []byte) bool {
	return len(sig) == mldsa65.SignatureSize
}
