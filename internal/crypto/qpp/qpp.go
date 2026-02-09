// Package qpp implements Quantum Permutation Pad encryption.
// Based on Grasshopper's QPP implementation.
package qpp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
)

const (
	// DefaultPads is the default number of permutation pads.
	// Using 61 (prime) as recommended by kcptun for mathematical security.
	DefaultPads = 61
	// MinPads is the minimum number of pads.
	MinPads = 16
	// MaxPads is the maximum number of pads.
	MaxPads = 1024
	// BlockSize is the block size for QPP (256 bytes = 2048 bits).
	BlockSize = 256
	// NonceSize is the size of the nonce.
	NonceSize = 8
	// ChecksumSize is the size of the MD5 checksum.
	ChecksumSize = 8
	// MinKeySize is the minimum key size (211 bytes as per kcptun).
	MinKeySize = 211
)

// Config configures QPP encryption.
type Config struct {
	Enabled     bool   `yaml:"enabled"`
	NumPads     int    `yaml:"num_pads"`      // Number of permutation pads (default: 251)
	Key         string `yaml:"key"`           // Encryption key
	Asymmetric  bool   `yaml:"asymmetric"`    // Use different cipher/key per direction
}

// ApplyDefaults sets default values.
func (c *Config) ApplyDefaults() {
	if c.NumPads == 0 {
		c.NumPads = DefaultPads
	}
	if c.NumPads < MinPads {
		c.NumPads = MinPads
	}
	if c.NumPads > MaxPads {
		c.NumPads = MaxPads
	}

	// Ensure NumPads is prime and coprime to 8 for mathematical security
	c.NumPads = OptimizePadCount(c.NumPads)
}

// IsPrime checks if a number is prime.
func IsPrime(n int) bool {
	if n < 2 {
		return false
	}
	if n == 2 {
		return true
	}
	if n%2 == 0 {
		return false
	}
	for i := 3; i*i <= n; i += 2 {
		if n%i == 0 {
			return false
		}
	}
	return true
}

// GCD calculates the greatest common divisor.
func GCD(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// IsCoprimeTo8 checks if a number is coprime to 8.
func IsCoprimeTo8(n int) bool {
	return GCD(n, 8) == 1
}

// NextPrime finds the next prime number >= n.
func NextPrime(n int) int {
	if n <= 2 {
		return 2
	}
	if n%2 == 0 {
		n++
	}
	for !IsPrime(n) {
		n += 2
	}
	return n
}

// OptimizePadCount finds the best pad count that is prime and coprime to 8.
// This provides mathematical security properties as recommended by kcptun.
func OptimizePadCount(n int) int {
	if n < MinPads {
		n = MinPads
	}
	if n > MaxPads {
		n = MaxPads
	}

	// Find nearest prime that is also coprime to 8
	// Since all odd numbers are coprime to 8, we just need an odd prime
	if n%2 == 0 {
		n++
	}

	for n <= MaxPads {
		if IsPrime(n) && IsCoprimeTo8(n) {
			return n
		}
		n += 2
	}

	// Fallback to default if we can't find a suitable prime
	return DefaultPads
}

// QPP implements Quantum Permutation Pad encryption.
type QPP struct {
	pads        [][]byte      // Permutation pads
	numPads     int
	key         []byte
	hasher      hash.Hash
	asymmetric  bool
	encryptPads [][]byte      // Separate pads for encryption (if asymmetric)
	decryptPads [][]byte      // Separate pads for decryption (if asymmetric)
}

// New creates a new QPP instance.
func New(key []byte, numPads int) (*QPP, error) {
	if numPads < MinPads {
		numPads = MinPads
	}
	if numPads > MaxPads {
		numPads = MaxPads
	}

	q := &QPP{
		key:     key,
		numPads: numPads,
		hasher:  sha256.New(),
	}

	// Generate permutation pads
	if err := q.generatePads(); err != nil {
		return nil, err
	}

	return q, nil
}

// NewAsymmetric creates a new QPP instance with asymmetric encryption/decryption pads.
func NewAsymmetric(encryptKey, decryptKey []byte, numPads int) (*QPP, error) {
	if numPads < MinPads {
		numPads = MinPads
	}
	if numPads > MaxPads {
		numPads = MaxPads
	}

	q := &QPP{
		key:        encryptKey,
		numPads:    numPads,
		hasher:     sha256.New(),
		asymmetric: true,
	}

	// Generate encryption pads
	if err := q.generateEncryptPads(encryptKey); err != nil {
		return nil, err
	}

	// Generate decryption pads
	if err := q.generateDecryptPads(decryptKey); err != nil {
		return nil, err
	}

	return q, nil
}

// generatePads generates permutation pads from the key.
func (q *QPP) generatePads() error {
	q.pads = make([][]byte, q.numPads)

	for i := 0; i < q.numPads; i++ {
		pad, err := q.derivePad(i, q.key)
		if err != nil {
			return err
		}
		q.pads[i] = pad
	}

	return nil
}

// generateEncryptPads generates pads for encryption direction.
func (q *QPP) generateEncryptPads(key []byte) error {
	q.encryptPads = make([][]byte, q.numPads)

	for i := 0; i < q.numPads; i++ {
		pad, err := q.derivePad(i, key)
		if err != nil {
			return err
		}
		q.encryptPads[i] = pad
	}

	return nil
}

// generateDecryptPads generates pads for decryption direction.
func (q *QPP) generateDecryptPads(key []byte) error {
	q.decryptPads = make([][]byte, q.numPads)

	for i := 0; i < q.numPads; i++ {
		pad, err := q.derivePad(i, key)
		if err != nil {
			return err
		}
		q.decryptPads[i] = pad
	}

	return nil
}

// derivePad derives a permutation pad using AES-CTR.
func (q *QPP) derivePad(index int, key []byte) ([]byte, error) {
	// Derive key material using SHA-256
	h := sha256.New()
	h.Write(key)
	binary.BigEndian.PutUint32(h.Sum(nil)[:4], uint32(index))
	keyMaterial := h.Sum(nil)

	// Use AES-256 to generate permutation
	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return nil, err
	}

	// Generate permutation using CTR mode
	ctr := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	pad := make([]byte, BlockSize)
	ctr.XORKeyStream(pad, pad)

	// Convert to permutation (sort indices based on pad values)
	perm := make([]byte, BlockSize)
	for i := range perm {
		perm[i] = byte(i)
	}

	// Simple bubble sort based on pad values to create permutation
	for i := 0; i < BlockSize; i++ {
		for j := i + 1; j < BlockSize; j++ {
			if pad[perm[i]] > pad[perm[j]] {
				perm[i], perm[j] = perm[j], perm[i]
			}
		}
	}

	return perm, nil
}

// Encrypt encrypts plaintext using QPP.
// Format: [8-byte nonce][8-byte checksum][encrypted data]
func (q *QPP) Encrypt(plaintext []byte) ([]byte, error) {
	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Calculate checksum
	checksum := q.calculateChecksum(plaintext)

	// Prepare output
	output := make([]byte, NonceSize+ChecksumSize+len(plaintext))
	copy(output[:NonceSize], nonce)
	copy(output[NonceSize:NonceSize+ChecksumSize], checksum)

	// Encrypt
	pads := q.pads
	if q.asymmetric {
		pads = q.encryptPads
	}

	for i := 0; i < len(plaintext); i++ {
		padIdx := int(nonce[i%NonceSize]) % q.numPads
		perm := pads[padIdx]
		output[NonceSize+ChecksumSize+i] = perm[plaintext[i]]
	}

	return output, nil
}

// Decrypt decrypts ciphertext using QPP.
func (q *QPP) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+ChecksumSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:NonceSize]
	expectedChecksum := ciphertext[NonceSize : NonceSize+ChecksumSize]
	encrypted := ciphertext[NonceSize+ChecksumSize:]

	// Decrypt
	plaintext := make([]byte, len(encrypted))
	pads := q.pads
	if q.asymmetric {
		pads = q.decryptPads
	}

	// Create inverse permutations for decryption
	for i := 0; i < len(encrypted); i++ {
		padIdx := int(nonce[i%NonceSize]) % q.numPads
		perm := pads[padIdx]
		// Find the byte that maps to the encrypted byte
		for j, p := range perm {
			if p == encrypted[i] {
				plaintext[i] = byte(j)
				break
			}
		}
	}

	// Verify checksum
	checksum := q.calculateChecksum(plaintext)
	if string(checksum) != string(expectedChecksum) {
		return nil, fmt.Errorf("checksum mismatch")
	}

	return plaintext, nil
}

// calculateChecksum calculates MD5 checksum (first 8 bytes).
func (q *QPP) calculateChecksum(data []byte) []byte {
	q.hasher.Reset()
	q.hasher.Write(data)
	sum := q.hasher.Sum(nil)
	return sum[:ChecksumSize]
}

// GetPadCount returns the number of pads.
func (q *QPP) GetPadCount() int {
	return q.numPads
}

// EncryptBlock encrypts a single block (256 bytes).
func (q *QPP) EncryptBlock(block []byte, nonce byte) []byte {
	if len(block) != BlockSize {
		// Pad or truncate
		newBlock := make([]byte, BlockSize)
		copy(newBlock, block)
		block = newBlock
	}

	result := make([]byte, BlockSize)
	padIdx := int(nonce) % q.numPads
	pads := q.pads
	if q.asymmetric {
		pads = q.encryptPads
	}
	perm := pads[padIdx]

	for i := 0; i < BlockSize; i++ {
		result[i] = perm[block[i]]
	}

	return result
}

// DecryptBlock decrypts a single block (256 bytes).
func (q *QPP) DecryptBlock(block []byte, nonce byte) []byte {
	if len(block) != BlockSize {
		newBlock := make([]byte, BlockSize)
		copy(newBlock, block)
		block = newBlock
	}

	result := make([]byte, BlockSize)
	padIdx := int(nonce) % q.numPads
	pads := q.pads
	if q.asymmetric {
		pads = q.decryptPads
	}
	perm := pads[padIdx]

	// Create inverse permutation
	invPerm := make([]byte, BlockSize)
	for i, p := range perm {
		invPerm[p] = byte(i)
	}

	for i := 0; i < BlockSize; i++ {
		result[i] = invPerm[block[i]]
	}

	return result
}

// Cipher implements the cipher.Block interface for QPP.
type Cipher struct {
	qpp *QPP
}

// NewCipher creates a new QPP cipher.Block.
func NewCipher(key []byte, numPads int) (cipher.Block, error) {
	q, err := New(key, numPads)
	if err != nil {
		return nil, err
	}
	return &Cipher{qpp: q}, nil
}

// BlockSize returns the block size.
func (c *Cipher) BlockSize() int {
	return BlockSize
}

// Encrypt encrypts a single block.
func (c *Cipher) Encrypt(dst, src []byte) {
	copy(dst, c.qpp.EncryptBlock(src, 0))
}

// Decrypt decrypts a single block.
func (c *Cipher) Decrypt(dst, src []byte) {
	copy(dst, c.qpp.DecryptBlock(src, 0))
}

// GenerateKey generates a random key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

// GenerateUniqueParams generates unique parameters for each deployment.
func GenerateUniqueParams() (key []byte, numPads int, err error) {
	key, err = GenerateKey()
	if err != nil {
		return nil, 0, err
	}

	// Random number of pads between MinPads and MaxPads
	numPads = MinPads + int(randInt(MaxPads-MinPads))

	return key, numPads, nil
}

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// ValidateKey checks if the key meets minimum size requirements.
func ValidateKey(key []byte) error {
	if len(key) < MinKeySize {
		return fmt.Errorf("key size %d is less than minimum required %d bytes", len(key), MinKeySize)
	}
	return nil
}

// DeriveKey derives a key from a password using PBKDF2-like iteration.
func DeriveKey(password string, salt []byte, iterations int) []byte {
	if iterations <= 0 {
		iterations = 100000 // Default iterations
	}

	key := []byte(password)
	if salt != nil {
		h := sha256.New()
		h.Write(key)
		h.Write(salt)
		key = h.Sum(nil)
	}

	for i := 0; i < iterations; i++ {
		h := sha256.New()
		h.Write(key)
		binary.BigEndian.PutUint32(h.Sum(nil)[:4], uint32(i))
		key = h.Sum(nil)
	}

	return key
}
