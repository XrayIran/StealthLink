package reality

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

// KeyPair represents an X25519 key pair.
type KeyPair struct {
	Private []byte
	Public  []byte
}

// GenerateKeyPair generates a new X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	private := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, private); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	return &KeyPair{
		Private: private,
		Public:  public,
	}, nil
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair for authentication.
func GenerateEd25519KeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, pub, err
}

// DeriveSharedKey derives a shared key using X25519.
func DeriveSharedKey(privateKey, publicKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, publicKey)
}

// DeriveSessionKeys derives session keys from the shared secret.
func DeriveSessionKeys(sharedSecret, salt []byte) (clientKey, serverKey []byte, err error) {
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, []byte("reality-session-keys"))

	clientKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, clientKey); err != nil {
		return nil, nil, fmt.Errorf("derive client key: %w", err)
	}

	serverKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, serverKey); err != nil {
		return nil, nil, fmt.Errorf("derive server key: %w", err)
	}

	return clientKey, serverKey, nil
}

// ShortID generates a short ID from a public key.
func ShortID(publicKey []byte, length int) []byte {
	if length > 32 {
		length = 32
	}
	hash := sha256.Sum256(publicKey)
	return hash[:length]
}

// ValidateShortID validates a short ID against the allowed list.
func ValidateShortID(id []byte, allowed [][]byte) bool {
	for _, allowedID := range allowed {
		if len(id) == len(allowedID) {
			match := true
			for i := range id {
				if id[i] != allowedID[i] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// ParseShortIDs parses a list of short ID strings.
func ParseShortIDs(ids []string) ([][]byte, error) {
	result := make([][]byte, len(ids))
	for i, id := range ids {
		decoded, err := parseKey(id)
		if err != nil {
			return nil, fmt.Errorf("parse short ID %d: %w", i, err)
		}
		result[i] = decoded
	}
	return result, nil
}

// Cipher provides encryption/decryption for REALITY sessions.
type Cipher struct {
	key []byte
}

// NewCipher creates a new cipher from a key.
func NewCipher(key []byte) *Cipher {
	// Copy the key to prevent modification
	k := make([]byte, len(key))
	copy(k, key)
	return &Cipher{key: k}
}

// XORKeyStream applies a stream cipher using the key.
// This is a simple XOR-based stream cipher for demonstration.
// In production, use a proper authenticated encryption scheme.
func (c *Cipher) XORKeyStream(dst, src, nonce []byte) {
	// Generate keystream using SHA-256 in CTR mode
	blockSize := 32 // SHA-256 output size
	counter := uint64(0)

	for i := 0; i < len(src); i += blockSize {
		// Generate keystream block
		blockInput := make([]byte, len(c.key)+len(nonce)+8)
		copy(blockInput, c.key)
		copy(blockInput[len(c.key):], nonce)
		blockInput[len(blockInput)-8] = byte(counter >> 56)
		blockInput[len(blockInput)-7] = byte(counter >> 48)
		blockInput[len(blockInput)-6] = byte(counter >> 40)
		blockInput[len(blockInput)-5] = byte(counter >> 32)
		blockInput[len(blockInput)-4] = byte(counter >> 24)
		blockInput[len(blockInput)-3] = byte(counter >> 16)
		blockInput[len(blockInput)-2] = byte(counter >> 8)
		blockInput[len(blockInput)-1] = byte(counter)

		keystream := sha256.Sum256(blockInput)

		// XOR with plaintext
		end := i + blockSize
		if end > len(src) {
			end = len(src)
		}
		for j := i; j < end; j++ {
			dst[j] = src[j] ^ keystream[j-i]
		}

		counter++
	}
}

// Encrypt encrypts plaintext using the cipher.
func (c *Cipher) Encrypt(plaintext, nonce []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	c.XORKeyStream(ciphertext, plaintext, nonce)
	return ciphertext
}

// Decrypt decrypts ciphertext using the cipher.
func (c *Cipher) Decrypt(ciphertext, nonce []byte) []byte {
	// XOR is symmetric
	plaintext := make([]byte, len(ciphertext))
	c.XORKeyStream(plaintext, ciphertext, nonce)
	return plaintext
}

// NonceSize returns the recommended nonce size.
func (c *Cipher) NonceSize() int {
	return 12 // 96 bits, same as GCM
}
