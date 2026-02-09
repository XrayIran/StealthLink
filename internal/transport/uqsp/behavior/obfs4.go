package behavior

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
)

// Obfs4Overlay implements obfs4 obfuscation as a behavior overlay.
// It provides deep obfuscation for TCP-based transports.
type Obfs4Overlay struct {
	EnabledField bool   `yaml:"enabled"`
	NodeID       string `yaml:"node_id"`
	PublicKey    string `yaml:"public_key"`
	PrivateKey   string `yaml:"private_key"`
	Seed         string `yaml:"seed"`
	IATMode      int    `yaml:"iat_mode"`
	ServerMode   bool   `yaml:"-"`

	nodeIDBytes     []byte
	publicKeyBytes  []byte
	privateKeyBytes []byte
	seedBytes       []byte
}

// Name returns the name of this overlay
func (o *Obfs4Overlay) Name() string {
	return "obfs4"
}

// Enabled returns whether this overlay is enabled
func (o *Obfs4Overlay) Enabled() bool {
	return o.EnabledField
}

// IsEnabled returns whether this overlay is enabled
func (o *Obfs4Overlay) IsEnabled() bool {
	return o.EnabledField
}

// Validate validates the configuration
func (o *Obfs4Overlay) Validate() error {
	if !o.EnabledField {
		return nil
	}

	if o.NodeID != "" {
		id, err := base64.StdEncoding.DecodeString(o.NodeID)
		if err != nil {
			id = make([]byte, 32)
			copy(id, []byte(o.NodeID))
		}
		o.nodeIDBytes = id
	}

	if o.PublicKey != "" {
		pk, err := base64.StdEncoding.DecodeString(o.PublicKey)
		if err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
		if len(pk) != 32 {
			return fmt.Errorf("public key must be 32 bytes, got %d", len(pk))
		}
		o.publicKeyBytes = pk
	}

	if o.PrivateKey != "" {
		sk, err := base64.StdEncoding.DecodeString(o.PrivateKey)
		if err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}
		if len(sk) != 32 {
			return fmt.Errorf("private key must be 32 bytes, got %d", len(sk))
		}
		o.privateKeyBytes = sk
	}

	if o.Seed != "" {
		seed, err := base64.StdEncoding.DecodeString(o.Seed)
		if err != nil {
			return fmt.Errorf("invalid seed: %w", err)
		}
		o.seedBytes = seed
	}

	if o.IATMode < 0 || o.IATMode > 2 {
		return fmt.Errorf("invalid IAT mode: %d (must be 0-2)", o.IATMode)
	}

	return nil
}

// Apply applies the obfs4 overlay to a connection
func (o *Obfs4Overlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}

	return NewObfs4Conn(conn, o)
}

// GenerateKeys generates new obfs4 keys
func (o *Obfs4Overlay) GenerateKeys() error {
	o.nodeIDBytes = make([]byte, 32)
	if _, err := rand.Read(o.nodeIDBytes); err != nil {
		return err
	}
	o.NodeID = base64.StdEncoding.EncodeToString(o.nodeIDBytes)

	var err error
	o.publicKeyBytes, o.privateKeyBytes, err = generateKeypair()
	if err != nil {
		return err
	}
	o.PublicKey = base64.StdEncoding.EncodeToString(o.publicKeyBytes)
	o.PrivateKey = base64.StdEncoding.EncodeToString(o.privateKeyBytes)

	o.seedBytes = make([]byte, 32)
	if _, err := rand.Read(o.seedBytes); err != nil {
		return err
	}
	o.Seed = base64.StdEncoding.EncodeToString(o.seedBytes)

	return nil
}

// Obfs4Conn wraps a net.Conn with obfs4 obfuscation
type Obfs4Conn struct {
	net.Conn
	overlay   *Obfs4Overlay
	state     obfs4State
	handshake []byte
	mu        sync.Mutex

	sendKey   [32]byte
	recvKey   [32]byte
	sendNonce uint64
	recvNonce uint64

	paddingDist *probabilityDist
	readBuf     []byte
}

type obfs4State int

const (
	obfs4StateHandshake obfs4State = iota
	obfs4StateEstablished
)

// NewObfs4Conn creates a new obfs4 connection
func NewObfs4Conn(conn net.Conn, overlay *Obfs4Overlay) (*Obfs4Conn, error) {
	c := &Obfs4Conn{
		Conn:        conn,
		overlay:     overlay,
		state:       obfs4StateHandshake,
		paddingDist: newProbabilityDist(overlay.seedBytes),
	}

	if overlay.ServerMode {
		if err := c.serverHandshake(); err != nil {
			return nil, err
		}
	} else {
		if err := c.clientHandshake(); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *Obfs4Conn) clientHandshake() error {
	ephemeralPub, ephemeralPriv, err := generateKeypair()
	if err != nil {
		return err
	}

	handshake := make([]byte, 0, 128)
	handshake = append(handshake, c.overlay.nodeIDBytes...)
	handshake = append(handshake, ephemeralPub...)

	paddingLen := c.paddingDist.randomLength(8192)
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		if _, err := rand.Read(padding); err != nil {
			return err
		}
		key := deriveKey(ephemeralPub, nil)
		encrypted := encryptPadding(padding, key)
		handshake = append(handshake, encrypted...)
	}

	if _, err := c.Conn.Write(handshake); err != nil {
		return err
	}

	sharedSecret, err := curve25519.X25519(ephemeralPriv, c.overlay.publicKeyBytes)
	if err != nil {
		return err
	}

	keys := deriveKeys(sharedSecret, ephemeralPub, c.overlay.publicKeyBytes)
	copy(c.sendKey[:], keys[0:32])
	copy(c.recvKey[:], keys[32:64])

	c.state = obfs4StateEstablished
	return nil
}

func (c *Obfs4Conn) serverHandshake() error {
	buf := make([]byte, 16384)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return err
	}

	if n < 64 {
		return fmt.Errorf("handshake too short")
	}

	nodeID := buf[0:32]
	ephemeralPub := buf[32:64]
	_ = nodeID

	sharedSecret, err := curve25519.X25519(c.overlay.privateKeyBytes, ephemeralPub)
	if err != nil {
		return err
	}

	keys := deriveKeys(sharedSecret, ephemeralPub, c.overlay.publicKeyBytes)
	copy(c.recvKey[:], keys[0:32])
	copy(c.sendKey[:], keys[32:64])

	responsePub, responsePriv, err := generateKeypair()
	if err != nil {
		return err
	}

	response := make([]byte, 0, 128)
	response = append(response, responsePub...)

	paddingLen := c.paddingDist.randomLength(8192)
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		if _, err := rand.Read(padding); err != nil {
			return err
		}
		key := deriveKey(responsePub, nil)
		encrypted := encryptPadding(padding, key)
		response = append(response, encrypted...)
	}

	if _, err := c.Conn.Write(response); err != nil {
		return err
	}

	_ = responsePriv

	c.state = obfs4StateEstablished
	return nil
}

func (c *Obfs4Conn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	var lenBuf [2]byte
	if _, err := c.Conn.Read(lenBuf[:]); err != nil {
		return 0, err
	}
	frameLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if frameLen == 0 || frameLen > 16384 {
		return 0, fmt.Errorf("invalid frame length: %d", frameLen)
	}

	frame := make([]byte, frameLen)
	if _, err := c.Conn.Read(frame); err != nil {
		return 0, err
	}

	plaintext, err := c.decrypt(frame)
	if err != nil {
		return 0, err
	}

	n := copy(b, plaintext)
	if n < len(plaintext) {
		c.readBuf = append(c.readBuf, plaintext[n:]...)
	}

	return n, nil
}

func (c *Obfs4Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	totalWritten := 0
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > 1400 {
			chunkSize = 1400
		}

		ciphertext := c.encrypt(b[:chunkSize])

		var lenBuf [2]byte
		lenBuf[0] = byte(len(ciphertext) >> 8)
		lenBuf[1] = byte(len(ciphertext))
		if _, err := c.Conn.Write(lenBuf[:]); err != nil {
			return totalWritten, err
		}

		if _, err := c.Conn.Write(ciphertext); err != nil {
			return totalWritten, err
		}

		b = b[chunkSize:]
		totalWritten += chunkSize

		if c.overlay.IATMode > 0 && len(b) > 0 {
			delay := c.calculateIATDelay()
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}

	return totalWritten, nil
}

func (c *Obfs4Conn) encrypt(plaintext []byte) []byte {
	var nonce [24]byte
	for i := 0; i < 8; i++ {
		nonce[i] = byte(c.sendNonce >> (i * 8))
	}
	c.sendNonce++

	return secretbox.Seal(nil, plaintext, &nonce, &c.sendKey)
}

func (c *Obfs4Conn) decrypt(ciphertext []byte) ([]byte, error) {
	var nonce [24]byte
	for i := 0; i < 8; i++ {
		nonce[i] = byte(c.recvNonce >> (i * 8))
	}
	c.recvNonce++

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &c.recvKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return plaintext, nil
}

func (c *Obfs4Conn) calculateIATDelay() time.Duration {
	switch c.overlay.IATMode {
	case 1:
		return time.Duration(c.paddingDist.randomLength(100)) * time.Millisecond
	case 2:
		return time.Duration(c.paddingDist.randomLength(500)) * time.Millisecond
	default:
		return 0
	}
}

func generateKeypair() (publicKey, privateKey []byte, err error) {
	privateKey = make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

func deriveKey(secret, salt []byte) []byte {
	h := sha256.New()
	h.Write(secret)
	h.Write(salt)
	return h.Sum(nil)
}

func deriveKeys(sharedSecret, clientPub, serverPub []byte) []byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(clientPub)
	h.Write(serverPub)
	h.Write([]byte("obfs4-key-v1"))
	return h.Sum(nil)
}

func encryptPadding(padding, key []byte) []byte {
	encrypted := make([]byte, len(padding))
	for i := range padding {
		encrypted[i] = padding[i] ^ key[i%len(key)]
	}
	return encrypted
}

type probabilityDist struct {
	seed []byte
}

func newProbabilityDist(seed []byte) *probabilityDist {
	if seed == nil {
		seed = make([]byte, 32)
		rand.Read(seed)
	}
	return &probabilityDist{seed: seed}
}

func (d *probabilityDist) randomLength(max int) int {
	if max <= 0 {
		return 0
	}
	h := sha256.New()
	h.Write(d.seed)
	h.Write([]byte{byte(max >> 24), byte(max >> 16), byte(max >> 8), byte(max)})
	hash := h.Sum(nil)

	val := int(hash[0])<<24 | int(hash[1])<<16 | int(hash[2])<<8 | int(hash[3])
	return val % max
}
