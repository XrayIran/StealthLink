// Package ech implements Encrypted Client Hello (ECH) support.
// ECH encrypts the Server Name Indication (SNI) in TLS Client Hello messages,
// preventing network observers from determining the destination server.
// Based on draft-ietf-tls-esni.
package ech

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"stealthlink/internal/tlsutil"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// ECH version
	ECHVersion = 0xfe0d

	// Maximum ECH config size
	MaxECHConfigSize = 65535
)

var (
	defaultResolver = tlsutil.NewECHResolver(tlsutil.ECHConfig{Enabled: true})
	fetchCacheMu    sync.RWMutex
	fetchCache      = map[string]cachedFetch{}
)

type cachedFetch struct {
	configs []*ECHConfig
	expiry  time.Time
}

// ECHConfig represents an ECH configuration.
type ECHConfig struct {
	Version     uint16
	PublicKey   []byte
	CipherSuite CipherSuite
	Extensions  []ECHExtension
	ID          uint8
}

// CipherSuite represents an ECH cipher suite.
type CipherSuite struct {
	KDFID  uint16
	AEADID uint16
}

// ECHExtension represents an ECH extension.
type ECHExtension struct {
	Type   uint16
	Length uint16
	Data   []byte
}

// ClientConfig holds client-side ECH configuration.
type ClientConfig struct {
	// ECH configs retrieved from DNS HTTPS records
	Configs []*ECHConfig

	// Server public name (outer SNI)
	PublicName string

	// Inner SNI (actual destination, encrypted)
	InnerSNI string

	// Whether to require ECH (fail if no valid config)
	RequireECH bool
}

// ServerConfig holds server-side ECH configuration.
type ServerConfig struct {
	// Private key for ECH decryption
	PrivateKey []byte

	// Public key (published in DNS)
	PublicKey []byte

	// Config ID
	ConfigID uint8

	// Cipher suite
	CipherSuite CipherSuite

	// Maximum age for ECH configs
	MaxAge time.Duration
}

// GenerateECHKeyPair generates an X25519 key pair for ECH.
func GenerateECHKeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// GenerateECHConfig generates a new ECH config for publishing in DNS.
func GenerateECHConfig(privateKey, publicKey []byte, configID uint8) *ECHConfig {
	return &ECHConfig{
		Version:   ECHVersion,
		ID:        configID,
		PublicKey: publicKey,
		CipherSuite: CipherSuite{
			KDFID:  0x0001, // HKDF-SHA256
			AEADID: 0x0001, // AES-128-GCM
		},
		Extensions: []ECHExtension{
			{
				Type:   0x0001, // "maximum_name_length"
				Length: 2,
				Data:   []byte{0x00, 0x40}, // 64 bytes max
			},
		},
	}
}

// Encode encodes the ECH config for DNS HTTPS record.
func (c *ECHConfig) Encode() ([]byte, error) {
	var buf []byte

	// Version
	buf = binary.BigEndian.AppendUint16(buf, c.Version)

	// Config ID
	buf = append(buf, c.ID)

	// Cipher suite
	buf = binary.BigEndian.AppendUint16(buf, c.CipherSuite.KDFID)
	buf = binary.BigEndian.AppendUint16(buf, c.CipherSuite.AEADID)

	// Public key length and key
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.PublicKey)))
	buf = append(buf, c.PublicKey...)

	// Extensions length
	extLen := 0
	for _, ext := range c.Extensions {
		extLen += 4 + len(ext.Data)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(extLen))

	// Extensions
	for _, ext := range c.Extensions {
		buf = binary.BigEndian.AppendUint16(buf, ext.Type)
		buf = binary.BigEndian.AppendUint16(buf, ext.Length)
		buf = append(buf, ext.Data...)
	}

	return buf, nil
}

// DecodeECHConfig decodes an ECH config from bytes.
func DecodeECHConfig(data []byte) (*ECHConfig, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("config too short")
	}

	offset := 0

	cfg := &ECHConfig{}

	// Version
	cfg.Version = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if cfg.Version != ECHVersion {
		return nil, fmt.Errorf("unsupported version: 0x%04x", cfg.Version)
	}

	// Config ID
	cfg.ID = data[offset]
	offset++

	// Cipher suite
	cfg.CipherSuite.KDFID = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	cfg.CipherSuite.AEADID = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Public key length
	pubKeyLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if len(data) < offset+int(pubKeyLen)+2 {
		return nil, fmt.Errorf("truncated config")
	}

	// Public key
	cfg.PublicKey = data[offset : offset+int(pubKeyLen)]
	offset += int(pubKeyLen)

	// Extensions length
	extLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Extensions
	if extLen > 0 {
		extEnd := offset + int(extLen)
		for offset < extEnd {
			if offset+4 > extEnd {
				return nil, fmt.Errorf("truncated extension")
			}
			ext := ECHExtension{
				Type:   binary.BigEndian.Uint16(data[offset:]),
				Length: binary.BigEndian.Uint16(data[offset+2:]),
			}
			offset += 4
			if offset+int(ext.Length) > extEnd {
				return nil, fmt.Errorf("truncated extension data")
			}
			ext.Data = data[offset : offset+int(ext.Length)]
			offset += int(ext.Length)
			cfg.Extensions = append(cfg.Extensions, ext)
		}
	}

	return cfg, nil
}

// ECHClient provides ECH encryption for TLS clients.
type ECHClient struct {
	config     *ClientConfig
	ephPrivKey []byte
	ephPubKey  []byte
}

// NewECHClient creates a new ECH client.
func NewECHClient(config *ClientConfig) (*ECHClient, error) {
	// Generate ephemeral key pair
	privKey, pubKey, err := GenerateECHKeyPair()
	if err != nil {
		return nil, err
	}

	return &ECHClient{
		config:     config,
		ephPrivKey: privKey,
		ephPubKey:  pubKey,
	}, nil
}

// Encrypt encrypts the inner Client Hello using ECH.
// Returns the encrypted payload and encapsulation key.
func (c *ECHClient) Encrypt(innerCH []byte, echConfig *ECHConfig) (encryptedCH, encapKey []byte, err error) {
	// Derive shared secret using X25519
	sharedSecret, err := curve25519.X25519(c.ephPrivKey, echConfig.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("derive shared secret: %w", err)
	}

	// Derive encryption key using HKDF
	key := c.deriveKey(sharedSecret, echConfig.CipherSuite)

	// Encrypt the inner Client Hello
	encryptedCH, err = c.encryptAEAD(key, innerCH)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt: %w", err)
	}

	// Encapsulation key is the ephemeral public key
	return encryptedCH, c.ephPubKey, nil
}

// deriveKey derives an encryption key using HKDF.
func (c *ECHClient) deriveKey(sharedSecret []byte, cs CipherSuite) []byte {
	// For HKDF-SHA256 + AES-128-GCM
	salt := []byte("ech_key_derivation")
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, nil)

	key := make([]byte, 16) // AES-128
	io.ReadFull(hkdfReader, key)

	return key
}

// encryptAEAD encrypts using AES-GCM.
func (c *ECHClient) encryptAEAD(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// ECHServer provides ECH decryption for TLS servers.
type ECHServer struct {
	config *ServerConfig
}

// NewECHServer creates a new ECH server.
func NewECHServer(config *ServerConfig) *ECHServer {
	return &ECHServer{config: config}
}

// Decrypt decrypts the ECH payload.
func (s *ECHServer) Decrypt(encryptedCH, encapKey []byte, cs CipherSuite) ([]byte, error) {
	// Derive shared secret
	sharedSecret, err := curve25519.X25519(s.config.PrivateKey, encapKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}

	// Derive key
	key := s.deriveKey(sharedSecret, cs)

	// Decrypt
	plaintext, err := s.decryptAEAD(key, encryptedCH)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// deriveKey derives a decryption key.
func (s *ECHServer) deriveKey(sharedSecret []byte, cs CipherSuite) []byte {
	salt := []byte("ech_key_derivation")
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, nil)

	key := make([]byte, 16)
	io.ReadFull(hkdfReader, key)

	return key
}

// decryptAEAD decrypts using AES-GCM.
func (s *ECHServer) decryptAEAD(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// FetchECHConfigs retrieves ECH configurations from DNS HTTPS records.
func FetchECHConfigs(hostname string) ([]*ECHConfig, error) {
	fetchCacheMu.RLock()
	if cached, ok := fetchCache[hostname]; ok && time.Now().Before(cached.expiry) {
		out := make([]*ECHConfig, len(cached.configs))
		copy(out, cached.configs)
		fetchCacheMu.RUnlock()
		return out, nil
	}
	fetchCacheMu.RUnlock()

	record, err := defaultResolver.Resolve(context.Background(), hostname)
	if err != nil {
		return nil, fmt.Errorf("resolve ECH config: %w", err)
	}

	configList := tlsutil.NormalizeECHConfigList(record.Config)
	cfg, err := DecodeECHConfig(configList)
	if err == nil {
		out := []*ECHConfig{cfg}
		cacheFetch(hostname, out, record.Expiry)
		return out, nil
	}

	configs, listErr := decodeECHConfigList(configList)
	if listErr != nil {
		return nil, fmt.Errorf("decode ECH config: %w", err)
	}
	cacheFetch(hostname, configs, record.Expiry)
	return configs, nil
}

// InvalidateECHConfigs clears both resolver and decoded-config caches for a hostname.
func InvalidateECHConfigs(hostname string) {
	defaultResolver.Invalidate(hostname)
	fetchCacheMu.Lock()
	delete(fetchCache, hostname)
	fetchCacheMu.Unlock()
}

func cacheFetch(hostname string, configs []*ECHConfig, expiry time.Time) {
	out := make([]*ECHConfig, len(configs))
	copy(out, configs)
	fetchCacheMu.Lock()
	fetchCache[hostname] = cachedFetch{
		configs: out,
		expiry:  expiry,
	}
	fetchCacheMu.Unlock()
}

func decodeECHConfigList(data []byte) ([]*ECHConfig, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("ECH config list too short")
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if listLen > len(data)-2 {
		return nil, fmt.Errorf("ECH config list truncated")
	}
	offset := 2
	end := 2 + listLen
	var out []*ECHConfig
	for offset < end {
		if offset+2 > end {
			return nil, fmt.Errorf("ECH config length truncated")
		}
		cfgLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+cfgLen > end {
			return nil, fmt.Errorf("ECH config entry truncated")
		}
		cfg, err := DecodeECHConfig(data[offset : offset+cfgLen])
		if err != nil {
			return nil, err
		}
		out = append(out, cfg)
		offset += cfgLen
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ECH config list is empty")
	}
	return out, nil
}

// BuildOuterClientHello builds the outer Client Hello with ECH extension.
func BuildOuterClientHello(publicName string, echExtension []byte, baseConfig *tls.Config) ([]byte, error) {
	// Build a Client Hello with:
	// - Outer SNI = public_name (e.g., cloudflare-ech.com)
	// - Encrypted Client Hello extension

	var buf []byte

	// Record layer
	buf = append(buf, 0x16)       // Handshake
	buf = append(buf, 0x03, 0x01) // TLS 1.0 (legacy)

	// Handshake header (length will be filled later)
	buf = append(buf, 0x01) // Client Hello
	handshakeLenPos := len(buf)
	buf = append(buf, 0, 0, 0) // Placeholder

	// Client Version
	buf = append(buf, 0x03, 0x03) // TLS 1.2

	// Random (32 bytes)
	random := make([]byte, 32)
	rand.Read(random)
	buf = append(buf, random...)

	// Session ID (0 length)
	buf = append(buf, 0)

	// Cipher suites
	buf = append(buf, 0, 4)       // Length
	buf = append(buf, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	buf = append(buf, 0x13, 0x02) // TLS_AES_256_GCM_SHA384

	// Compression methods
	buf = append(buf, 1, 0)

	// Extensions length placeholder
	extLenPos := len(buf)
	buf = append(buf, 0, 0)

	// SNI extension
	sniExt := buildSNIExtension(publicName)
	buf = append(buf, sniExt...)

	// ECH extension
	buf = append(buf, 0xfe, 0x0d) // ECH extension type
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(echExtension)))
	buf = append(buf, echExtension...)

	// Fill in lengths
	extLen := len(buf) - extLenPos - 2
	buf[extLenPos] = byte(extLen >> 8)
	buf[extLenPos+1] = byte(extLen)

	handshakeLen := len(buf) - handshakeLenPos - 3
	buf[handshakeLenPos] = byte(handshakeLen >> 16)
	buf[handshakeLenPos+1] = byte(handshakeLen >> 8)
	buf[handshakeLenPos+2] = byte(handshakeLen)

	// Fill in record length
	recordLen := len(buf) - 5
	buf[3] = byte(recordLen >> 8)
	buf[4] = byte(recordLen)

	return buf, nil
}

// buildSNIExtension builds an SNI extension.
func buildSNIExtension(serverName string) []byte {
	var buf []byte

	buf = binary.BigEndian.AppendUint16(buf, 0) // SNI extension type

	sniData := make([]byte, 0)
	sniData = binary.BigEndian.AppendUint16(sniData, uint16(len(serverName)+3))
	sniData = append(sniData, 0) // Host name type
	sniData = binary.BigEndian.AppendUint16(sniData, uint16(len(serverName)))
	sniData = append(sniData, []byte(serverName)...)

	buf = binary.BigEndian.AppendUint16(buf, uint16(len(sniData)))
	buf = append(buf, sniData...)

	return buf
}

// EncryptedConn wraps a net.Conn with ECH capability.
type EncryptedConn struct {
	net.Conn
	innerSNI string
	outerSNI string
}

// InnerSNI returns the decrypted inner SNI.
func (c *EncryptedConn) InnerSNI() string {
	return c.innerSNI
}

// OuterSNI returns the outer SNI visible to observers.
func (c *EncryptedConn) OuterSNI() string {
	return c.outerSNI
}

// ConfigForClient returns TLS configuration for ECH.
func ConfigForClient(serverConfig *ServerConfig) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// Check for ECH extension in Client Hello
		// If present, decrypt to get inner SNI
		// Otherwise, return normal config

		// This is a simplified version - real implementation would:
		// 1. Parse the Client Hello
		// 2. Extract ECH extension
		// 3. Decrypt using server private key
		// 4. Return config for inner SNI

		return nil, nil // Use default config
	}
}

// Base64Encode encodes ECH config for HTTPS DNS record.
func Base64Encode(config *ECHConfig) (string, error) {
	encoded, err := config.Encode()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

// Base64Decode decodes ECH config from HTTPS DNS record.
func Base64Decode(encoded string) (*ECHConfig, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return DecodeECHConfig(decoded)
}

// Client wraps an HTTP client with ECH support.
type Client struct {
	HTTPClient *http.Client
	ECHConfig  *ClientConfig
}

// NewClient creates an HTTP client with ECH support.
func NewClient(config *ClientConfig) *Client {
	transport := &http.Transport{}
	if config != nil {
		echDialer := tlsutil.NewECHDialer(tlsutil.ECHConfig{
			Enabled:      true,
			RetryWithout: !config.RequireECH,
		})
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return echDialer.Dial(ctx, network, addr)
		}
	}

	return &Client{
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		ECHConfig: config,
	}
}
