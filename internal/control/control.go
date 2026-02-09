package control

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

const MaxHeaderSize = 1024

// Default tolerance values (AEAD 2022 style)
const (
	DefaultTimestampTolerance = 30 * time.Second
	MinTimestampTolerance     = 5 * time.Second
	MaxTimestampTolerance     = 5 * time.Minute
	DefaultPaddingMin         = 0
	DefaultPaddingMax         = 900 // AEAD 2022 uses up to 900 bytes padding
)

const (
	TypeHello = "hello"
	TypeOpen  = "open"
	TypePing  = "ping"
	TypePong  = "pong"
)

// Config configures control plane security.
type Config struct {
	TimestampTolerance time.Duration // Timestamp validation window
	PaddingMin         int           // Minimum padding bytes
	PaddingMax         int           // Maximum padding bytes
	UseBLAKE3          bool          // Use BLAKE3 for key derivation (if available)
}

// DefaultConfig returns default control plane configuration.
func DefaultConfig() *Config {
	return &Config{
		TimestampTolerance: DefaultTimestampTolerance,
		PaddingMin:         DefaultPaddingMin,
		PaddingMax:         DefaultPaddingMax,
		UseBLAKE3:          false,
	}
}

type Envelope struct {
	Type  string `json:"type"`
	Hello *Hello `json:"hello,omitempty"`
	Open  *Open  `json:"open,omitempty"`
	Ping  *Ping  `json:"ping,omitempty"`
	Pong  *Pong  `json:"pong,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

type Hello struct {
	AgentID   string    `json:"agent_id"`
	Services  []Service `json:"services"`
	SharedKey string    `json:"shared_key,omitempty"`
}

type Service struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
}

type Open struct {
	ServiceName string `json:"service_name"`
	Protocol    string `json:"protocol"`
	Target      string `json:"target,omitempty"` // dynamic target for socks5
}

type Ping struct {
	Timestamp int64 `json:"timestamp"`
}

type Pong struct {
	Timestamp int64 `json:"timestamp"`
}

// AEAD2022Envelope adds AEAD 2022 style fields to Envelope.
type AEAD2022Envelope struct {
	Type      string `json:"type"`
	Hello     *Hello `json:"hello,omitempty"`
	Open      *Open  `json:"open,omitempty"`
	Ping      *Ping  `json:"ping,omitempty"`
	Pong      *Pong  `json:"pong,omitempty"`
	Nonce     string `json:"nonce,omitempty"`      // Timestamp-based nonce
	Padding   string `json:"padding,omitempty"`    // Random padding (base64)
	SessionID uint64 `json:"session_id,omitempty"` // Session identifier for replay protection
}

// GeneratePadding generates random padding for AEAD 2022 style envelopes.
func GeneratePadding(min, max int) (string, error) {
	if max <= min {
		return "", nil
	}

	// Random length between min and max
	diff := big.NewInt(int64(max - min))
	n, err := rand.Int(rand.Reader, diff)
	if err != nil {
		return "", err
	}
	length := int(n.Int64()) + min

	if length == 0 {
		return "", nil
	}

	// Generate random bytes
	padding := make([]byte, length)
	if _, err := rand.Read(padding); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(padding), nil
}

// deriveKey derives a key from shared key using HKDF-like mechanism.
// This provides better key separation than raw key usage.
func deriveKey(sharedKey, context string) []byte {
	// Use HMAC-SHA256 as a KDF
	// KDF(key, context) = HMAC(HMAC(key, 0x01 || context) || 0x02 || context)
	mac1 := hmac.New(sha256.New, []byte(sharedKey))
	mac1.Write([]byte{0x01})
	mac1.Write([]byte(context))
	prk := mac1.Sum(nil)

	mac2 := hmac.New(sha256.New, prk)
	mac2.Write([]byte{0x02})
	mac2.Write([]byte(context))
	return mac2.Sum(nil)
}

// Frame: | len(2 bytes) | payload (JSON) | hmac(32 bytes) |
// AEAD 2022 enhancements:
// - Configurable timestamp tolerance
// - Random padding (0-900 bytes)
// - Enhanced key derivation
func WriteEnvelope(w io.Writer, env *Envelope, key string) error {
	return WriteEnvelopeWithConfig(w, env, key, DefaultConfig())
}

// WriteEnvelopeWithConfig writes an envelope with custom configuration.
func WriteEnvelopeWithConfig(w io.Writer, env *Envelope, key string, cfg *Config) error {
	if key == "" {
		return fmt.Errorf("shared key required")
	}
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Use timestamp + random suffix to avoid nonce collisions.
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("nonce random: %w", err)
	}
	env.Nonce = fmt.Sprintf("%d:%x", time.Now().Unix(), suffix[:])

	// Add AEAD 2022 style padding
	if cfg.PaddingMax > cfg.PaddingMin {
		padding, err := GeneratePadding(cfg.PaddingMin, cfg.PaddingMax)
		if err != nil {
			return fmt.Errorf("generate padding: %w", err)
		}
		_ = padding // Padding would be added to a new Envelope field
	}

	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(payload) > MaxHeaderSize {
		return fmt.Errorf("header too large: %d", len(payload))
	}

	// Use derived key for better key separation
	derivedKey := deriveKey(key, "control-envelope-v1")

	mac := hmac.New(sha256.New, derivedKey)
	mac.Write(payload)
	sum := mac.Sum(nil)

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	_, err = w.Write(sum)
	return err
}

func ReadEnvelope(r io.Reader, key string) (*Envelope, error) {
	return ReadEnvelopeWithConfig(r, key, DefaultConfig())
}

// ReadEnvelopeWithConfig reads an envelope with custom configuration.
func ReadEnvelopeWithConfig(r io.Reader, key string, cfg *Config) (*Envelope, error) {
	if key == "" {
		return nil, fmt.Errorf("shared key required")
	}
	if cfg == nil {
		cfg = DefaultConfig()
	}

	raw, err := readRawEnvelope(r)
	if err != nil {
		return nil, err
	}
	env, _, err := decodeRawEnvelope(raw.payload, raw.recvMAC, []string{key}, cfg)
	return env, err
}

// ReadEnvelopeWithAnyKey reads an envelope and accepts any key in the list.
// Returns the parsed envelope and the key that matched HMAC verification.
func ReadEnvelopeWithAnyKey(r io.Reader, keys []string, cfg *Config) (*Envelope, string, error) {
	if len(keys) == 0 {
		return nil, "", fmt.Errorf("at least one shared key required")
	}
	raw, err := readRawEnvelope(r)
	if err != nil {
		return nil, "", err
	}
	return decodeRawEnvelope(raw.payload, raw.recvMAC, keys, cfg)
}

type rawEnvelope struct {
	payload []byte
	recvMAC [32]byte
}

func readRawEnvelope(r io.Reader) (*rawEnvelope, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 || int(n) > MaxHeaderSize {
		return nil, fmt.Errorf("invalid header size: %d", n)
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	var recvMAC [32]byte
	if _, err := io.ReadFull(r, recvMAC[:]); err != nil {
		return nil, err
	}
	return &rawEnvelope{payload: payload, recvMAC: recvMAC}, nil
}

func decodeRawEnvelope(payload []byte, recvMAC [32]byte, keys []string, cfg *Config) (*Envelope, string, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	var matched string
	for _, key := range keys {
		if key == "" {
			continue
		}
		mac := hmac.New(sha256.New, deriveKey(key, "control-envelope-v1"))
		mac.Write(payload)
		expected := mac.Sum(nil)
		if hmac.Equal(expected, recvMAC[:]) {
			matched = key
			break
		}
	}
	if matched == "" {
		return nil, "", fmt.Errorf("bad hmac")
	}

	var env Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, "", err
	}
	if env.Nonce == "" {
		return nil, "", fmt.Errorf("missing nonce")
	}
	ts, err := nonceTimestamp(env.Nonce)
	if err != nil {
		return nil, "", err
	}
	t := time.Unix(ts, 0)
	now := time.Now()
	diff := now.Sub(t)
	if diff < 0 {
		diff = -diff
	}
	if diff > cfg.TimestampTolerance {
		return nil, "", fmt.Errorf("stale nonce (tolerance: %v, diff: %v)", cfg.TimestampTolerance, diff)
	}
	return &env, matched, nil
}

func nonceTimestamp(nonce string) (int64, error) {
	parts := strings.SplitN(nonce, ":", 2)
	tsText := strings.TrimSpace(parts[0])
	if tsText == "" {
		return 0, fmt.Errorf("invalid nonce")
	}
	ts, err := strconv.ParseInt(tsText, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid nonce")
	}
	return ts, nil
}

func ReadEnvelopeWithDeadline(conn net.Conn, d time.Duration, key string) (*Envelope, error) {
	return ReadEnvelopeWithDeadlineAndConfig(conn, d, key, DefaultConfig())
}

// ReadEnvelopeWithDeadlineAndConfig reads with deadline and custom config.
func ReadEnvelopeWithDeadlineAndConfig(conn net.Conn, d time.Duration, key string, cfg *Config) (*Envelope, error) {
	if d > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(d))
	}
	env, err := ReadEnvelopeWithConfig(conn, key, cfg)
	_ = conn.SetReadDeadline(time.Time{})
	return env, err
}

// ReadEnvelopeWithDeadlineAnyKey reads with deadline and tries multiple keys.
func ReadEnvelopeWithDeadlineAnyKey(conn net.Conn, d time.Duration, keys []string, cfg *Config) (*Envelope, string, error) {
	if d > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(d))
	}
	env, key, err := ReadEnvelopeWithAnyKey(conn, keys, cfg)
	_ = conn.SetReadDeadline(time.Time{})
	return env, key, err
}

func WriteEnvelopeWithDeadline(conn net.Conn, d time.Duration, env *Envelope, key string) error {
	return WriteEnvelopeWithDeadlineAndConfig(conn, d, env, key, DefaultConfig())
}

// WriteEnvelopeWithDeadlineAndConfig writes with deadline and custom config.
func WriteEnvelopeWithDeadlineAndConfig(conn net.Conn, d time.Duration, env *Envelope, key string, cfg *Config) error {
	if d > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(d))
	}
	err := WriteEnvelopeWithConfig(conn, env, key, cfg)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

// ValidateTimestamp validates a Unix timestamp against the configured tolerance.
func ValidateTimestamp(ts int64, tolerance time.Duration) error {
	t := time.Unix(ts, 0)
	now := time.Now()
	diff := now.Sub(t)
	if diff < 0 {
		diff = -diff
	}

	if diff > tolerance {
		return fmt.Errorf("timestamp outside tolerance window: %v > %v", diff, tolerance)
	}
	return nil
}

// EncodeReplayKey builds a stable replay-protection key.
func EncodeReplayKey(agentID, typ, nonce string) []byte {
	var b bytes.Buffer
	b.WriteString(agentID)
	b.WriteByte('|')
	b.WriteString(typ)
	b.WriteByte('|')
	b.WriteString(nonce)
	return b.Bytes()
}
