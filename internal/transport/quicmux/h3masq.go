// Package quicmux implements HTTP/3 masquerading for QUIC transport.
package quicmux

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// H3MasqueradeConfig configures HTTP/3 masquerading behavior.
// Based on Hysteria's HTTP/3 authentication protocol.
type H3MasqueradeConfig struct {
	Enabled      bool          `yaml:"enabled"`
	AuthMin      int           `yaml:"auth_min"`       // Min auth padding (default: 256)
	AuthMax      int           `yaml:"auth_max"`       // Max auth padding (default: 2048)
	DataMin      int           `yaml:"data_min"`       // Min data padding (default: 64)
	DataMax      int           `yaml:"data_max"`       // Max data padding (default: 1024)
	CustomStatus int           `yaml:"custom_status"`  // Custom HTTP status (default: 233)
	StatusText   string        `yaml:"status_text"`    // Custom status text (default: "HyOK")
	Headers      H3Headers     `yaml:"headers"`        // Custom headers
}

// H3Headers contains Hysteria-style HTTP/3 headers.
type H3Headers struct {
	AuthHeader    string `yaml:"auth_header"`     // Authentication header name
	CCRXHeader    string `yaml:"cc_rx_header"`    // Congestion control RX header
	CCBandwidth   int    `yaml:"cc_bandwidth"`    // Bandwidth in Mbps
	PaddingHeader string `yaml:"padding_header"`  // Padding header name
}

// ApplyDefaults sets default values for H3 masquerade config.
func (c *H3MasqueradeConfig) ApplyDefaults() {
	if c.AuthMin <= 0 {
		c.AuthMin = 256
	}
	if c.AuthMax <= 0 {
		c.AuthMax = 2048
	}
	if c.AuthMax < c.AuthMin {
		c.AuthMax = c.AuthMin
	}
	if c.DataMin <= 0 {
		c.DataMin = 64
	}
	if c.DataMax <= 0 {
		c.DataMax = 1024
	}
	if c.DataMax < c.DataMin {
		c.DataMax = c.DataMin
	}
	if c.CustomStatus <= 0 {
		c.CustomStatus = 233 // Hysteria's custom status code
	}
	if c.StatusText == "" {
		c.StatusText = "HyOK"
	}
	if c.Headers.AuthHeader == "" {
		c.Headers.AuthHeader = "Hysteria-Auth"
	}
	if c.Headers.CCRXHeader == "" {
		c.Headers.CCRXHeader = "Hysteria-CC-RX"
	}
	if c.Headers.PaddingHeader == "" {
		c.Headers.PaddingHeader = "Hysteria-Padding"
	}
}

// GenerateAuthPadding generates random padding for authentication.
func (c *H3MasqueradeConfig) GenerateAuthPadding() []byte {
	c.ApplyDefaults()

	size := c.AuthMin
	if c.AuthMax > c.AuthMin {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(c.AuthMax-c.AuthMin)))
		size += int(n.Int64())
	}

	padding := make([]byte, size)
	rand.Read(padding)
	return padding
}

// GenerateDataPadding generates random padding for data frames.
func (c *H3MasqueradeConfig) GenerateDataPadding() []byte {
	c.ApplyDefaults()

	size := c.DataMin
	if c.DataMax > c.DataMin {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(c.DataMax-c.DataMin)))
		size += int(n.Int64())
	}

	padding := make([]byte, size)
	rand.Read(padding)
	return padding
}

// AuthRequest represents an HTTP/3 authentication request.
type AuthRequest struct {
	ProtocolVersion uint8
	AuthPadding     []byte
	Timestamp       int64
}

// Marshal serializes the auth request.
func (r *AuthRequest) Marshal() []byte {
	// Format: [version:1][timestamp:8][padding_len:2][padding...]
	buf := make([]byte, 1+8+2+len(r.AuthPadding))
	buf[0] = r.ProtocolVersion
	binary.BigEndian.PutUint64(buf[1:9], uint64(r.Timestamp))
	binary.BigEndian.PutUint16(buf[9:11], uint16(len(r.AuthPadding)))
	copy(buf[11:], r.AuthPadding)
	return buf
}

// Unmarshal deserializes the auth request.
func (r *AuthRequest) Unmarshal(data []byte) error {
	if len(data) < 11 {
		return fmt.Errorf("auth request too short")
	}

	r.ProtocolVersion = data[0]
	r.Timestamp = int64(binary.BigEndian.Uint64(data[1:9]))
	paddingLen := binary.BigEndian.Uint16(data[9:11])

	if len(data) < 11+int(paddingLen) {
		return fmt.Errorf("auth request padding truncated")
	}

	r.AuthPadding = make([]byte, paddingLen)
	copy(r.AuthPadding, data[11:11+paddingLen])
	return nil
}

// IsValid checks if the auth request is valid (not expired).
func (r *AuthRequest) IsValid(maxAge time.Duration) bool {
	if maxAge <= 0 {
		maxAge = 30 * time.Second
	}
	return time.Since(time.Unix(r.Timestamp, 0)) <= maxAge
}

// AuthResponse represents an HTTP/3 authentication response.
type AuthResponse struct {
	StatusCode  int
	StatusText  string
	Padding     []byte
	Headers     map[string]string
}

// Marshal serializes the auth response.
func (r *AuthResponse) Marshal() []byte {
	// Format: [status_code:2][status_len:1][status_text...][padding_len:2][padding...]
	statusText := []byte(r.StatusText)
	buf := make([]byte, 2+1+len(statusText)+2+len(r.Padding))

	offset := 0
	binary.BigEndian.PutUint16(buf[offset:], uint16(r.StatusCode))
	offset += 2
	buf[offset] = uint8(len(statusText))
	offset++
	copy(buf[offset:], statusText)
	offset += len(statusText)
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(r.Padding)))
	offset += 2
	copy(buf[offset:], r.Padding)

	return buf
}

// NewAuthResponse creates a new auth response with generated padding.
func NewAuthResponse(config *H3MasqueradeConfig, success bool) *AuthResponse {
	config.ApplyDefaults()

	statusCode := config.CustomStatus
	if !success {
		statusCode = 401
	}

	return &AuthResponse{
		StatusCode: statusCode,
		StatusText: config.StatusText,
		Padding:    config.GenerateAuthPadding(),
		Headers: map[string]string{
			config.Headers.PaddingHeader: fmt.Sprintf("%d", len(config.GenerateAuthPadding())),
		},
	}
}

// H3Masquerader handles HTTP/3 masquerading.
type H3Masquerader struct {
	config *H3MasqueradeConfig
}

// NewH3Masquerader creates a new HTTP/3 masquerader.
func NewH3Masquerader(config *H3MasqueradeConfig) *H3Masquerader {
	if config == nil {
		config = &H3MasqueradeConfig{}
	}
	config.ApplyDefaults()
	return &H3Masquerader{config: config}
}

// GenerateAuthRequest generates a new authentication request.
func (m *H3Masquerader) GenerateAuthRequest(version uint8) *AuthRequest {
	return &AuthRequest{
		ProtocolVersion: version,
		AuthPadding:     m.config.GenerateAuthPadding(),
		Timestamp:       time.Now().Unix(),
	}
}

// VerifyAuthRequest verifies an authentication request.
func (m *H3Masquerader) VerifyAuthRequest(req *AuthRequest) bool {
	return req.IsValid(30 * time.Second)
}

// GetAuthHeaders returns the HTTP/3 authentication headers.
func (m *H3Masquerader) GetAuthHeaders(authToken string) map[string]string {
	return map[string]string{
		m.config.Headers.AuthHeader:    authToken,
		m.config.Headers.PaddingHeader: fmt.Sprintf("%d", len(m.config.GenerateDataPadding())),
	}
}

// GetStatusLine returns the custom HTTP status line.
func (m *H3Masquerader) GetStatusLine() string {
	return fmt.Sprintf("HTTP/3 %d %s", m.config.CustomStatus, m.config.StatusText)
}
