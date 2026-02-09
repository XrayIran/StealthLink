// Package tlsutil provides TLS utilities including TLSMirror for fetching
// live session tickets from real sites to replay to clients.
package tlsutil

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// MirrorState holds captured TLS state from a real site.
type MirrorState struct {
	ServerName    string              `json:"server_name"`
	Version       uint16              `json:"version"`
	CipherSuite   uint16              `json:"cipher_suite"`
	Certificates  [][]byte            `json:"certificates"`
	SessionTicket []byte              `json:"session_ticket"`
	OCSPResponse  []byte              `json:"ocsp_response"`
	SCTList       []byte              `json:"sct_list"`
	ALPN          string              `json:"alpn"`
	Extensions    []ExtensionInfo     `json:"extensions"`
	Timestamp     time.Time           `json:"timestamp"`
	TTL           time.Duration       `json:"ttl"`
}

// ExtensionInfo holds information about a TLS extension.
type ExtensionInfo struct {
	Type uint16 `json:"type"`
	Data []byte `json:"data"`
}

// MirrorEnrollment connects to a real target and captures its TLS state.
// This can be used to make our TLS look indistinguishable from the real site.
func MirrorEnrollment(target string) (*MirrorState, error) {
	// Ensure target has port
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}

	// Connect and perform TLS handshake
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("connect to target: %w", err)
	}
	defer conn.Close()

	// Get server name
	host, _, _ := net.SplitHostPort(target)
	if host == "" {
		host = target
	}

	// Perform TLS handshake
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // We're just capturing, not verifying
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()

	// Capture state
	mirror := &MirrorState{
		ServerName:   host,
		Version:      state.Version,
		CipherSuite:  state.CipherSuite,
		ALPN:         state.NegotiatedProtocol,
		Timestamp:    time.Now(),
		TTL:          24 * time.Hour, // Default TTL
	}

	// Capture certificates
	for _, cert := range state.PeerCertificates {
		mirror.Certificates = append(mirror.Certificates, cert.Raw)
	}

	// Capture OCSP response
	mirror.OCSPResponse = state.OCSPResponse

	return mirror, nil
}

// MirrorEnrollmentUTLS performs enrollment using uTLS for fingerprint matching.
func MirrorEnrollmentUTLS(target, fingerprint string) (*MirrorState, error) {
	// Ensure target has port
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}

	// Get server name
	host, _, _ := net.SplitHostPort(target)
	if host == "" {
		host = target
	}

	// Use uTLS for fingerprint matching
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := DialUTLS(ctx, "tcp", target, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("uTLS dial: %w", err)
	}
	defer conn.Close()

	// Get connection state
	uconn := conn.(*utls.UConn)
	state := uconn.ConnectionState()

	mirror := &MirrorState{
		ServerName:  host,
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
		ALPN:        state.NegotiatedProtocol,
		Timestamp:   time.Now(),
		TTL:         24 * time.Hour,
	}

	// Capture certificates
	for _, cert := range state.PeerCertificates {
		mirror.Certificates = append(mirror.Certificates, cert.Raw)
	}

	return mirror, nil
}

// IsExpired returns true if the mirror state has expired.
func (m *MirrorState) IsExpired() bool {
	return time.Since(m.Timestamp) > m.TTL
}

// TimeRemaining returns the remaining time before expiration.
func (m *MirrorState) TimeRemaining() time.Duration {
	remaining := m.TTL - time.Since(m.Timestamp)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ToJSON serializes the mirror state to JSON.
func (m *MirrorState) ToJSON() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// FromJSON deserializes the mirror state from JSON.
func FromJSON(data []byte) (*MirrorState, error) {
	var m MirrorState
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// MirrorCache caches mirror states for multiple targets.
type MirrorCache struct {
	states map[string]*MirrorState
	mu     sync.RWMutex
}

// NewMirrorCache creates a new mirror cache.
func NewMirrorCache() *MirrorCache {
	return &MirrorCache{
		states: make(map[string]*MirrorState),
	}
}

// Get gets a cached mirror state.
func (c *MirrorCache) Get(target string) (*MirrorState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	state, ok := c.states[target]
	if !ok {
		return nil, false
	}

	if state.IsExpired() {
		return nil, false
	}

	return state, true
}

// Set caches a mirror state.
func (c *MirrorCache) Set(target string, state *MirrorState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.states[target] = state
}

// Delete removes a cached mirror state.
func (c *MirrorCache) Delete(target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.states, target)
}

// Refresh refreshes an expired or missing mirror state.
func (c *MirrorCache) Refresh(target string, fingerprint string) (*MirrorState, error) {
	state, ok := c.Get(target)
	if ok {
		return state, nil
	}

	state, err := MirrorEnrollmentUTLS(target, fingerprint)
	if err != nil {
		return nil, err
	}

	c.Set(target, state)
	return state, nil
}

// CleanExpired removes expired entries from the cache.
func (c *MirrorCache) CleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for target, state := range c.states {
		if state.IsExpired() {
			delete(c.states, target)
		}
	}
}

// ApplyToConfig applies the mirror state to a TLS config.
func (m *MirrorState) ApplyToConfig(cfg *tls.Config) {
	// Note: Most of these can't actually be applied to a standard tls.Config
	// This is more for documentation/reference purposes
	cfg.ServerName = m.ServerName
	cfg.NextProtos = []string{m.ALPN}
}

// CipherSuiteName returns the name of the cipher suite.
func (m *MirrorState) CipherSuiteName() string {
	return tls.CipherSuiteName(m.CipherSuite)
}

// TLSVersionName returns the name of the TLS version.
func (m *MirrorState) TLSVersionName() string {
	switch m.Version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", m.Version)
	}
}
