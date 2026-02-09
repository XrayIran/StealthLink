// Package anyconnect implements Cisco AnyConnect protocol support
// including CSTP (Cisco Secure Thin Protocol) and DTLS transport.
package anyconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

// CSTPConfig configures CSTP (Cisco Secure Thin Protocol) transport
type CSTPConfig struct {
	// Server endpoint
	Server string

	// Credentials
	Username string
	Password string
	Group    string

	// TLS configuration
	TLSConfig *tls.Config

	// User-Agent spoofing
	UserAgent string

	// Connection settings
	ConnectTimeout time.Duration
	Keepalive      time.Duration

	// Buffer sizes
	ReadBuffer  int
	WriteBuffer int
}

// DefaultCSTPConfig returns default CSTP configuration
func DefaultCSTPConfig() *CSTPConfig {
	return &CSTPConfig{
		UserAgent:      "AnyConnect Darwin_arm64 5.1.1.42",
		ConnectTimeout: 30 * time.Second,
		Keepalive:      12 * time.Second,
		ReadBuffer:     16384,
		WriteBuffer:    16384,
	}
}

// CSTPSession represents a CSTP tunnel session
type CSTPSession struct {
	config   *CSTPConfig
	conn     net.Conn
	reader   *bufio.Reader
	writer   *bufio.Writer
	sessionID string
	address   string
	mtu       int

	// State
	closed   atomic.Bool
	closeCh  chan struct{}

	// Statistics
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	pktsIn   atomic.Uint64
	pktsOut  atomic.Uint64

	// Sync
	mu sync.RWMutex
}

// CSTPFrameType represents CSTP frame types
const (
	CSTPFrameData        = 0x00
	CSTPFrameKeepalive   = 0x03
	CSTPFrameDPDReq      = 0x04
	CSTPFrameDPDResp     = 0x05
	CSTPFrameDisconnect  = 0x06
)

// CSTPHeaderSize is the size of CSTP frame header
const CSTPHeaderSize = 8

// CSTPFrame represents a CSTP protocol frame
type CSTPFrame struct {
	Type    uint8
	Flags   uint8
	Length  uint16
	Payload []byte
}

// Encode serializes the frame
func (f *CSTPFrame) Encode() []byte {
	buf := make([]byte, CSTPHeaderSize+len(f.Payload))
	buf[0] = f.Type
	buf[1] = f.Flags
	buf[2] = uint8(f.Length >> 8)
	buf[3] = uint8(f.Length)
	// Bytes 4-7 are reserved/unused
	copy(buf[CSTPHeaderSize:], f.Payload)
	return buf
}

// ParseCSTPFrame parses a CSTP frame from data
func ParseCSTPFrame(data []byte) (*CSTPFrame, error) {
	if len(data) < CSTPHeaderSize {
		return nil, fmt.Errorf("data too short for CSTP header")
	}

	length := uint16(data[2])<<8 | uint16(data[3])
	if len(data) < CSTPHeaderSize+int(length) {
		return nil, fmt.Errorf("incomplete CSTP frame")
	}

	return &CSTPFrame{
		Type:    data[0],
		Flags:   data[1],
		Length:  length,
		Payload: data[CSTPHeaderSize : CSTPHeaderSize+length],
	}, nil
}

// Connect establishes a CSTP connection
func ConnectCSTP(ctx context.Context, config *CSTPConfig) (*CSTPSession, error) {
	if config == nil {
		config = DefaultCSTPConfig()
	}

	// Parse server URL
	serverURL := config.Server
	if !strings.HasPrefix(serverURL, "https://") {
		serverURL = "https://" + serverURL
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}

	// Step 1: Authentication
	cookie, sessionID, err := authenticate(ctx, config, u)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Step 2: Establish CSTP connection
	conn, address, mtu, err := establishCSTP(ctx, config, u, cookie)
	if err != nil {
		return nil, fmt.Errorf("CSTP establishment failed: %w", err)
	}

	session := &CSTPSession{
		config:    config,
		conn:      conn,
		reader:    bufio.NewReaderSize(conn, config.ReadBuffer),
		writer:    bufio.NewWriterSize(conn, config.WriteBuffer),
		sessionID: sessionID,
		address:   address,
		mtu:       mtu,
		closeCh:   make(chan struct{}),
	}

	// Start keepalive
	go session.keepaliveLoop()

	return session, nil
}

// authenticate performs AnyConnect authentication
func authenticate(ctx context.Context, config *CSTPConfig, serverURL *url.URL) (string, string, error) {
	// Build auth URL
	authURL := *serverURL
	authURL.Path = "/+webvpn+/index.html"

	// Create auth request
	data := url.Values{}
	data.Set("username", config.Username)
	data.Set("password", config.Password)
	if config.Group != "" {
		data.Set("group", config.Group)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", authURL.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", config.UserAgent)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config.TLSConfig,
		},
		Timeout: config.ConnectTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// Check for Set-Cookie with webvpn cookie
	var cookie, sessionID string
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(c, "webvpn=") {
			parts := strings.SplitN(c, ";", 2)
			cookie = strings.TrimSpace(parts[0])
			// Extract session ID from cookie
			if idx := strings.Index(cookie, "="); idx > 0 {
				sessionID = cookie[idx+1:]
			}
		}
	}

	if cookie == "" {
		return "", "", fmt.Errorf("no webvpn cookie received")
	}

	return cookie, sessionID, nil
}

// establishCSTP establishes the CSTP tunnel connection
func establishCSTP(ctx context.Context, config *CSTPConfig, serverURL *url.URL, cookie string) (net.Conn, string, int, error) {
	// Build connect URL
	connectURL := *serverURL
	connectURL.Path = "/CSCOSSLC/tunnel"

	req, err := http.NewRequestWithContext(ctx, "CONNECT", connectURL.String(), nil)
	if err != nil {
		return nil, "", 0, err
	}

	req.Header.Set("Cookie", cookie)
	req.Header.Set("User-Agent", config.UserAgent)
	req.Header.Set("X-CSTP-Version", "1")
	req.Header.Set("X-CSTP-Hostname", "stealthlink")
	req.Header.Set("X-CSTP-Accept-Encoding", "deflate")

	// Connect via TLS
	host := serverURL.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	dialer := &tls.Dialer{
		Config: config.TLSConfig,
	}

	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, "", 0, err
	}

	// Send CONNECT request
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, "", 0, err
	}

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		conn.Close()
		return nil, "", 0, err
	}

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, "", 0, fmt.Errorf("CSTP connect failed: %s", resp.Status)
	}

	// Parse response headers for configuration
	address := resp.Header.Get("X-CSTP-Address")
	mtuStr := resp.Header.Get("X-CSTP-MTU")
	mtu := 1400
	if mtuStr != "" {
		fmt.Sscanf(mtuStr, "%d", &mtu)
	}

	return conn, address, mtu, nil
}

// keepaliveLoop sends periodic keepalives
func (s *CSTPSession) keepaliveLoop() {
	ticker := time.NewTicker(s.config.Keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
			if err := s.sendFrame(CSTPFrameKeepalive, nil); err != nil {
				s.Close()
				return
			}
		}
	}
}

// sendFrame sends a CSTP frame
func (s *CSTPSession) sendFrame(frameType uint8, payload []byte) error {
	if s.closed.Load() {
		return fmt.Errorf("session closed")
	}

	frame := &CSTPFrame{
		Type:    frameType,
		Length:  uint16(len(payload)),
		Payload: payload,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.writer.Write(frame.Encode()); err != nil {
		return err
	}

	return s.writer.Flush()
}

// Read reads data from the CSTP tunnel
func (s *CSTPSession) Read(p []byte) (n int, err error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("session closed")
	}

	for {
		// Read frame header
		header := make([]byte, CSTPHeaderSize)
		if _, err := io.ReadFull(s.reader, header); err != nil {
			return 0, err
		}

		frame, err := ParseCSTPFrame(append(header, make([]byte, uint16(header[2])<<8|uint16(header[3]))...))
		if err != nil {
			return 0, err
		}

		// Read payload
		if frame.Length > 0 {
			if _, err := io.ReadFull(s.reader, frame.Payload); err != nil {
				return 0, err
			}
		}

		s.pktsIn.Add(1)

		switch frame.Type {
		case CSTPFrameData:
			n = copy(p, frame.Payload)
			s.bytesIn.Add(uint64(n))
			return n, nil

		case CSTPFrameKeepalive:
			// Respond to keepalive with keepalive
			s.sendFrame(CSTPFrameKeepalive, nil)

		case CSTPFrameDPDReq:
			// Respond to DPD request
			s.sendFrame(CSTPFrameDPDResp, frame.Payload)

		case CSTPFrameDisconnect:
			s.Close()
			return 0, fmt.Errorf("server disconnected")

		default:
			// Unknown frame type, ignore
		}
	}
}

// Write writes data to the CSTP tunnel
func (s *CSTPSession) Write(p []byte) (n int, err error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("session closed")
	}

	// Fragment if needed (respect MTU)
	maxPayload := s.mtu - CSTPHeaderSize - 100 // Leave room for headers
	if maxPayload < 100 {
		maxPayload = 100
	}

	offset := 0
	for offset < len(p) {
		end := offset + maxPayload
		if end > len(p) {
			end = len(p)
		}

		chunk := p[offset:end]
		if err := s.sendFrame(CSTPFrameData, chunk); err != nil {
			return offset, err
		}

		s.pktsOut.Add(1)
		s.bytesOut.Add(uint64(len(chunk)))
		offset = end
	}

	return len(p), nil
}

// Close closes the CSTP session
func (s *CSTPSession) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(s.closeCh)

	// Send disconnect
	s.sendFrame(CSTPFrameDisconnect, nil)

	return s.conn.Close()
}

// LocalAddr returns the local address
func (s *CSTPSession) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the remote address
func (s *CSTPSession) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

// SetDeadline sets read/write deadlines
func (s *CSTPSession) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (s *CSTPSession) SetReadDeadline(t time.Time) error {
	return s.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (s *CSTPSession) SetWriteDeadline(t time.Time) error {
	return s.conn.SetWriteDeadline(t)
}

// GetStats returns session statistics
func (s *CSTPSession) GetStats() CSTPStats {
	return CSTPStats{
		BytesIn:   s.bytesIn.Load(),
		BytesOut:  s.bytesOut.Load(),
		PacketsIn: s.pktsIn.Load(),
		PacketsOut: s.pktsOut.Load(),
		SessionID: s.sessionID,
		Address:   s.address,
		MTU:       s.mtu,
	}
}

// CSTPStats contains CSTP session statistics
type CSTPStats struct {
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
	SessionID  string
	Address    string
	MTU        int
}

// Dialer implements CSTP dialer
type Dialer struct {
	config *CSTPConfig
	smux   *smux.Config
}

// NewDialer creates a new CSTP dialer
func NewDialer(config *CSTPConfig, smuxCfg *smux.Config) *Dialer {
	return &Dialer{
		config: config,
		smux:   smuxCfg,
	}
}

// Dial connects to an AnyConnect server
func (d *Dialer) Dial(ctx context.Context) (*smux.Session, error) {
	session, err := ConnectCSTP(ctx, d.config)
	if err != nil {
		return nil, err
	}

	return smux.Client(session, d.smux)
}

// BasicAuth creates a Basic auth header value
func BasicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
