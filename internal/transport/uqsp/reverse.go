// Package uqsp provides the Unified QUIC Superset Protocol implementation
// Reverse proxy mode allows server-initiated connections for stealth
package uqsp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// ReverseMode configures reverse proxy mode where the server initiates connections
// to the client instead of the client connecting to the server. This makes it
// harder to detect the server since it appears as an outbound connection.
type ReverseMode struct {
	Enabled bool   `yaml:"enabled"`
	Role    string `yaml:"role"` // "dialer" (normally client) or "listener" (normally server)

	// Connection settings
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	ReconnectDelay    time.Duration `yaml:"reconnect_delay"`
	MaxRetries        int           `yaml:"max_retries"`

	// Address configuration
	ClientAddress string `yaml:"client_address"` // Address for server to connect to (when server is dialer)
	ServerAddress string `yaml:"server_address"` // Address for client to listen on (when client is listener)

	// Authentication
	AuthToken string `yaml:"auth_token"` // Token to authenticate reverse connections

	// TLS configuration
	TLSConfig *tls.Config `yaml:"-"`

	// HTTP registration improves reverse connectivity behind CDNs/proxies.
	UseHTTPRegistration bool   `yaml:"use_http_registration"`
	RegistrationPath    string `yaml:"registration_path"`
}

// ReverseDialer implements a dialer that works in reverse mode
type ReverseDialer struct {
	mode      *ReverseMode
	tlsConfig *tls.Config
	connChan  chan net.Conn
	mu        sync.RWMutex
	closed    bool
	stopCh    chan struct{}
	qualityMu sync.RWMutex
	quality   ReverseQuality
}

type ReverseQuality struct {
	Score          float64
	DialLatency    time.Duration
	ConsecutiveErr int
	LastHeartbeat  time.Time
	LastConnected  time.Time
}

// NewReverseDialer creates a new reverse dialer
func NewReverseDialer(mode *ReverseMode, tlsConfig *tls.Config) *ReverseDialer {
	return &ReverseDialer{
		mode:      mode,
		tlsConfig: tlsConfig,
		connChan:  make(chan net.Conn, 10),
		stopCh:    make(chan struct{}),
	}
}

// Start starts the reverse dialer based on role
func (d *ReverseDialer) Start(ctx context.Context) error {
	if !d.mode.Enabled {
		return fmt.Errorf("reverse mode not enabled")
	}

	switch d.mode.Role {
	case "dialer":
		// In reverse mode, the "dialer" role means we initiate connections
		// (typically the server's role, but in reverse mode it's the client)
		return d.startDialer(ctx)
	case "listener":
		// In reverse mode, the "listener" role means we accept connections
		// (typically the client's role, but in reverse mode it's the server)
		return d.startListener(ctx)
	default:
		return fmt.Errorf("unknown role: %s", d.mode.Role)
	}
}

// startDialer continuously dials the peer (server's behavior in reverse mode)
func (d *ReverseDialer) startDialer(ctx context.Context) error {
	addr := d.mode.ClientAddress
	if addr == "" {
		return fmt.Errorf("client_address required for dialer role")
	}

	go d.dialLoop(ctx, addr)
	return nil
}

// dialLoop continuously attempts to connect
func (d *ReverseDialer) dialLoop(ctx context.Context, addr string) {
	retryDelay := d.mode.ReconnectDelay
	if retryDelay == 0 {
		retryDelay = 5 * time.Second
	}

	maxRetries := d.mode.MaxRetries
	if maxRetries == 0 {
		maxRetries = 10
	}

	retries := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stopCh:
			return
		default:
		}

		conn, err := d.dialWithRetry(addr)
		if err != nil {
			retries++
			if retries >= maxRetries {
				return
			}
			time.Sleep(retryDelay)
			continue
		}

		retries = 0

		// Send the connection to the channel
		select {
		case d.connChan <- conn:
		case <-ctx.Done():
			conn.Close()
			return
		case <-d.stopCh:
			conn.Close()
			return
		}

		// Wait for connection to close before reconnecting
		d.waitForClose(conn)
	}
}

// dialWithRetry attempts to dial with authentication
func (d *ReverseDialer) dialWithRetry(addr string) (net.Conn, error) {
	start := time.Now()
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS if configured
	if d.tlsConfig != nil {
		tlsConn := tls.Client(conn, d.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	// Send authentication token if configured
	if d.mode.UseHTTPRegistration {
		if err := d.sendHTTPRegistration(conn); err != nil {
			conn.Close()
			d.recordFailure(time.Since(start))
			return nil, fmt.Errorf("registration failed: %w", err)
		}
	}

	if d.mode.AuthToken != "" {
		if err := d.sendAuth(conn); err != nil {
			conn.Close()
			d.recordFailure(time.Since(start))
			return nil, fmt.Errorf("auth failed: %w", err)
		}
	}
	d.recordSuccess(time.Since(start))

	return conn, nil
}

// sendAuth sends authentication token
func (d *ReverseDialer) sendAuth(conn net.Conn) error {
	// Simple auth protocol: [4-byte length][token]
	tokenBytes := []byte(d.mode.AuthToken)
	length := make([]byte, 4)
	length[0] = byte(len(tokenBytes) >> 24)
	length[1] = byte(len(tokenBytes) >> 16)
	length[2] = byte(len(tokenBytes) >> 8)
	length[3] = byte(len(tokenBytes))

	if _, err := conn.Write(length); err != nil {
		return err
	}
	if _, err := conn.Write(tokenBytes); err != nil {
		return err
	}

	// Read response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}

	if resp[0] != 0x00 || resp[1] != 0x00 {
		return fmt.Errorf("auth rejected")
	}

	return nil
}

// waitForClose waits for a connection to close
func (d *ReverseDialer) waitForClose(conn net.Conn) {
	buf := make([]byte, 1)
	conn.Read(buf) // This will block until connection closes
}

// startListener starts listening for incoming connections
// (client's behavior in reverse mode)
func (d *ReverseDialer) startListener(ctx context.Context) error {
	addr := d.mode.ServerAddress
	if addr == "" {
		return fmt.Errorf("server_address required for listener role")
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	go d.acceptLoop(ctx, ln)
	return nil
}

// acceptLoop accepts incoming connections
func (d *ReverseDialer) acceptLoop(ctx context.Context, ln net.Listener) {
	defer ln.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stopCh:
			return
		default:
		}

		ln.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			return
		}

		go d.handleIncoming(ctx, conn)
	}
}

// handleIncoming handles an incoming connection
func (d *ReverseDialer) handleIncoming(ctx context.Context, conn net.Conn) {
	if d.mode.UseHTTPRegistration {
		registeredConn, err := d.verifyHTTPRegistration(conn)
		if err != nil {
			conn.Close()
			return
		}
		conn = registeredConn
	}

	// Handle TLS if configured
	if d.tlsConfig != nil {
		tlsConn := tls.Server(conn, d.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return
		}
		conn = tlsConn
	}

	// Verify authentication if configured
	if d.mode.AuthToken != "" {
		if err := d.verifyAuth(conn); err != nil {
			conn.Close()
			return
		}
	}

	// Send the connection to the channel
	select {
	case d.connChan <- conn:
	case <-ctx.Done():
		conn.Close()
	case <-d.stopCh:
		conn.Close()
	}
}

// verifyAuth verifies the authentication token
func (d *ReverseDialer) verifyAuth(conn net.Conn) error {
	// Read length
	var lengthBuf [4]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint32(lengthBuf[:]))
	if length > 4096 {
		return fmt.Errorf("token too long")
	}

	// Read token
	token := make([]byte, length)
	if _, err := io.ReadFull(conn, token); err != nil {
		return err
	}

	// Verify
	expected := []byte(d.mode.AuthToken)
	if len(token) != len(expected) || subtle.ConstantTimeCompare(token, expected) != 1 {
		// Send rejection
		_, _ = conn.Write([]byte{0xFF, 0xFF})
		return fmt.Errorf("invalid token")
	}

	// Send acceptance
	_, _ = conn.Write([]byte{0x00, 0x00})
	return nil
}

// Dial simulates a dial operation by returning a pre-established connection
func (d *ReverseDialer) Dial(network, addr string) (net.Conn, error) {
	select {
	case conn := <-d.connChan:
		return conn, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for reverse connection")
	}
}

// Close closes the reverse dialer
func (d *ReverseDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true
	close(d.stopCh)
	return nil
}

func (d *ReverseDialer) sendHTTPRegistration(conn net.Conn) error {
	path := d.mode.RegistrationPath
	if path == "" {
		path = "/_reverse_register"
	}
	payload := map[string]any{
		"role":      d.mode.Role,
		"timestamp": time.Now().Unix(),
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, "http://reverse.local"+path, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Host", "reverse.local")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "keep-alive")
	if d.mode.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+d.mode.AuthToken)
	}
	if err := req.Write(conn); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("registration rejected: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (d *ReverseDialer) verifyHTTPRegistration(conn net.Conn) (net.Conn, error) {
	path := d.mode.RegistrationPath
	if path == "" {
		path = "/_reverse_register"
	}
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()
	if req.Method != http.MethodPost || req.URL.Path != path {
		_, _ = io.WriteString(conn, "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return nil, fmt.Errorf("invalid registration request")
	}
	if d.mode.AuthToken != "" {
		want := []byte("Bearer " + d.mode.AuthToken)
		got := []byte(req.Header.Get("Authorization"))
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			_, _ = io.WriteString(conn, "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
			return nil, fmt.Errorf("invalid registration token")
		}
	}
	_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok")
	return &bufferedConn{Conn: conn, r: br}, nil
}

func (d *ReverseDialer) recordSuccess(latency time.Duration) {
	d.qualityMu.Lock()
	defer d.qualityMu.Unlock()
	d.quality.LastConnected = time.Now()
	d.quality.LastHeartbeat = time.Now()
	d.quality.ConsecutiveErr = 0
	if d.quality.DialLatency == 0 {
		d.quality.DialLatency = latency
	} else {
		d.quality.DialLatency = (d.quality.DialLatency*8 + latency*2) / 10
	}
	d.quality.Score = scoreFromQuality(d.quality)
}

func (d *ReverseDialer) recordFailure(latency time.Duration) {
	d.qualityMu.Lock()
	defer d.qualityMu.Unlock()
	d.quality.ConsecutiveErr++
	if latency > 0 {
		d.quality.DialLatency = latency
	}
	d.quality.Score = scoreFromQuality(d.quality)
}

func scoreFromQuality(q ReverseQuality) float64 {
	base := 100.0
	if q.DialLatency > 0 {
		base -= float64(q.DialLatency.Milliseconds()) * 0.05
	}
	base -= float64(q.ConsecutiveErr) * 12
	if base < 0 {
		return 0
	}
	return base
}

func (d *ReverseDialer) Quality() ReverseQuality {
	d.qualityMu.RLock()
	defer d.qualityMu.RUnlock()
	return d.quality
}

// ReverseListener wraps the reverse connection channel as a net.Listener
type ReverseListener struct {
	dialer *ReverseDialer
	addr   net.Addr
	closed bool
	mu     sync.Mutex
}

// NewReverseListener creates a listener for reverse connections
func NewReverseListener(dialer *ReverseDialer, addr string) (*ReverseListener, error) {
	return &ReverseListener{
		dialer: dialer,
		addr:   &reverseAddr{network: "tcp", address: addr},
	}, nil
}

// Accept accepts incoming reverse connections
func (l *ReverseListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, fmt.Errorf("listener closed")
	}
	l.mu.Unlock()

	conn := <-l.dialer.connChan
	if conn == nil {
		return nil, fmt.Errorf("listener closed")
	}

	return &reverseConn{Conn: conn}, nil
}

// Close closes the listener
func (l *ReverseListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true
	return l.dialer.Close()
}

// Addr returns the listener address
func (l *ReverseListener) Addr() net.Addr {
	return l.addr
}

// reverseAddr implements net.Addr for reverse connections
type reverseAddr struct {
	network string
	address string
}

func (a *reverseAddr) Network() string { return a.network }
func (a *reverseAddr) String() string  { return a.address }

// reverseConn wraps a connection with reverse mode metadata
type reverseConn struct {
	net.Conn
	isReverse bool
}

// IsReverse returns true if this is a reverse connection
func (c *reverseConn) IsReverse() bool {
	return true
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// ReverseConnector manages reverse connections for a session
type ReverseConnector struct {
	mode   *ReverseMode
	mu     sync.RWMutex
	conn   net.Conn
	ready  chan struct{}
	stopCh chan struct{}
}

// NewReverseConnector creates a new reverse connector
func NewReverseConnector(mode *ReverseMode) *ReverseConnector {
	return &ReverseConnector{
		mode:   mode,
		ready:  make(chan struct{}),
		stopCh: make(chan struct{}),
	}
}

// Connect initiates the reverse connection
func (r *ReverseConnector) Connect(ctx context.Context) error {
	if !r.mode.Enabled {
		return fmt.Errorf("reverse mode not enabled")
	}

	dialer := NewReverseDialer(r.mode, r.mode.TLSConfig)
	if err := dialer.Start(ctx); err != nil {
		return err
	}

	conn, err := dialer.Dial("tcp", r.mode.ClientAddress)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.conn = conn
	r.mu.Unlock()

	close(r.ready)

	return nil
}

// Wait waits for the connection to be established
func (r *ReverseConnector) Wait(ctx context.Context) error {
	select {
	case <-r.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-r.stopCh:
		return fmt.Errorf("connector stopped")
	}
}

// GetConn returns the established connection
func (r *ReverseConnector) GetConn() net.Conn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conn
}

// Close closes the connector
func (r *ReverseConnector) Close() error {
	close(r.stopCh)

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.conn != nil {
		return r.conn.Close()
	}

	return nil
}
