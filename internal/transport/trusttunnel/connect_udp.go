//go:build ignore

package trusttunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectUDPConfig configures CONNECT-UDP support (RFC 9298)
type ConnectUDPConfig struct {
	Enabled         bool
	ContextID       uint64
	MaxDatagramSize int
	Endpoint        string // Target UDP endpoint
}

// DefaultConnectUDPConfig returns default CONNECT-UDP configuration
func DefaultConnectUDPConfig() *ConnectUDPConfig {
	return &ConnectUDPConfig{
		Enabled:         false,
		ContextID:       0,
		MaxDatagramSize: 1350,
		Endpoint:        "",
	}
}

// ConnectUDPManager manages CONNECT-UDP contexts
type ConnectUDPManager struct {
	config    *ConnectUDPConfig
	contexts  map[uint64]*ConnectUDPContext
	contextMu sync.RWMutex
	nextID    atomic.Uint64

	// HTTP client for CONNECT-UDP
	httpClient *http.Client

	// Active connections
	conns    map[uint64]*ConnectUDPConn
	connMu   sync.RWMutex
}

// NewConnectUDPManager creates a new CONNECT-UDP manager
func NewConnectUDPManager(config *ConnectUDPConfig, httpClient *http.Client) *ConnectUDPManager {
	if config == nil {
		config = DefaultConnectUDPConfig()
	}
	return &ConnectUDPManager{
		config:     config,
		contexts:   make(map[uint64]*ConnectUDPContext),
		httpClient: httpClient,
		conns:      make(map[uint64]*ConnectUDPConn),
	}
}

// CreateContext creates a new CONNECT-UDP context
func (m *ConnectUDPManager) CreateContext(target string) (*ConnectUDPContext, error) {
	if !m.config.Enabled {
		return nil, fmt.Errorf("CONNECT-UDP is not enabled")
	}

	ctx := &ConnectUDPContext{
		ID:        m.nextID.Add(1),
		Target:    target,
		CreatedAt: time.Now(),
		manager:   m,
	}

	m.contextMu.Lock()
	m.contexts[ctx.ID] = ctx
	m.contextMu.Unlock()

	return ctx, nil
}

// GetContext retrieves a context by ID
func (m *ConnectUDPManager) GetContext(id uint64) (*ConnectUDPContext, bool) {
	m.contextMu.RLock()
	defer m.contextMu.RUnlock()
	ctx, ok := m.contexts[id]
	return ctx, ok
}

// RemoveContext removes a context
func (m *ConnectUDPManager) RemoveContext(id uint64) {
	m.contextMu.Lock()
	delete(m.contexts, id)
	m.contextMu.Unlock()
}

// Dial establishes a CONNECT-UDP association
func (m *ConnectUDPManager) Dial(ctx context.Context, serverURL, target string) (*ConnectUDPConn, error) {
	if !m.config.Enabled {
		return nil, fmt.Errorf("CONNECT-UDP is not enabled")
	}

	// Parse server URL
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	// Create UDP context
	udpCtx, err := m.CreateContext(target)
	if err != nil {
		return nil, err
	}

	// Build CONNECT-UDP request
	u.Path = "/.well-known/masque/udp"
	req, err := http.NewRequestWithContext(ctx, "CONNECT", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Add CONNECT-UDP headers (RFC 9298)
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set("Connect-UDP-Bind", target)

	// Perform request
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CONNECT request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", resp.Status)
	}

	// Create connection
	conn := &ConnectUDPConn{
		ctx:      udpCtx,
		reader:   resp.Body,
		manager:  m,
		closeCh:  make(chan struct{}),
		readCh:   make(chan []byte, 32),
		writeBuf: make([]byte, 0, m.config.MaxDatagramSize),
	}

	// Store connection
	m.connMu.Lock()
	m.conns[udpCtx.ID] = conn
	m.connMu.Unlock()

	// Start reading capsules
	go conn.readCapsules()

	return conn, nil
}

// ConnectUDPContext represents a CONNECT-UDP context
type ConnectUDPContext struct {
	ID        uint64
	Target    string
	CreatedAt time.Time
	LastUsed  time.Time
	manager   *ConnectUDPManager
}

// ConnectUDPConn represents a CONNECT-UDP connection
type ConnectUDPConn struct {
	ctx      *ConnectUDPContext
	reader   io.ReadCloser
	writer   io.WriteCloser
	manager  *ConnectUDPManager
	closeCh  chan struct{}
	readCh   chan []byte
	writeBuf []byte
	closed   atomic.Bool
	readMu   sync.Mutex
	writeMu  sync.Mutex
}

// Read reads a UDP datagram
func (c *ConnectUDPConn) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, fmt.Errorf("connection closed")
	}

	// Check write buffer first
	c.readMu.Lock()
	if len(c.writeBuf) > 0 {
		n := copy(p, c.writeBuf)
		c.writeBuf = c.writeBuf[n:]
		c.readMu.Unlock()
		return n, nil
	}
	c.readMu.Unlock()

	// Wait for datagram
	select {
	case data := <-c.readCh:
		n := copy(p, data)
		if n < len(data) {
			c.readMu.Lock()
			c.writeBuf = append(c.writeBuf, data[n:]...)
			c.readMu.Unlock()
		}
		return n, nil
	case <-c.closeCh:
		return 0, fmt.Errorf("connection closed")
	}
}

// Write writes a UDP datagram
func (c *ConnectUDPConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, fmt.Errorf("connection closed")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Build datagram capsule (RFC 9298)
	// Format: [Context ID (varint)] [Payload]
	capsule := c.buildDatagramCapsule(p)

	// Write capsule
	if c.writer != nil {
		_, err := c.writer.Write(capsule)
		if err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

// buildDatagramCapsule builds a UDP datagram capsule
func (c *ConnectUDPConn) buildDatagramCapsule(data []byte) []byte {
	// Variable-length integer encoding for context ID
	contextIDBytes := encodeVarInt(c.ctx.ID)

	capsule := make([]byte, len(contextIDBytes)+len(data))
	copy(capsule, contextIDBytes)
	copy(capsule[len(contextIDBytes):], data)

	return capsule
}

// readCapsules reads capsules from the response body
func (c *ConnectUDPConn) readCapsules() {
	defer c.Close()

	buf := make([]byte, 65536)
	for {
		select {
		case <-c.closeCh:
			return
		default:
		}

		// Read capsule length
		var lenBuf [2]byte
		_, err := io.ReadFull(c.reader, lenBuf[:])
		if err != nil {
			return
		}

		length := binary.BigEndian.Uint16(lenBuf[:])
		if length == 0 || length > 16384 {
			continue
		}

		// Read capsule data
		capsule := make([]byte, length)
		_, err = io.ReadFull(c.reader, capsule)
		if err != nil {
			return
		}

		// Parse capsule
		datagram := c.parseDatagramCapsule(capsule)
		if datagram != nil {
			select {
			case c.readCh <- datagram:
			case <-c.closeCh:
				return
			}
		}
	}
}

// parseDatagramCapsule parses a UDP datagram capsule
func (c *ConnectUDPConn) parseDatagramCapsule(capsule []byte) []byte {
	if len(capsule) < 1 {
		return nil
	}

	// Decode context ID
	_, n, err := decodeVarInt(capsule)
	if err != nil {
		return nil
	}

	// Extract payload
	if n >= len(capsule) {
		return nil
	}

	return capsule[n:]
}

// Close closes the connection
func (c *ConnectUDPConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(c.closeCh)

	if c.reader != nil {
		c.reader.Close()
	}
	if c.writer != nil {
		c.writer.Close()
	}

	// Remove from manager
	c.manager.connMu.Lock()
	delete(c.manager.conns, c.ctx.ID)
	c.manager.connMu.Unlock()

	c.manager.RemoveContext(c.ctx.ID)

	return nil
}

// LocalAddr returns the local address
func (c *ConnectUDPConn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr returns the remote address
func (c *ConnectUDPConn) RemoteAddr() net.Addr {
	if c.ctx != nil && c.ctx.Target != "" {
		addr, _ := net.ResolveUDPAddr("udp", c.ctx.Target)
		return addr
	}
	return nil
}

// SetDeadline sets the deadline
func (c *ConnectUDPConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the read deadline
func (c *ConnectUDPConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline
func (c *ConnectUDPConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Ensure ConnectUDPConn implements net.Conn
var _ net.Conn = (*ConnectUDPConn)(nil)

// ConnectUDPServer handles server-side CONNECT-UDP
type ConnectUDPServer struct {
	config *ConnectUDPConfig
	conns  map[string]*net.UDPConn
	connMu sync.RWMutex
}

// NewConnectUDPServer creates a new CONNECT-UDP server
func NewConnectUDPServer(config *ConnectUDPConfig) *ConnectUDPServer {
	if config == nil {
		config = DefaultConnectUDPConfig()
	}
	return &ConnectUDPServer{
		config: config,
		conns:  make(map[string]*net.UDPConn),
	}
}

// HandleConnect handles a CONNECT-UDP request
func (s *ConnectUDPServer) HandleConnect(w http.ResponseWriter, r *http.Request) {
	if !s.config.Enabled {
		http.Error(w, "CONNECT-UDP not enabled", http.StatusNotImplemented)
		return
	}

	// Get target from header
	target := r.Header.Get("Connect-UDP-Bind")
	if target == "" {
		target = r.URL.Query().Get("target")
	}
	if target == "" {
		http.Error(w, "Missing target", http.StatusBadRequest)
		return
	}

	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// Send 200 response
	fmt.Fprintf(bufrw, "HTTP/1.1 200 OK\r\n")
	fmt.Fprintf(bufrw, "Capsule-Protocol: ?1\r\n")
	fmt.Fprintf(bufrw, "\r\n")
	bufrw.Flush()

	// Establish UDP relay
	udpConn, err := net.Dial("udp", target)
	if err != nil {
		return
	}
	defer udpConn.Close()

	// Relay between HTTP and UDP
	s.relay(bufrw, udpConn)
}

// relay relays between HTTP connection and UDP
func (s *ConnectUDPServer) relay(hijacked io.ReadWriter, udpConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// HTTP -> UDP
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			// Read capsule
			var lenBuf [2]byte
			_, err := io.ReadFull(hijacked, lenBuf[:])
			if err != nil {
				return
			}

			length := binary.BigEndian.Uint16(lenBuf[:])
			if length == 0 || length > 16384 {
				continue
			}

			capsule := make([]byte, length)
			_, err = io.ReadFull(hijacked, capsule)
			if err != nil {
				return
			}

			// Skip context ID and send to UDP
			_, n, _ := decodeVarInt(capsule)
			if n < len(capsule) {
				udpConn.Write(capsule[n:])
			}
		}
	}()

	// UDP -> HTTP
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := udpConn.Read(buf)
			if err != nil {
				return
			}

			// Build capsule with context ID 0
			contextIDBytes := encodeVarInt(0)
			capsule := make([]byte, len(contextIDBytes)+n)
			copy(capsule, contextIDBytes)
			copy(capsule[len(contextIDBytes):], buf[:n])

			// Send length prefix
			var lenBuf [2]byte
			binary.BigEndian.PutUint16(lenBuf[:], uint16(len(capsule)))
			hijacked.Write(lenBuf[:])
			hijacked.Write(capsule)
		}
	}()

	wg.Wait()
}

// encodeVarInt encodes a uint64 as a variable-length integer (RFC 9000)
func encodeVarInt(v uint64) []byte {
	if v <= 63 {
		return []byte{byte(v)}
	}
	if v <= 16383 {
		return []byte{byte(v>>8 | 0x40), byte(v)}
	}
	if v <= 1073741823 {
		return []byte{byte(v>>24 | 0x80), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return []byte{
		byte(v>>56 | 0xC0), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

// decodeVarInt decodes a variable-length integer from the buffer
func decodeVarInt(buf []byte) (uint64, int) {
	if len(buf) == 0 {
		return 0, 0
	}
	first := buf[0]
	switch first & 0xC0 {
	case 0x00:
		return uint64(first), 1
	case 0x40:
		if len(buf) < 2 {
			return 0, 0
		}
		return uint64(first&0x3F)<<8 | uint64(buf[1]), 2
	case 0x80:
		if len(buf) < 4 {
			return 0, 0
		}
		return uint64(first&0x3F)<<24 | uint64(buf[1])<<16 | uint64(buf[2])<<8 | uint64(buf[3]), 4
	default: // 0xC0
		if len(buf) < 8 {
			return 0, 0
		}
		return uint64(first&0x3F)<<56 | uint64(buf[1])<<48 | uint64(buf[2])<<40 | uint64(buf[3])<<32 |
			uint64(buf[4])<<24 | uint64(buf[5])<<16 | uint64(buf[6])<<8 | uint64(buf[7]), 8
	}
}
