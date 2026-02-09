package carrier

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"stealthlink/internal/tlsutil"

	"github.com/xtaci/smux"
)

// XHTTPCarrier implements XHTTP (SplitHTTP) as a UQSP carrier.
// XHTTP splits HTTP requests/responses across multiple connections.
type XHTTPCarrier struct {
	config    XHTTPConfig
	smuxCfg   *smux.Config
	client    *http.Client
	tlsConfig *tls.Config
	streams   map[uint32]*xhttpStream
	mu        sync.RWMutex
	nextID    uint32
}

// XHTTPConfig configures the XHTTP carrier.
type XHTTPConfig struct {
	Server   string            `yaml:"server"`
	Path     string            `yaml:"path"`
	Mode     string            `yaml:"mode"` // stream-one, stream-up, stream-down, packet-up
	Headers  map[string]string `yaml:"headers"`
	MaxConns int               `yaml:"max_connections"`

	// TLS config
	TLSInsecureSkipVerify bool   `yaml:"tls_insecure_skip_verify"`
	TLSServerName         string `yaml:"tls_server_name"`
	TLSFingerprint        string `yaml:"tls_fingerprint"`

	HeaderRandomization bool `yaml:"header_randomization"`
	RequestDelayMs      int  `yaml:"request_delay_ms"`
	ResponseDelayMs     int  `yaml:"response_delay_ms"`
}

// NewXHTTPCarrier creates a new XHTTP carrier.
func NewXHTTPCarrier(cfg XHTTPConfig, smuxCfg *smux.Config) *XHTTPCarrier {
	if cfg.Path == "" {
		cfg.Path = "/xhttp"
	}
	if cfg.Mode == "" {
		cfg.Mode = "stream-one"
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 4
	}
	if cfg.RequestDelayMs < 0 {
		cfg.RequestDelayMs = 0
	}
	if cfg.ResponseDelayMs < 0 {
		cfg.ResponseDelayMs = 0
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
		ServerName:         cfg.TLSServerName,
	}

	httpTransport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        cfg.MaxConns,
		MaxIdleConnsPerHost: cfg.MaxConns,
		DisableKeepAlives:   false,
	}
	httpTransport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialCarrierTLS(ctx, network, addr, tlsConfig, cfg.TLSFingerprint)
	}

	return &XHTTPCarrier{
		config:    cfg,
		smuxCfg:   smuxCfg,
		tlsConfig: tlsConfig,
		streams:   make(map[uint32]*xhttpStream),
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: httpTransport,
		},
	}
}

// Dial connects to the XHTTP server.
func (c *XHTTPCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	switch c.config.Mode {
	case "stream-one", "stream-up", "stream-down":
		return c.dialStreamMode(ctx)
	case "packet-up":
		return c.dialPacketMode(ctx)
	default:
		return nil, fmt.Errorf("unsupported XHTTP mode: %s", c.config.Mode)
	}
}

// dialStreamMode dials in streaming mode.
func (c *XHTTPCarrier) dialStreamMode(ctx context.Context) (net.Conn, error) {
	// Connect to server
	conn, err := dialCarrierTLS(ctx, "tcp", c.config.Server, c.tlsConfig, c.config.TLSFingerprint)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}

	// Build HTTP request based on mode
	var method string
	switch c.config.Mode {
	case "stream-up":
		method = "POST"
	case "stream-down":
		method = "GET"
	default: // stream-one
		method = "POST"
	}

	if c.config.RequestDelayMs > 0 {
		time.Sleep(time.Duration(c.config.RequestDelayMs) * time.Millisecond)
	}

	frontOpts, hasFrontOpts := tlsutil.FrontDialOptionsFromContext(ctx)
	hostHeader := c.config.Server
	if hasFrontOpts && frontOpts.Enabled && frontOpts.RealHost != "" {
		hostHeader = frontOpts.RealHost
	}

	// Send HTTP request
	req := fmt.Sprintf("%s %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/octet-stream\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"X-Stealthlink-Mode: %s\r\n",
		method,
		c.config.Path,
		hostHeader,
		c.config.Mode,
	)

	if hasFrontOpts && frontOpts.Enabled && frontOpts.CFWorker != "" {
		req += fmt.Sprintf("CF-Worker: %s\r\n", frontOpts.CFWorker)
	}

	// Add custom headers
	for k, v := range randomizeHeaderOrder(c.config.Headers, c.config.HeaderRandomization) {
		parts := strings.SplitN(k, "\x00", 2)
		name, value := parts[0], ""
		if len(parts) == 2 {
			value = parts[1]
		}
		if value == "" {
			value = v
		}
		req += fmt.Sprintf("%s: %s\r\n", name, value)
	}
	if c.config.HeaderRandomization {
		req += fmt.Sprintf("X-Pad: %x\r\n", randomPadBytes(8))
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write request: %w", err)
	}

	// For stream-up and stream-one, we're ready to send data
	// For stream-down, we need to read the response first
	if c.config.Mode == "stream-down" {
		if c.config.ResponseDelayMs > 0 {
			time.Sleep(time.Duration(c.config.ResponseDelayMs) * time.Millisecond)
		}
		// Read HTTP response
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read response: %w", err)
		}
		// Parse response to ensure 200 OK
		if !bytes.Contains(buf[:n], []byte("200")) {
			conn.Close()
			return nil, fmt.Errorf("server returned error")
		}
	}

	return &xhttpConn{
		Conn:   conn,
		mode:   c.config.Mode,
		server: c.config.Server,
		path:   c.config.Path,
	}, nil
}

func randomizeHeaderOrder(headers map[string]string, enabled bool) map[string]string {
	if !enabled || len(headers) <= 1 {
		return headers
	}
	out := make(map[string]string, len(headers))
	keys := make([]string, 0, len(headers))
	for k, v := range headers {
		keys = append(keys, k+"\x00"+v)
	}
	for i := len(keys) - 1; i > 0; i-- {
		j := secureRandInt(i + 1)
		keys[i], keys[j] = keys[j], keys[i]
	}
	for _, kv := range keys {
		parts := strings.SplitN(kv, "\x00", 2)
		if len(parts) == 2 {
			out[parts[0]] = parts[1]
		}
	}
	return out
}

func randomPadBytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func secureRandInt(max int) int {
	if max <= 1 {
		return 0
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(max))
}

// Write writes data to the connection using chunked encoding.
func (c *xhttpConn) Write(b []byte) (int, error) {
	// Segment chunk writes to mimic natural transfer behavior.
	written := 0
	for written < len(b) {
		remain := len(b) - written
		chunkSize := remain
		if chunkSize > 1024 {
			chunkSize = 256 + secureRandInt(768)
			if chunkSize > remain {
				chunkSize = remain
			}
		}
		part := b[written : written+chunkSize]
		chunk := fmt.Sprintf("%x\r\n", len(part))
		if _, err := c.Conn.Write([]byte(chunk)); err != nil {
			return written, err
		}
		if _, err := c.Conn.Write(part); err != nil {
			return written, err
		}
		if _, err := c.Conn.Write([]byte("\r\n")); err != nil {
			return written, err
		}
		written += chunkSize
	}
	return len(b), nil
}

// dialPacketMode dials in packet mode (for UDP-like semantics).
func (c *XHTTPCarrier) dialPacketMode(ctx context.Context) (net.Conn, error) {
	// In packet-up mode, we send data as individual HTTP POST requests
	return &xhttpPacketConn{
		server:  c.config.Server,
		path:    c.config.Path,
		client:  c.client,
		headers: c.config.Headers,
	}, nil
}

// Network returns the network type.
func (c *XHTTPCarrier) Network() string {
	return "tcp"
}

// Listen is not supported for XHTTP (client-only).
func (c *XHTTPCarrier) Listen(addr string) (Listener, error) {
	return nil, fmt.Errorf("xhttp carrier does not support listening (client-only)")
}

// Close closes the carrier.
func (c *XHTTPCarrier) Close() error {
	return nil
}

// IsAvailable returns true if XHTTP is available.
func (c *XHTTPCarrier) IsAvailable() bool {
	return true
}

// Name returns the carrier name.
func (c *XHTTPCarrier) Name() string {
	return "xhttp"
}

// xhttpStream represents a single XHTTP stream.
type xhttpStream struct {
	id      uint32
	readCh  chan []byte
	writeCh chan []byte
	closeCh chan struct{}
	closed  bool
}

// xhttpConn wraps a TLS connection for XHTTP.
type xhttpConn struct {
	net.Conn
	mode   string
	server string
	path   string
	buf    []byte
}

// Read reads data from the connection.
func (c *xhttpConn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	return c.Conn.Read(b)
}

// xhttpPacketConn implements packet-mode XHTTP.
type xhttpPacketConn struct {
	server  string
	path    string
	client  *http.Client
	headers map[string]string
	readBuf []byte
	mu      sync.Mutex
}

// Read reads a packet.
func (c *xhttpPacketConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// In packet mode, we need to poll for data
	// This is a simplified implementation
	return 0, io.EOF
}

// Write sends a packet.
func (c *xhttpPacketConn) Write(b []byte) (int, error) {
	url := fmt.Sprintf("https://%s%s", c.server, c.path)
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Stealthlink-Mode", "packet-up")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	return len(b), nil
}

// Close closes the connection.
func (c *xhttpPacketConn) Close() error {
	return nil
}

// LocalAddr returns the local address.
func (c *xhttpPacketConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// RemoteAddr returns the remote address.
func (c *xhttpPacketConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

// SetDeadline sets the deadline.
func (c *xhttpPacketConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *xhttpPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *xhttpPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// XHTTPListener implements an XHTTP server listener.
type XHTTPListener struct {
	listener net.Listener
	mux      *http.ServeMux
	conns    chan net.Conn
	closed   bool
	mu       sync.Mutex
}

// NewXHTTPListener creates a new XHTTP listener.
func NewXHTTPListener(addr string, tlsConfig *tls.Config) (*XHTTPListener, error) {
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}

	xl := &XHTTPListener{
		listener: ln,
		mux:      http.NewServeMux(),
		conns:    make(chan net.Conn, 100),
	}

	// Setup handlers
	xl.mux.HandleFunc("/", xl.handleRequest)

	// Start HTTP server
	go http.Serve(ln, xl.mux)

	return xl, nil
}

// handleRequest handles XHTTP requests.
func (l *XHTTPListener) handleRequest(w http.ResponseWriter, r *http.Request) {
	mode := r.Header.Get("X-Stealthlink-Mode")
	if mode == "" {
		mode = "stream-one"
	}

	switch mode {
	case "stream-one", "stream-up", "stream-down":
		l.handleStreamRequest(w, r)
	case "packet-up":
		l.handlePacketRequest(w, r)
	default:
		http.Error(w, "Invalid mode", http.StatusBadRequest)
	}
}

// handleStreamRequest handles streaming mode requests.
func (l *XHTTPListener) handleStreamRequest(w http.ResponseWriter, r *http.Request) {
	// Hijack the connection
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

	// Send 200 OK
	bufrw.WriteString("HTTP/1.1 200 OK\r\n")
	bufrw.WriteString("Content-Type: application/octet-stream\r\n")
	bufrw.WriteString("Transfer-Encoding: chunked\r\n")
	bufrw.WriteString("\r\n")
	bufrw.Flush()

	// Wrap the connection for chunked encoding
	xconn := &xhttpServerConn{
		Conn:   conn,
		reader: bufrw.Reader,
	}

	// Send to accept queue
	select {
	case l.conns <- xconn:
	default:
		conn.Close()
	}
}

// handlePacketRequest handles packet mode requests.
func (l *XHTTPListener) handlePacketRequest(w http.ResponseWriter, r *http.Request) {
	// Read packet data
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Process packet (would be forwarded to the target)
	_ = data

	// Send response
	w.WriteHeader(http.StatusOK)
}

// Accept accepts XHTTP connections.
func (l *XHTTPListener) Accept() (net.Conn, error) {
	conn := <-l.conns
	return conn, nil
}

// Close closes the listener.
func (l *XHTTPListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.conns)
	return l.listener.Close()
}

// Addr returns the listener address.
func (l *XHTTPListener) Addr() net.Addr {
	return l.listener.Addr()
}

// xhttpServerConn wraps a hijacked HTTP connection.
type xhttpServerConn struct {
	net.Conn
	reader *bufio.Reader
	buf    []byte
}

// Read reads data (handling chunked encoding).
func (c *xhttpServerConn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	// Read chunk size line
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return 0, err
	}

	// Parse chunk size
	var size int
	if _, err := fmt.Sscanf(line, "%x", &size); err != nil {
		return 0, err
	}

	if size == 0 {
		// Last chunk, read trailing CRLF
		c.reader.ReadString('\n')
		return 0, io.EOF
	}

	// Read chunk data
	data := make([]byte, size)
	if _, err := io.ReadFull(c.reader, data); err != nil {
		return 0, err
	}

	// Read trailing CRLF
	c.reader.ReadString('\n')

	n := copy(b, data)
	if n < len(data) {
		c.buf = data[n:]
	}

	return n, nil
}
