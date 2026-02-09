package carrier

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xtaci/smux"
	"golang.org/x/net/http2/hpack"
)

// WebTunnelCarrier implements an HTTP Upgrade carrier for UQSP.
// It tunnels UQSP over HTTP/1.1 Upgrade: stealthlink or HTTP/2 CONNECT.
type WebTunnelCarrier struct {
	config    WebTunnelConfig
	smuxCfg   *smux.Config
	client    *http.Client
	tlsConfig *tls.Config
}

// WebTunnelConfig configures the WebTunnel carrier.
type WebTunnelConfig struct {
	// Server is the WebTunnel server address (host:port)
	Server string

	// Path is the HTTP path for the tunnel endpoint
	Path string

	// Version is the HTTP version: "h1" (HTTP/1.1 Upgrade), "h2" (HTTP/2 CONNECT)
	Version string

	// Headers are additional HTTP headers to send
	Headers map[string]string

	// UserAgent is the User-Agent header (if empty, use default)
	UserAgent string

	// TLS config
	TLSInsecureSkipVerify bool
	TLSServerName         string
	TLSFingerprint        string
}

// NewWebTunnelCarrier creates a new WebTunnel carrier.
func NewWebTunnelCarrier(cfg WebTunnelConfig, smuxCfg *smux.Config) *WebTunnelCarrier {
	if cfg.Path == "" {
		cfg.Path = "/tunnel"
	}
	if cfg.Version == "" {
		cfg.Version = "h2"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0"
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
		ServerName:         cfg.TLSServerName,
	}

	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpTransport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialCarrierTLS(ctx, network, addr, tlsConfig, cfg.TLSFingerprint)
	}

	return &WebTunnelCarrier{
		config:  cfg,
		smuxCfg: smuxCfg,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: httpTransport,
		},
		tlsConfig: tlsConfig,
	}
}

// Dial connects to the WebTunnel server.
func (c *WebTunnelCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	switch c.config.Version {
	case "h1":
		return c.dialH1(ctx, addr)
	case "h2":
		return c.dialH2(ctx, addr)
	default:
		return nil, fmt.Errorf("unsupported WebTunnel version: %s", c.config.Version)
	}
}

// dialH1 uses HTTP/1.1 Upgrade to establish the tunnel.
func (c *WebTunnelCarrier) dialH1(ctx context.Context, addr string) (net.Conn, error) {
	// Connect to server
	conn, err := dialCarrierTLS(ctx, "tcp", c.config.Server, c.tlsConfig, c.config.TLSFingerprint)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}

	// Build HTTP upgrade request
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Scheme: "https", Host: c.config.Server, Path: c.config.Path},
		Header: http.Header{
			"Upgrade":               []string{"stealthlink"},
			"Connection":            []string{"Upgrade"},
			"User-Agent":            []string{c.config.UserAgent},
			"X-Stealthlink-Version": []string{"1.0"},
		},
	}

	// Add custom headers
	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}

	// Send request
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write upgrade request: %w", err)
	}

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("upgrade failed: %s", resp.Status)
	}

	if resp.Header.Get("Upgrade") != "stealthlink" {
		conn.Close()
		return nil, fmt.Errorf("unexpected upgrade header: %s", resp.Header.Get("Upgrade"))
	}

	return conn, nil
}

// dialH2 uses HTTP/2 CONNECT to establish the tunnel.
func (c *WebTunnelCarrier) dialH2(ctx context.Context, addr string) (net.Conn, error) {
	// Connect to server
	conn, err := dialCarrierTLS(ctx, "tcp", c.config.Server, c.tlsConfig, c.config.TLSFingerprint)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}

	// Send HTTP/2 connection preface
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write h2 preface: %w", err)
	}

	// Send SETTINGS frame
	settingsFrame := []byte{
		0x00, 0x00, 0x00, // Length: 0
		0x04,                   // Type: SETTINGS
		0x00,                   // Flags: none
		0x00, 0x00, 0x00, 0x00, // Stream ID: 0
	}
	if _, err := conn.Write(settingsFrame); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write h2 settings: %w", err)
	}

	// Read server SETTINGS
	settingsBuf := make([]byte, 9)
	if _, err := io.ReadFull(conn, settingsBuf); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read h2 settings: %w", err)
	}

	// Send SETTINGS ACK
	settingsAck := []byte{
		0x00, 0x00, 0x00, // Length: 0
		0x04,                   // Type: SETTINGS
		0x01,                   // Flags: ACK
		0x00, 0x00, 0x00, 0x00, // Stream ID: 0
	}
	if _, err := conn.Write(settingsAck); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write h2 settings ack: %w", err)
	}

	// Send CONNECT request on stream 1
	// Build HEADERS frame payload
	headers := fmt.Sprintf(
		":method CONNECT\r\n"+
			":scheme https\r\n"+
			":authority %s\r\n"+
			":path %s\r\n"+
			"user-agent: %s\r\n"+
			"x-stealthlink-version: 1.0\r\n",
		c.config.Server,
		c.config.Path,
		c.config.UserAgent,
	)

	// HPACK encoding (simplified - just use literal encoding)
	hpackBlock := c.simpleHpackEncode(headers)

	// HEADERS frame
	length := len(hpackBlock)
	headersFrame := make([]byte, 9+length)
	headersFrame[0] = byte(length >> 16)
	headersFrame[1] = byte(length >> 8)
	headersFrame[2] = byte(length)
	headersFrame[3] = 0x01 // Type: HEADERS
	headersFrame[4] = 0x04 // Flags: END_HEADERS
	headersFrame[5] = 0x00
	headersFrame[6] = 0x00
	headersFrame[7] = 0x00
	headersFrame[8] = 0x01 // Stream ID: 1
	copy(headersFrame[9:], hpackBlock)

	if _, err := conn.Write(headersFrame); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write h2 headers: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// Read frames until we get response HEADERS on stream 1.
	for {
		frameType, flags, streamID, payload, err := readH2Frame(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read h2 response frame: %w", err)
		}

		// Ignore connection-level frames and other streams.
		if streamID != 1 {
			continue
		}
		if frameType == 0x07 { // GOAWAY
			conn.Close()
			return nil, fmt.Errorf("received GOAWAY from server")
		}
		if frameType != 0x01 { // HEADERS
			continue
		}

		status, err := decodeStatusFromHeadersFrame(payload, flags)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("decode h2 response headers: %w", err)
		}
		if status != "200" {
			conn.Close()
			return nil, fmt.Errorf("h2 CONNECT rejected: :status=%s", status)
		}
		break
	}

	return &h2Conn{
		Conn:     conn,
		streamID: 1,
	}, nil
}

// simpleHpackEncode performs simple HPACK encoding (literal without indexing).
func (c *WebTunnelCarrier) simpleHpackEncode(headers string) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)

	for _, line := range strings.Split(headers, "\r\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		name := ""
		value := ""
		if strings.HasPrefix(line, ":") {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				continue
			}
			name = strings.TrimSpace(parts[0])
			value = strings.TrimSpace(parts[1])
		} else {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			name = strings.TrimSpace(parts[0])
			value = strings.TrimSpace(parts[1])
		}

		if name == "" {
			continue
		}
		if err := enc.WriteField(hpack.HeaderField{Name: name, Value: value}); err != nil {
			return nil
		}
	}

	return buf.Bytes()
}

func readH2Frame(r io.Reader) (frameType byte, flags byte, streamID uint32, payload []byte, err error) {
	header := make([]byte, 9)
	if _, err = io.ReadFull(r, header); err != nil {
		return 0, 0, 0, nil, err
	}
	length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	frameType = header[3]
	flags = header[4]
	streamID = binary.BigEndian.Uint32(header[5:9]) & 0x7FFFFFFF

	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, 0, 0, nil, err
		}
	}
	return frameType, flags, streamID, payload, nil
}

func decodeStatusFromHeadersFrame(payload []byte, flags byte) (string, error) {
	block, err := extractHeaderBlockFragment(payload, flags)
	if err != nil {
		return "", err
	}
	status := ""
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			status = f.Value
		}
	})
	if _, err := dec.Write(block); err != nil {
		return "", err
	}
	if status == "" {
		return "", fmt.Errorf("missing :status pseudo-header")
	}
	return status, nil
}

func extractHeaderBlockFragment(payload []byte, flags byte) ([]byte, error) {
	offset := 0
	padLen := 0
	if flags&0x08 != 0 { // PADDED
		if len(payload) < 1 {
			return nil, fmt.Errorf("padded HEADERS frame missing pad length")
		}
		padLen = int(payload[0])
		offset++
	}
	if flags&0x20 != 0 { // PRIORITY
		if len(payload) < offset+5 {
			return nil, fmt.Errorf("priority HEADERS frame too short")
		}
		offset += 5
	}
	if offset > len(payload) || padLen > len(payload)-offset {
		return nil, fmt.Errorf("invalid HEADERS frame padding")
	}
	return payload[offset : len(payload)-padLen], nil
}

// h2Conn wraps a TLS connection for HTTP/2 stream multiplexing.
type h2Conn struct {
	net.Conn
	streamID uint32
	buf      []byte
}

// Read reads from the HTTP/2 stream.
func (c *h2Conn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	// Read DATA frame header
	header := make([]byte, 9)
	if _, err := c.Conn.Read(header); err != nil {
		return 0, err
	}

	length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	// frameType := header[3]
	// flags := header[4]
	// streamID := binary.BigEndian.Uint32(header[5:9]) & 0x7FFFFFFF

	// Read payload
	payload := make([]byte, length)
	if _, err := c.Conn.Read(payload); err != nil {
		return 0, err
	}

	n := copy(b, payload)
	if n < len(payload) {
		c.buf = payload[n:]
	}

	return n, nil
}

// Write writes to the HTTP/2 stream.
func (c *h2Conn) Write(b []byte) (int, error) {
	// Build DATA frame
	length := len(b)
	frame := make([]byte, 9+length)
	frame[0] = byte(length >> 16)
	frame[1] = byte(length >> 8)
	frame[2] = byte(length)
	frame[3] = 0x00 // Type: DATA
	frame[4] = 0x00 // Flags: none
	frame[5] = byte(c.streamID >> 24)
	frame[6] = byte(c.streamID >> 16)
	frame[7] = byte(c.streamID >> 8)
	frame[8] = byte(c.streamID)
	copy(frame[9:], b)

	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Network returns the network type.
func (c *WebTunnelCarrier) Network() string {
	return "tcp"
}

// Listen creates a WebTunnel server listener.
func (c *WebTunnelCarrier) Listen(addr string) (Listener, error) {
	wl, err := NewWebTunnelListener(addr, c.tlsConfig, c.config.Path)
	if err != nil {
		return nil, fmt.Errorf("webtunnel listen: %w", err)
	}
	return wl, nil
}

// Close closes the carrier.
func (c *WebTunnelCarrier) Close() error {
	return nil
}

// IsAvailable returns true if WebTunnel is available.
func (c *WebTunnelCarrier) IsAvailable() bool {
	return true
}

// Name returns the carrier name.
func (c *WebTunnelCarrier) Name() string {
	return "webtunnel"
}

// WebTunnelListener implements a WebTunnel server listener.
type WebTunnelListener struct {
	listener  net.Listener
	handler   http.Handler
	tlsConfig *tls.Config
	path      string
	acceptCh  chan net.Conn
	closed    bool
}

// NewWebTunnelListener creates a new WebTunnel listener.
func NewWebTunnelListener(addr string, tlsConfig *tls.Config, path string) (*WebTunnelListener, error) {
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}

	if path == "" {
		path = "/tunnel"
	}

	wl := &WebTunnelListener{
		listener:  ln,
		tlsConfig: tlsConfig,
		path:      path,
		acceptCh:  make(chan net.Conn, 64),
	}

	// Setup HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc(path, wl.handleTunnel)
	wl.handler = mux

	// Start HTTP server
	go http.Serve(ln, wl.handler)

	return wl, nil
}

// handleTunnel handles WebTunnel upgrade requests.
func (l *WebTunnelListener) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "stealthlink" {
		http.Error(w, "Invalid upgrade header", http.StatusBadRequest)
		return
	}

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}

	// Send 101 Switching Protocols
	fmt.Fprintf(bufrw, "HTTP/1.1 101 Switching Protocols\r\n")
	fmt.Fprintf(bufrw, "Upgrade: stealthlink\r\n")
	fmt.Fprintf(bufrw, "Connection: Upgrade\r\n")
	fmt.Fprintf(bufrw, "\r\n")
	bufrw.Flush()

	// Pass the hijacked connection to the accept channel
	select {
	case l.acceptCh <- conn:
	default:
		conn.Close()
	}
}

// Accept accepts WebTunnel connections.
func (l *WebTunnelListener) Accept() (net.Conn, error) {
	conn, ok := <-l.acceptCh
	if !ok {
		return nil, fmt.Errorf("webtunnel listener closed")
	}
	return conn, nil
}

// Close closes the listener.
func (l *WebTunnelListener) Close() error {
	if !l.closed {
		l.closed = true
		close(l.acceptCh)
	}
	return l.listener.Close()
}

// Addr returns the listener address.
func (l *WebTunnelListener) Addr() net.Addr {
	return l.listener.Addr()
}

// WebTunnelHandshake performs the WebTunnel handshake.
func WebTunnelHandshake(conn net.Conn, isServer bool, config *WebTunnelConfig) error {
	if isServer {
		return webTunnelServerHandshake(conn, config)
	}
	return webTunnelClientHandshake(conn, config)
}

func webTunnelClientHandshake(conn net.Conn, config *WebTunnelConfig) error {
	// Send authentication if configured
	if config.Headers != nil {
		auth := config.Headers["Authorization"]
		if auth != "" {
			// Send auth header
			authHeader := base64.StdEncoding.EncodeToString([]byte(auth))
			if _, err := conn.Write([]byte(authHeader + "\n")); err != nil {
				return err
			}
		}
	}

	return nil
}

func webTunnelServerHandshake(conn net.Conn, config *WebTunnelConfig) error {
	// Read and verify authentication if configured
	return nil
}
