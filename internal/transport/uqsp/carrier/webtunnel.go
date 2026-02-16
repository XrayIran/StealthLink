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
	clientTLS *tls.Config
	serverTLS *tls.Config
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
func NewWebTunnelCarrier(cfg WebTunnelConfig, baseTLS *tls.Config, smuxCfg *smux.Config) *WebTunnelCarrier {
	if cfg.Path == "" {
		cfg.Path = "/tunnel"
	}
	if cfg.Version == "" {
		cfg.Version = "h2"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0"
	}

	clientTLS := &tls.Config{}
	if baseTLS != nil {
		clientTLS = baseTLS.Clone()
	}
	clientTLS.InsecureSkipVerify = cfg.TLSInsecureSkipVerify
	if strings.TrimSpace(cfg.TLSServerName) != "" {
		clientTLS.ServerName = strings.TrimSpace(cfg.TLSServerName)
	}

	serverTLS := baseTLS
	if serverTLS == nil {
		serverTLS = &tls.Config{}
	}

	return &WebTunnelCarrier{
		config:    cfg,
		smuxCfg:   smuxCfg,
		clientTLS: clientTLS,
		serverTLS: serverTLS,
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
	conn, err := dialCarrierTLS(ctx, "tcp", c.config.Server, c.clientTLS, c.config.TLSFingerprint)
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

	if !hasUpgradeToken(resp.Header.Get("Upgrade"), "stealthlink") {
		conn.Close()
		return nil, fmt.Errorf("unexpected upgrade header: %s", resp.Header.Get("Upgrade"))
	}

	return conn, nil
}

func hasUpgradeToken(headerValue string, want string) bool {
	if strings.TrimSpace(headerValue) == "" {
		return false
	}
	// RFC 7230 token list; be permissive about comma/space separated values.
	for _, part := range strings.Split(headerValue, ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	// Some stacks may send space-separated values.
	for _, part := range strings.Fields(headerValue) {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}

// dialH2 uses HTTP/2 CONNECT to establish the tunnel.
func (c *WebTunnelCarrier) dialH2(ctx context.Context, addr string) (net.Conn, error) {
	// Connect to server
	conn, err := dialCarrierTLS(ctx, "tcp", c.config.Server, c.clientTLS, c.config.TLSFingerprint)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}

	// Send HTTP/2 connection preface
	if _, err := writeAll(conn, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write h2 preface: %w", err)
	}

	// Send SETTINGS frame
	if err := writeH2Frame(conn, 0x04, 0x00, 0, nil); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write h2 settings: %w", err)
	}

	// Read and ACK server SETTINGS (payload can be non-empty in real deployments).
	if err := awaitInitialH2Settings(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read h2 settings: %w", err)
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

	if _, err := writeAll(conn, headersFrame); err != nil {
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

		if streamID == 0 {
			if err := handleH2ControlFrame(conn, frameType, flags, payload); err != nil {
				conn.Close()
				return nil, fmt.Errorf("h2 control frame: %w", err)
			}
			continue
		}
		if frameType == 0x07 { // GOAWAY
			conn.Close()
			return nil, fmt.Errorf("received GOAWAY from server")
		}
		if streamID != 1 {
			continue
		}
		if frameType != 0x01 { // HEADERS
			continue
		}

		block, err := readResponseHeaderBlock(conn, streamID, payload, flags)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("collect h2 response headers: %w", err)
		}

		status, err := decodeStatusFromHeaderBlock(block)
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
	return decodeStatusFromHeaderBlock(block)
}

func decodeStatusFromHeaderBlock(block []byte) (string, error) {
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

	for {
		frameType, flags, streamID, payload, err := readH2Frame(c.Conn)
		if err != nil {
			return 0, err
		}

		if streamID == 0 {
			if err := handleH2ControlFrame(c.Conn, frameType, flags, payload); err != nil {
				return 0, err
			}
			continue
		}
		if streamID != c.streamID {
			continue
		}

		switch frameType {
		case 0x00: // DATA
			data, err := extractDataPayload(payload, flags)
			if err != nil {
				return 0, err
			}
			if len(data) == 0 {
				if flags&0x01 != 0 { // END_STREAM
					return 0, io.EOF
				}
				continue
			}
			n := copy(b, data)
			if n < len(data) {
				c.buf = append(c.buf[:0], data[n:]...)
			}
			return n, nil
		case 0x03: // RST_STREAM
			return 0, fmt.Errorf("stream reset by peer")
		case 0x07: // GOAWAY
			return 0, io.EOF
		default:
			// Ignore non-data frames for this stream.
		}
	}
}

// Write writes to the HTTP/2 stream.
func (c *h2Conn) Write(b []byte) (int, error) {
	const maxFramePayload = 16 * 1024
	total := 0
	for len(b) > 0 {
		chunk := len(b)
		if chunk > maxFramePayload {
			chunk = maxFramePayload
		}
		if err := writeH2Frame(c.Conn, 0x00, 0x00, c.streamID, b[:chunk]); err != nil {
			return total, err
		}
		total += chunk
		b = b[chunk:]
	}
	return total, nil
}

// Network returns the network type.
func (c *WebTunnelCarrier) Network() string {
	return "tcp"
}

// Listen creates a WebTunnel server listener.
func (c *WebTunnelCarrier) Listen(addr string) (Listener, error) {
	if c.serverTLS == nil || (len(c.serverTLS.Certificates) == 0 && c.serverTLS.GetCertificate == nil && c.serverTLS.GetConfigForClient == nil) {
		return nil, fmt.Errorf("webtunnel listen requires a server TLS config with certificates")
	}
	wl, err := NewWebTunnelListener(addr, c.serverTLS, c.config.Path)
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

	go wl.acceptLoop()

	return wl, nil
}

func (l *WebTunnelListener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if l.closed {
				return
			}
			continue
		}
		go l.handleConn(conn)
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (l *WebTunnelListener) handleConn(conn net.Conn) {
	defer func() {
		// If we didn't hand it off, close it.
	}()

	br := bufio.NewReader(conn)
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	peek, err := br.Peek(len(preface))
	_ = conn.SetReadDeadline(time.Time{})

	if err == nil && bytes.Equal(peek, preface) {
		if err := l.handleH2(conn, br); err != nil {
			_ = conn.Close()
		}
		return
	}
	if err := l.handleH1(conn, br); err != nil {
		_ = conn.Close()
	}
}

func (l *WebTunnelListener) handleH1(conn net.Conn, br *bufio.Reader) error {
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	defer req.Body.Close()
	if req.URL == nil || req.URL.Path != l.path {
		_, _ = io.WriteString(conn, "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return fmt.Errorf("invalid webtunnel path")
	}
	if req.Header.Get("Upgrade") != "stealthlink" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return fmt.Errorf("invalid upgrade header")
	}
	_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: stealthlink\r\nConnection: Upgrade\r\n\r\n")
	select {
	case l.acceptCh <- &bufferedConn{Conn: conn, r: br}:
		return nil
	default:
		return fmt.Errorf("accept queue full")
	}
}

func (l *WebTunnelListener) handleH2(conn net.Conn, br *bufio.Reader) error {
	// Consume client preface.
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err := io.ReadFull(br, make([]byte, len(preface))); err != nil {
		return err
	}

	// Await client's SETTINGS.
	for {
		ft, flags, sid, payload, err := readH2Frame(br)
		if err != nil {
			return err
		}
		if sid != 0 {
			continue
		}
		if ft == 0x04 && flags&0x01 == 0 { // SETTINGS (non-ACK)
			if len(payload)%6 != 0 {
				return fmt.Errorf("invalid SETTINGS payload length: %d", len(payload))
			}
			break
		}
	}

	// Send server SETTINGS (empty is fine) and ACK client's SETTINGS.
	if err := writeH2Frame(conn, 0x04, 0x00, 0, nil); err != nil {
		return err
	}
	if err := writeH2Frame(conn, 0x04, 0x01, 0, nil); err != nil {
		return err
	}

	// Read until CONNECT HEADERS on stream 1, then respond with :status 200.
	for {
		ft, flags, sid, payload, err := readH2Frame(br)
		if err != nil {
			return err
		}
		if sid == 0 {
			if err := handleH2ControlFrame(conn, ft, flags, payload); err != nil {
				return err
			}
			continue
		}
		if sid != 1 || ft != 0x01 { // HEADERS
			continue
		}

		var hb bytes.Buffer
		enc := hpack.NewEncoder(&hb)
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		_ = enc.WriteField(hpack.HeaderField{Name: "server", Value: "stealthlink"})
		if err := writeH2Frame(conn, 0x01, 0x04, 1, hb.Bytes()); err != nil {
			return err
		}
		break
	}

	select {
	case l.acceptCh <- &h2Conn{Conn: &bufferedConn{Conn: conn, r: br}, streamID: 1}:
		return nil
	default:
		return fmt.Errorf("accept queue full")
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

func awaitInitialH2Settings(conn net.Conn) error {
	for {
		frameType, flags, streamID, payload, err := readH2Frame(conn)
		if err != nil {
			return err
		}
		if streamID != 0 {
			continue
		}
		if frameType == 0x04 { // SETTINGS
			if flags&0x01 != 0 { // ACK
				continue
			}
			if len(payload)%6 != 0 {
				return fmt.Errorf("invalid SETTINGS payload length: %d", len(payload))
			}
			return writeH2Frame(conn, 0x04, 0x01, 0, nil)
		}
		if err := handleH2ControlFrame(conn, frameType, flags, payload); err != nil {
			return err
		}
	}
}

func readResponseHeaderBlock(conn net.Conn, streamID uint32, firstPayload []byte, firstFlags byte) ([]byte, error) {
	first, err := extractHeaderBlockFragment(firstPayload, firstFlags)
	if err != nil {
		return nil, err
	}
	block := append([]byte(nil), first...)
	if firstFlags&0x04 != 0 { // END_HEADERS
		return block, nil
	}

	for {
		frameType, flags, sid, payload, err := readH2Frame(conn)
		if err != nil {
			return nil, err
		}
		if sid != streamID {
			return nil, fmt.Errorf("unexpected interleaved frame stream=%d while waiting CONTINUATION", sid)
		}
		if frameType != 0x09 { // CONTINUATION
			return nil, fmt.Errorf("expected CONTINUATION frame, got type=%d", frameType)
		}
		block = append(block, payload...)
		if flags&0x04 != 0 { // END_HEADERS
			return block, nil
		}
	}
}

func extractDataPayload(payload []byte, flags byte) ([]byte, error) {
	if flags&0x08 == 0 { // not padded
		return payload, nil
	}
	if len(payload) < 1 {
		return nil, fmt.Errorf("padded DATA frame missing pad length")
	}
	padLen := int(payload[0])
	if padLen > len(payload)-1 {
		return nil, fmt.Errorf("invalid DATA padding")
	}
	return payload[1 : len(payload)-padLen], nil
}

func handleH2ControlFrame(conn net.Conn, frameType byte, flags byte, payload []byte) error {
	switch frameType {
	case 0x04: // SETTINGS
		if flags&0x01 == 0 { // non-ACK
			if len(payload)%6 != 0 {
				return fmt.Errorf("invalid SETTINGS payload length: %d", len(payload))
			}
			return writeH2Frame(conn, 0x04, 0x01, 0, nil)
		}
	case 0x06: // PING
		if len(payload) != 8 {
			return fmt.Errorf("invalid PING payload length: %d", len(payload))
		}
		if flags&0x01 == 0 {
			return writeH2Frame(conn, 0x06, 0x01, 0, payload)
		}
	case 0x07: // GOAWAY
		return fmt.Errorf("received GOAWAY")
	}
	return nil
}

func writeH2Frame(w io.Writer, frameType byte, flags byte, streamID uint32, payload []byte) error {
	if len(payload) > 0xFFFFFF {
		return fmt.Errorf("frame payload too large: %d", len(payload))
	}
	frame := make([]byte, 9+len(payload))
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = frameType
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7FFFFFFF)
	copy(frame[9:], payload)
	_, err := writeAll(w, frame)
	return err
}

func writeAll(w io.Writer, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := w.Write(p[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
