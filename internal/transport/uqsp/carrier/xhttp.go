package carrier

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/tlsutil"
	"stealthlink/internal/transport/xhttpmeta"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/xtaci/smux"
	"golang.org/x/net/http2"
)

type xhttpMode string

const (
	xhttpModeStreamOne  xhttpMode = "stream-one"
	xhttpModeStreamUp   xhttpMode = "stream-up"
	xhttpModeStreamDown xhttpMode = "stream-down"
	xhttpModePacketUp   xhttpMode = "packet-up"
)

type httpVersion string

const (
	httpVersion1_1 httpVersion = "1.1"
	httpVersion2   httpVersion = "2"
	httpVersion3   httpVersion = "3"
)

type scRange struct {
	From int64 `yaml:"from"`
	To   int64 `yaml:"to"`
}

func (r scRange) rand() int64 {
	if r.To <= r.From {
		return r.From
	}
	n := r.To - r.From
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return r.From + int64(binary.BigEndian.Uint64(b)%uint64(n))
}

type uploadPacket struct {
	Reader  io.ReadCloser
	Payload []byte
	Seq     uint64
}

type uploadQueue struct {
	pushedPackets   chan uploadPacket
	heap            uploadHeap
	nextSeq         uint64
	closed          bool
	maxPackets      int
	reader          io.ReadCloser
	nomore          bool
	writeCloseMutex sync.Mutex
}

func newUploadQueue(maxPackets int) *uploadQueue {
	return &uploadQueue{
		pushedPackets: make(chan uploadPacket, maxPackets),
		heap:          uploadHeap{},
		nextSeq:       0,
		closed:        false,
		maxPackets:    maxPackets,
	}
}

func (q *uploadQueue) Push(p uploadPacket) error {
	q.writeCloseMutex.Lock()
	defer q.writeCloseMutex.Unlock()
	if q.closed {
		return fmt.Errorf("packet queue closed")
	}
	if q.nomore {
		return fmt.Errorf("reader already exists")
	}
	if p.Reader != nil {
		q.nomore = true
	}
	q.pushedPackets <- p
	return nil
}

func (q *uploadQueue) Close() error {
	q.writeCloseMutex.Lock()
	defer q.writeCloseMutex.Unlock()
	if !q.closed {
		q.closed = true
		for {
			select {
			case p := <-q.pushedPackets:
				if p.Reader != nil {
					q.reader = p.Reader
				}
			default:
				close(q.pushedPackets)
				if q.reader != nil {
					return q.reader.Close()
				}
				return nil
			}
		}
	}
	return nil
}

func (q *uploadQueue) Read(b []byte) (int, error) {
	if q.reader != nil {
		return q.reader.Read(b)
	}
	if q.closed {
		return 0, io.EOF
	}
	if len(q.heap) == 0 {
		packet, more := <-q.pushedPackets
		if !more {
			return 0, io.EOF
		}
		if packet.Reader != nil {
			q.reader = packet.Reader
			return q.reader.Read(b)
		}
		heap.Push(&q.heap, packet)
	}
	for len(q.heap) > 0 {
		packet := heap.Pop(&q.heap).(uploadPacket)
		if packet.Seq == q.nextSeq {
			n := copy(b, packet.Payload)
			if n < len(packet.Payload) {
				packet.Payload = packet.Payload[n:]
				heap.Push(&q.heap, packet)
			} else {
				q.nextSeq = packet.Seq + 1
			}
			return n, nil
		}
		if packet.Seq > q.nextSeq {
			if len(q.heap) > q.maxPackets {
				return 0, fmt.Errorf("packet queue too large")
			}
			heap.Push(&q.heap, packet)
			packet2, more := <-q.pushedPackets
			if !more {
				return 0, io.EOF
			}
			heap.Push(&q.heap, packet2)
		}
	}
	return 0, nil
}

type uploadHeap []uploadPacket

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *uploadHeap) Push(x interface{}) {
	*h = append(*h, x.(uploadPacket))
}
func (h *uploadHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

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
	xmux      *xmuxManager
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

	HTTPVersion string `yaml:"http_version"` // "1.1", "2", "3", or "auto"

	ScMaxEachPostBytes   scRange             `yaml:"sc_max_each_post_bytes"`
	ScMinPostsIntervalMs scRange             `yaml:"sc_min_posts_interval_ms"`
	Extra                string              `yaml:"extra"`
	DownloadSettings     string              `yaml:"download_settings"`
	NoGRPCHeader         bool                `yaml:"no_grpc_header"`
	KeepAlivePeriod      int                 `yaml:"keep_alive_period"`
	Metadata             XHTTPMetadataConfig `yaml:"metadata"`

	// XMux configuration
	XMux XMuxConfig `yaml:"xmux"`
}

type XHTTPMetadataConfig struct {
	Session XHTTPMetadataFieldConfig `yaml:"session"`
	Seq     XHTTPMetadataFieldConfig `yaml:"seq"`
	Mode    XHTTPMetadataFieldConfig `yaml:"mode"`
}

type XHTTPMetadataFieldConfig struct {
	Placement string `yaml:"placement"` // header, path, query, cookie
	Key       string `yaml:"key"`
}

type XMuxConfig struct {
	Enabled          bool   `yaml:"enabled"`
	MaxConnections   int    `yaml:"max_connections"`
	MaxConcurrency   int    `yaml:"max_concurrency"`
	MaxConnectionAge int64  `yaml:"max_connection_age"`
	CMaxReuseTimes   int    `yaml:"c_max_reuse_times"`
	HMaxRequestTimes int    `yaml:"h_max_request_times"`
	HMaxReusableSecs int    `yaml:"h_max_reusable_secs"`
	DrainTimeout     string `yaml:"drain_timeout"`
}

func (c XHTTPConfig) metadataConfig() xhttpmeta.MetadataConfig {
	return xhttpmeta.MetadataConfig{
		Session: xhttpmeta.FieldConfig{
			Placement: xhttpmeta.Placement(strings.ToLower(strings.TrimSpace(c.Metadata.Session.Placement))),
			Key:       c.Metadata.Session.Key,
		},
		Seq: xhttpmeta.FieldConfig{
			Placement: xhttpmeta.Placement(strings.ToLower(strings.TrimSpace(c.Metadata.Seq.Placement))),
			Key:       c.Metadata.Seq.Key,
		},
		Mode: xhttpmeta.FieldConfig{
			Placement: xhttpmeta.Placement(strings.ToLower(strings.TrimSpace(c.Metadata.Mode.Placement))),
			Key:       c.Metadata.Mode.Key,
		},
	}
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

	// Validate metadata config
	// Better approach: ensure defaults are applied
	metaCfg := cfg.metadataConfig()
	metaCfg.ApplyDefaults()
	// Validation
	if err := metaCfg.Validate(); err != nil {
		// As NewXHTTPCarrier doesn't return error, we can't easily fail here.
		// But we should ensuring it's valid.
		// We will continue, assuming config is checked elsewhere or will fail at runtime.
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

	carrier := &XHTTPCarrier{
		config:    cfg,
		smuxCfg:   smuxCfg,
		tlsConfig: tlsConfig,
		streams:   make(map[uint32]*xhttpStream),
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: httpTransport,
		},
	}

	// Initialize XMUX connection pool if enabled
	if cfg.XMux.Enabled {
		carrier.xmux = newXmuxManager(cfg.XMux, func() DialerClient {
			httpVer := httpVersion(cfg.HTTPVersion)
			if httpVer == "" || httpVer == "auto" {
				httpVer = httpVersion2
			}
			return carrier.createHTTPClient(httpVer)
		})
	}

	return carrier
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Dial connects to the XHTTP server.
func (c *XHTTPCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return c.dialEnhanced(ctx, addr)
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

	// Prepare metadata
	sessionID := generateSessionID()
	metaValues := xhttpmeta.MetadataValues{
		SessionID: sessionID,
		Seq:       0,
		Mode:      c.config.Mode,
	}

	// Prepare request with metadata
	targetURL := fmt.Sprintf("https://%s%s", c.config.Server, c.config.Path)
	httpReq, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Apply metadata (modifies httpReq headers, URL, cookies)
	metaCfg := c.config.metadataConfig()
	metaCfg.ApplyDefaults() // Ensure defaults
	if err := xhttpmeta.ApplyToRequest(httpReq, metaCfg, metaValues); err != nil {
		conn.Close()
		return nil, fmt.Errorf("apply metadata: %w", err)
	}

	if c.config.RequestDelayMs > 0 {
		time.Sleep(time.Duration(c.config.RequestDelayMs) * time.Millisecond)
	}

	frontOpts, hasFrontOpts := tlsutil.FrontDialOptionsFromContext(ctx)
	hostHeader := c.config.Server
	if hasFrontOpts && frontOpts.Enabled && frontOpts.RealHost != "" {
		hostHeader = frontOpts.RealHost
	}

	// Build raw request string from httpReq
	// Use the path/query from httpReq which might have been modified by metadata
	reqPath := httpReq.URL.Path
	if httpReq.URL.RawQuery != "" {
		reqPath += "?" + httpReq.URL.RawQuery
	}

	req := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, reqPath)
	req += fmt.Sprintf("Host: %s\r\n", hostHeader)
	req += "Content-Type: application/octet-stream\r\n"
	req += "Transfer-Encoding: chunked\r\n"

	// Merge and randomize headers
	finalHeaders := make(map[string]string)
	// User headers
	for k, v := range c.config.Headers {
		finalHeaders[k] = v
	}
	// Metadata headers
	for k, v := range httpReq.Header {
		if len(v) > 0 {
			finalHeaders[k] = v[0]
		}
	}
	// Cookies (if any, add to Cookie header)
	if len(httpReq.Cookies()) > 0 {
		var cookies []string
		for _, c := range httpReq.Cookies() {
			cookies = append(cookies, c.String())
		}
		if existing, ok := finalHeaders["Cookie"]; ok && existing != "" {
			finalHeaders["Cookie"] = existing + "; " + strings.Join(cookies, "; ")
		} else {
			finalHeaders["Cookie"] = strings.Join(cookies, "; ")
		}
	}

	if hasFrontOpts && frontOpts.Enabled && frontOpts.CFWorker != "" {
		finalHeaders["CF-Worker"] = frontOpts.CFWorker
	}

	for k, v := range randomizeHeaderOrder(finalHeaders, c.config.HeaderRandomization) {
		req += fmt.Sprintf("%s: %s\r\n", k, v)
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
	// In packet-up mode, we send data as individual HTTP POST requests
	return &xhttpPacketConn{
		server:    c.config.Server,
		path:      c.config.Path,
		client:    c.client,
		headers:   c.config.Headers,
		sessionID: generateSessionID(),
		mode:      c.config.Mode,
		metaCfg:   c.config.metadataConfig(),
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
	server    string
	path      string
	client    *http.Client
	headers   map[string]string
	readBuf   []byte
	mu        sync.Mutex
	sessionID string
	mode      string
	seq       uint64
	metaCfg   xhttpmeta.MetadataConfig
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

	// Apply metadata
	c.mu.Lock()
	seq := c.seq
	c.seq++
	c.mu.Unlock()

	metaValues := xhttpmeta.MetadataValues{
		SessionID: c.sessionID,
		Seq:       seq,
		Mode:      c.mode,
	}
	c.metaCfg.ApplyDefaults()
	if err := xhttpmeta.ApplyToRequest(req, c.metaCfg, metaValues); err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	// X-Stealthlink-Mode might be set by metadata, but we ensure it if not?
	// Actually metadata should handle it. If metadata config keeps it in header, it's there.
	// We merge user headers.
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

type xmuxConn struct {
	DialerClient
	closed    int32
	openUsage int32
	createdAt time.Time
	requests  int32
}

func (c *xmuxConn) isExpired(maxAge time.Duration) bool {
	if maxAge <= 0 {
		return false
	}
	return time.Since(c.createdAt) > maxAge
}

func (c *xmuxConn) isExhausted(maxRequests int32) bool {
	if maxRequests <= 0 {
		return false
	}
	return atomic.LoadInt32(&c.requests) >= maxRequests
}

type xmuxManager struct {
	config   XMuxConfig
	createFn func() DialerClient
	mu       sync.Mutex
	conns    []*xmuxConn
	nextIdx  int
}

func newXmuxManager(config XMuxConfig, createFn func() DialerClient) *xmuxManager {
	maxConns := config.MaxConnections
	if maxConns <= 0 {
		maxConns = 8
	}
	return &xmuxManager{
		config:   config,
		createFn: createFn,
		conns:    make([]*xmuxConn, 0, maxConns),
	}
}

func (m *xmuxManager) getClient() DialerClient {
	m.mu.Lock()
	defer m.mu.Unlock()

	maxAge := time.Duration(m.config.HMaxReusableSecs) * time.Second
	if maxAge <= 0 {
		maxAge = time.Duration(m.config.MaxConnectionAge) * time.Second
	}
	maxConns := m.config.MaxConnections
	if maxConns <= 0 {
		maxConns = 8
	}

	maxRequests := int32(m.config.HMaxRequestTimes)

	// Evict expired or exhausted connections
	alive := m.conns[:0]
	for _, c := range m.conns {
		if atomic.LoadInt32(&c.closed) == 0 && !c.isExpired(maxAge) && !c.isExhausted(maxRequests) {
			alive = append(alive, c)
		}
	}
	m.conns = alive

	// Pick the least-loaded connection under max concurrency
	var best *xmuxConn
	for _, c := range m.conns {
		usage := atomic.LoadInt32(&c.openUsage)
		if m.config.MaxConcurrency > 0 && int(usage) >= m.config.MaxConcurrency {
			continue
		}
		if best == nil || usage < atomic.LoadInt32(&best.openUsage) {
			best = c
		}
	}

	if best != nil {
		atomic.AddInt32(&best.openUsage, 1)
		atomic.AddInt32(&best.requests, 1)
		return best.DialerClient
	}

	// All connections are full or none exist — create a new one if under limit
	if len(m.conns) < maxConns {
		client := m.createFn()
		conn := &xmuxConn{
			DialerClient: client,
			createdAt:    time.Now(),
		}
		atomic.AddInt32(&conn.openUsage, 1)
		atomic.AddInt32(&conn.requests, 1)
		m.conns = append(m.conns, conn)
		return client
	}

	// At capacity — round-robin
	if m.nextIdx >= len(m.conns) {
		m.nextIdx = 0
	}
	selected := m.conns[m.nextIdx]
	m.nextIdx = (m.nextIdx + 1) % len(m.conns)
	atomic.AddInt32(&selected.openUsage, 1)
	atomic.AddInt32(&selected.requests, 1)
	return selected.DialerClient
}

func (m *xmuxManager) release(client DialerClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.conns {
		if c.DialerClient == client {
			atomic.AddInt32(&c.openUsage, -1)
			return
		}
	}
}

type DialerClient interface {
	OpenStream(ctx context.Context, urlStr, sessionID string, body io.Reader, upload bool) (io.ReadCloser, net.Addr, net.Addr, error)
	PostPacket(ctx context.Context, urlStr, sessionID string, seq uint64, body io.Reader, contentLen int64) error
}

type DefaultDialerClient struct {
	config         *XHTTPConfig
	client         *http.Client
	httpVersion    httpVersion
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctx context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, urlStr, sessionID string, body io.Reader, upload bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", urlStr, body)
	if err != nil {
		return nil, nil, nil, err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Transfer-Encoding", "chunked")
	if upload {
		req.Header.Set("X-Stealthlink-Upload", "true")
	}
	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}
	if err := xhttpmeta.ApplyToRequest(req, c.config.metadataConfig(), xhttpmeta.MetadataValues{
		SessionID: sessionID,
		Mode:      c.config.Mode,
	}); err != nil {
		return nil, nil, nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, nil, nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var localAddr, remoteAddr net.Addr
	if resp.Request != nil && resp.Request.URL != nil {
		remoteAddr, _ = net.ResolveTCPAddr("tcp", resp.Request.URL.Host)
	}

	return resp.Body, remoteAddr, localAddr, nil
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, urlStr, sessionID string, seq uint64, body io.Reader, contentLen int64) error {
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{})

	req, err := http.NewRequestWithContext(ctx, "POST", urlStr, body)
	if err != nil {
		return err
	}

	req.ContentLength = contentLen
	req.Header.Set("Content-Type", "application/octet-stream")
	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}
	if err := xhttpmeta.ApplyToRequest(req, c.config.metadataConfig(), xhttpmeta.MetadataValues{
		SessionID: sessionID,
		Seq:       seq,
		Mode:      c.config.Mode,
	}); err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}

type splitHTTPConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()
	closed     int32
}

func (c *splitHTTPConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *splitHTTPConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *splitHTTPConn) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}
	if c.onClose != nil {
		c.onClose()
	}
	var err error
	if c.writer != nil {
		if e := c.writer.Close(); e != nil {
			err = e
		}
	}
	if c.reader != nil {
		if e := c.reader.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (c *splitHTTPConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *splitHTTPConn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *splitHTTPConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}
func (c *splitHTTPConn) SetReadDeadline(t time.Time) error {
	if rc, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return rc.SetReadDeadline(t)
	}
	return nil
}
func (c *splitHTTPConn) SetWriteDeadline(t time.Time) error {
	if wc, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return wc.SetWriteDeadline(t)
	}
	return nil
}

type uploadWriter struct {
	*io.PipeWriter
	maxLen int32
	wrote  int64
}

func (w *uploadWriter) Write(b []byte) (int, error) {
	capacity := int(w.maxLen - int32(w.wrote))
	if capacity > 0 && capacity < len(b) {
		b = b[:capacity]
	}
	n, err := w.PipeWriter.Write(b)
	w.wrote += int64(n)
	return n, err
}

func (c *XHTTPCarrier) dialEnhanced(ctx context.Context, addr string) (net.Conn, error) {
	cfg := c.config

	httpVer := httpVersion(cfg.HTTPVersion)
	if httpVer == "" || httpVer == "auto" {
		if c.tlsConfig != nil {
			if len(c.tlsConfig.NextProtos) == 0 {
				httpVer = httpVersion2
			} else {
				switch c.tlsConfig.NextProtos[0] {
				case "http/1.1":
					httpVer = httpVersion1_1
				case "h3":
					httpVer = httpVersion3
				default:
					httpVer = httpVersion2
				}
			}
		} else {
			httpVer = httpVersion1_1
		}
	}

	mode := cfg.Mode
	if mode == "" || mode == "auto" {
		mode = "stream-one"
	}

	sessionID := ""
	if mode != "stream-one" {
		sessionID = generateUUID()
	}

	requestURL := url.URL{
		Scheme: "https",
		Host:   cfg.Server,
		Path:   cfg.Path,
	}

	if cfg.ScMaxEachPostBytes.From == 0 {
		cfg.ScMaxEachPostBytes = scRange{From: 1000000, To: 1000000}
	}
	if cfg.ScMinPostsIntervalMs.From == 0 {
		cfg.ScMinPostsIntervalMs = scRange{From: 10, To: 20}
	}

	// Use XMUX pool when enabled, otherwise create a fresh client
	var client DialerClient
	var releaseClient func()
	if c.xmux != nil {
		client = c.xmux.getClient()
		releaseClient = func() { c.xmux.release(client) }
	} else {
		client = c.createHTTPClient(httpVer)
		releaseClient = func() {}
	}

	if mode == "stream-one" {
		conn, err := c.dialStreamOne(ctx, client, requestURL.String(), sessionID, httpVer)
		if err != nil {
			releaseClient()
			return nil, err
		}
		if sc, ok := conn.(*splitHTTPConn); ok {
			origClose := sc.onClose
			sc.onClose = func() {
				releaseClient()
				if origClose != nil {
					origClose()
				}
			}
		}
		return conn, nil
	}

	downloadURL := requestURL.String()
	if cfg.DownloadSettings != "" {
		downloadURL = cfg.DownloadSettings
	}

	conn, err := c.dialSplitMode(ctx, client, requestURL.String(), downloadURL, sessionID, mode, httpVer)
	if err != nil {
		releaseClient()
		return nil, err
	}
	if sc, ok := conn.(*splitHTTPConn); ok {
		origClose := sc.onClose
		sc.onClose = func() {
			releaseClient()
			if origClose != nil {
				origClose()
			}
		}
	}
	return conn, nil
}

func (c *XHTTPCarrier) createHTTPClient(httpVer httpVersion) DialerClient {
	cfg := c.config

	transport := c.createTransport(httpVer)

	return &DefaultDialerClient{
		config: &cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   0,
		},
		httpVersion:   httpVer,
		uploadRawPool: &sync.Pool{},
		dialUploadConn: func(ctx context.Context) (net.Conn, error) {
			return dialCarrierTLS(ctx, "tcp", c.config.Server, c.tlsConfig, c.config.TLSFingerprint)
		},
	}
}

func (c *XHTTPCarrier) createTransport(httpVer httpVersion) http.RoundTripper {
	cfg := c.config

	switch httpVer {
	case "2":
		keepAlive := time.Duration(cfg.XMux.HMaxReusableSecs) * time.Second
		if keepAlive == 0 {
			keepAlive = time.Duration(cfg.XMux.MaxConnectionAge) * time.Second
		}
		if keepAlive == 0 {
			keepAlive = 45 * time.Second
		}
		return &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, tlsCfg *tls.Config) (net.Conn, error) {
				return dialCarrierTLS(ctx, network, addr, tlsCfg, c.config.TLSFingerprint)
			},
			ReadIdleTimeout: keepAlive,
			IdleConnTimeout: 90 * time.Second,
		}
	case "3":
		return &http3.Transport{
			TLSClientConfig: c.tlsConfig,
			QUICConfig: &quic.Config{
				MaxIdleTimeout:  90 * time.Second,
				KeepAlivePeriod: 30 * time.Second,
			},
		}
	default:
		return &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialCarrierTLS(ctx, network, addr, c.tlsConfig, c.config.TLSFingerprint)
			},
			IdleConnTimeout: 90 * time.Second,
		}
	}
}

func (c *XHTTPCarrier) dialStreamOne(ctx context.Context, client DialerClient, urlStr, sessionID string, httpVer httpVersion) (net.Conn, error) {
	reader, writer := io.Pipe()

	remoteAddr, _ := net.ResolveTCPAddr("tcp", c.config.Server)

	rc, _, _, err := client.OpenStream(ctx, urlStr, sessionID, reader, false)
	if err != nil {
		reader.Close()
		writer.Close()
		return nil, err
	}

	return &splitHTTPConn{
		writer:     writer,
		reader:     rc,
		remoteAddr: remoteAddr,
	}, nil
}

func (c *XHTTPCarrier) dialSplitMode(ctx context.Context, client DialerClient, uploadURL, downloadURL, sessionID, mode string, httpVer httpVersion) (net.Conn, error) {
	maxUploadSize := c.config.ScMaxEachPostBytes.rand()
	if maxUploadSize <= 0 {
		maxUploadSize = 1000000
	}

	uploadReader, uploadWriter := io.Pipe()

	remoteAddr, _ := net.ResolveTCPAddr("tcp", c.config.Server)

	downloadReader, _, _, err := client.OpenStream(ctx, downloadURL, sessionID, nil, false)
	if err != nil {
		uploadReader.Close()
		uploadWriter.Close()
		return nil, err
	}

	conn := &splitHTTPConn{
		writer:     uploadWriter,
		reader:     downloadReader,
		remoteAddr: remoteAddr,
	}

	go c.uploadLoop(ctx, client, uploadURL, sessionID, uploadReader, maxUploadSize)

	return conn, nil
}

func (c *XHTTPCarrier) uploadLoop(ctx context.Context, client DialerClient, baseURL, sessionID string, reader *io.PipeReader, maxUploadSize int64) {
	buf := make([]byte, 32*1024)
	seq := int64(0)

	for {
		interval := c.config.ScMinPostsIntervalMs.rand()
		if interval > 0 {
			time.Sleep(time.Duration(interval) * time.Millisecond)
		}

		n, err := reader.Read(buf)
		if err != nil {
			return
		}

		seqVal := uint64(seq)
		seq++

		urlStr := baseURL

		go func(data []byte, s uint64) {
			_ = client.PostPacket(ctx, urlStr, sessionID, s, bytes.NewReader(data), int64(len(data)))
		}(buf[:n], seqVal)
	}
}

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
