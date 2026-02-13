// Package trusttunnel implements TrustTunnel protocol support
// with H1/H2/H3 multiplexing and obfuscation.
package trusttunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/xtaci/smux"
	"golang.org/x/net/http2"
)

// ProtocolVersion represents TrustTunnel protocol version
type ProtocolVersion string

const (
	VersionH1  ProtocolVersion = "h1"
	VersionH2  ProtocolVersion = "h2"
	VersionH3  ProtocolVersion = "h3"
	VersionMux ProtocolVersion = "mux" // Automatic multiplexing
)

// Config configures TrustTunnel transport
type Config struct {
	// Server endpoint (HTTPS URL)
	Server string

	// Protocol version to use
	Version ProtocolVersion

	// TLS configuration
	TLSConfig *tls.Config

	// Authentication
	Token    string
	Username string
	Password string

	// HTTP settings
	UserAgent       string
	Headers         map[string]string
	RequestInterval time.Duration

	// Multiplexing
	MaxConcurrent int
	StreamTimeout time.Duration

	// Obfuscation
	PaddingMin     int
	PaddingMax     int
	HostRotate     []string
	DomainFronting string
}

// DefaultConfig returns default TrustTunnel configuration
func DefaultConfig() *Config {
	return &Config{
		Version:         VersionMux,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		RequestInterval: 30 * time.Second,
		MaxConcurrent:   8,
		StreamTimeout:   60 * time.Second,
		PaddingMin:      0,
		PaddingMax:      256,
		Headers:         make(map[string]string),
	}
}

// TrustTunnel represents a TrustTunnel client
type TrustTunnel struct {
	config     *Config
	version    ProtocolVersion
	httpClient *http.Client
	quicConn   quic.Conn //nolint:unused

	// Connection state
	closed  atomic.Bool
	closeCh chan struct{}

	// Streams
	streams   map[uint32]*ttStream
	streamID  atomic.Uint32
	streamsMu sync.RWMutex

	// Statistics
	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64
	streamsIn atomic.Uint64
}

// ttStream represents a TrustTunnel stream
type ttStream struct {
	id      uint32
	tunnel  *TrustTunnel
	txCh    chan []byte
	rxCh    chan []byte
	closeCh chan struct{}
	closed  atomic.Bool

	// Read buffer for partial reads — guarded by readMu
	readMu     sync.Mutex
	readBuf    []byte
	readOffset int

	// Addresses captured from HTTP conn during stream init
	localAddr  net.Addr
	remoteAddr net.Addr

	// Deadlines
	readDeadline  atomic.Value // time.Time
	writeDeadline atomic.Value // time.Time
}

// Dial connects to a TrustTunnel server
func Dial(ctx context.Context, config *Config) (*TrustTunnel, error) {
	if config == nil {
		config = DefaultConfig()
	} else {
		// Normalize partial configs so callers can set only required fields.
		if config.Version == "" {
			config.Version = VersionMux
		}
		if config.UserAgent == "" {
			config.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
		}
		if config.RequestInterval <= 0 {
			config.RequestInterval = 30 * time.Second
		}
		if config.MaxConcurrent <= 0 {
			config.MaxConcurrent = 8
		}
		if config.StreamTimeout <= 0 {
			config.StreamTimeout = 60 * time.Second
		}
		if config.PaddingMax < config.PaddingMin {
			config.PaddingMax = config.PaddingMin
		}
		if config.Headers == nil {
			config.Headers = make(map[string]string)
		}
	}

	// Determine protocol version
	version := config.Version
	if version == VersionMux {
		version = negotiateVersion(config)
	}

	t := &TrustTunnel{
		config:  config,
		version: version,
		closeCh: make(chan struct{}),
		streams: make(map[uint32]*ttStream),
	}

	// Setup HTTP client based on version
	switch version {
	case VersionH1:
		if err := t.setupH1(); err != nil {
			return nil, err
		}
	case VersionH2:
		if err := t.setupH2(); err != nil {
			return nil, err
		}
	case VersionH3:
		if err := t.setupH3(); err != nil {
			return nil, err
		}
	}

	// Start background tasks
	go t.keepaliveLoop()

	return t, nil
}

// negotiateVersion determines the best protocol version
func negotiateVersion(config *Config) ProtocolVersion {
	// Try H3 first (best performance)
	if config.Server != "" {
		if u, err := url.Parse(config.Server); err == nil {
			// Check if server supports HTTP/3
			if probeH3(u.Host) {
				return VersionH3
			}
		}
	}

	// Fall back to H2 (good performance, widely supported)
	if probeH2(config.Server) {
		return VersionH2
	}

	// Fall back to H1 (universal support)
	return VersionH1
}

// probeH3 probes for HTTP/3 support via QUIC ALPN handshake.
func probeH3(host string) bool {
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, host, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}, nil)
	if err != nil {
		return false
	}
	_ = conn.CloseWithError(0, "probe")
	return true
}

// probeH2 probes for HTTP/2 support via TLS ALPN negotiation.
func probeH2(serverURL string) bool {
	u, err := url.Parse(serverURL)
	if err != nil {
		return false
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	return conn.ConnectionState().NegotiatedProtocol == "h2"
}

// setupH1 configures HTTP/1.1 transport
func (t *TrustTunnel) setupH1() error {
	t.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   t.config.TLSConfig,
			ForceAttemptHTTP2: false,
		},
		Timeout: t.config.StreamTimeout,
	}
	return nil
}

// setupH2 configures HTTP/2 transport with TLS session ticket support
func (t *TrustTunnel) setupH2() error {
	tlsCfg := t.config.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	// Enable TLS session resumption via session tickets
	tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(32)

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		return err
	}

	t.httpClient = &http.Client{
		Transport: transport,
		Timeout:   t.config.StreamTimeout,
	}
	return nil
}

// setupH3 configures HTTP/3 transport with session resumption
func (t *TrustTunnel) setupH3() error {
	tlsCfg := t.config.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	// Enable TLS session cache for QUIC 0-RTT resumption
	tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(32)

	transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
	}

	t.httpClient = &http.Client{
		Transport: transport,
		Timeout:   t.config.StreamTimeout,
	}
	return nil
}

// OpenStream opens a new stream
func (t *TrustTunnel) OpenStream() (net.Conn, error) {
	if t.closed.Load() {
		return nil, fmt.Errorf("tunnel closed")
	}

	streamID := t.streamID.Add(1)
	stream := &ttStream{
		id:      streamID,
		tunnel:  t,
		txCh:    make(chan []byte, 64),
		rxCh:    make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}

	t.streamsMu.Lock()
	t.streams[streamID] = stream
	t.streamsMu.Unlock()

	t.streamsIn.Add(1)

	// Initiate HTTP request for this stream
	go t.initiateStream(stream)

	return stream, nil
}

// initiateStream initiates the HTTP connection for a stream
func (t *TrustTunnel) initiateStream(stream *ttStream) {
	u, err := url.Parse(t.config.Server)
	if err != nil {
		stream.Close()
		return
	}

	// Build request path with stream ID
	u.Path = "/tunnel/" + fmt.Sprintf("%d", stream.id)

	req, err := http.NewRequest("POST", u.String(), t.getRequestBody(stream))
	if err != nil {
		stream.Close()
		return
	}

	// Set headers
	req.Header.Set("User-Agent", t.config.UserAgent)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Stream-ID", fmt.Sprintf("%d", stream.id))
	req.Header.Set("X-Protocol-Version", string(t.version))

	// Add auth
	if t.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.config.Token)
	}

	// Add custom headers
	for k, v := range t.config.Headers {
		req.Header.Set(k, v)
	}

	// Add padding for obfuscation
	padding := t.generatePadding()
	if padding > 0 {
		req.Header.Set("X-Padding", fmt.Sprintf("%d", padding))
	}

	// Domain fronting
	if t.config.DomainFronting != "" {
		req.Host = t.config.DomainFronting
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		stream.Close()
		return
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		stream.Close()
		return
	}

	// Capture addresses from the underlying HTTP connection for net.Conn interface
	if u, parseErr := url.Parse(t.config.Server); parseErr == nil {
		stream.remoteAddr = &net.TCPAddr{IP: net.ParseIP(u.Hostname())}
	}

	// Read response body and feed to stream
	go t.readResponse(stream, resp.Body)
}

// getRequestBody returns the request body reader for a stream
func (t *TrustTunnel) getRequestBody(stream *ttStream) io.Reader {
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()

		// Write data from stream to pipe
		for {
			select {
			case <-stream.closeCh:
				return
			case data := <-stream.txCh:
				// Framing: [type(1)][len(4)][pad_len(2)][data][padding]
				padding := t.generatePadding()
				frame := make([]byte, 1+4+2+len(data)+padding)
				if len(data) == 0 {
					frame[0] = 0x02 // DPD ping
				} else {
					frame[0] = 0x01 // Data frame
				}
				binary.BigEndian.PutUint32(frame[1:5], uint32(len(data)))
				binary.BigEndian.PutUint16(frame[5:7], uint16(padding))
				copy(frame[7:], data)
				// Padding tail is zero-filled by make()
				if _, err := pw.Write(frame); err != nil {
					return
				}
				t.bytesOut.Add(uint64(len(frame)))
			}
		}
	}()

	return pr
}

// readResponse reads the HTTP response body
func (t *TrustTunnel) readResponse(stream *ttStream, body io.ReadCloser) {
	defer body.Close()
	defer stream.Close()

	reader := bufio.NewReader(body)

	for {
		// Read frame header: [type(1)][len(4)][pad_len(2)]
		header := make([]byte, 7)
		if _, err := io.ReadFull(reader, header); err != nil {
			return
		}

		frameType := header[0]
		length := binary.BigEndian.Uint32(header[1:5])
		padLen := int(binary.BigEndian.Uint16(header[5:7]))

		// Reject excessively large frames to prevent memory exhaustion attacks.
		const maxFrameSize = 16 << 20 // 16 MiB
		if length > maxFrameSize || padLen > 65535 {
			return
		}

		if length == 0 {
			if frameType == 0x02 {
				// DPD ping — respond with pong (empty data frame)
				select {
				case stream.txCh <- []byte{}:
				default:
				}
			}
			if padLen > 0 {
				if _, err := io.CopyN(io.Discard, reader, int64(padLen)); err != nil {
					return
				}
			}
			continue
		}

		data := make([]byte, length)
		if _, err := io.ReadFull(reader, data); err != nil {
			return
		}
		if padLen > 0 {
			if _, err := io.CopyN(io.Discard, reader, int64(padLen)); err != nil {
				return
			}
		}

		t.bytesIn.Add(uint64(length + 7 + uint32(padLen)))

		if frameType == 0x02 {
			continue // DPD, don't deliver to application
		}

		select {
		case stream.rxCh <- data:
		case <-stream.closeCh:
			return
		}
	}
}

// generatePadding generates random padding size
func (t *TrustTunnel) generatePadding() int {
	if t.config.PaddingMax <= t.config.PaddingMin {
		if t.config.PaddingMin < 0 {
			return 0
		}
		return t.config.PaddingMin
	}
	span := t.config.PaddingMax - t.config.PaddingMin + 1
	r, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return t.config.PaddingMin
	}
	return t.config.PaddingMin + int(r.Int64())
}

// keepaliveLoop sends periodic keepalives
func (t *TrustTunnel) keepaliveLoop() {
	ticker := time.NewTicker(t.config.RequestInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.closeCh:
			return
		case <-ticker.C:
			t.sendKeepalive()
		}
	}
}

// sendKeepalive sends a keepalive request
func (t *TrustTunnel) sendKeepalive() {
	// Implementation: send empty frame through active streams
	t.streamsMu.RLock()
	streams := make([]*ttStream, 0, len(t.streams))
	for _, s := range t.streams {
		streams = append(streams, s)
	}
	t.streamsMu.RUnlock()

	for _, s := range streams {
		// Send empty data as keepalive
		select {
		case s.txCh <- []byte{}:
		default:
		}
	}
}

// Close closes the TrustTunnel and all active streams.
// A brief drain period allows pending txCh data to be flushed before closing.
func (t *TrustTunnel) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}

	t.streamsMu.RLock()
	for _, s := range t.streams {
		s.drain(100 * time.Millisecond)
	}
	t.streamsMu.RUnlock()

	close(t.closeCh)

	if t.httpClient != nil {
		t.httpClient.CloseIdleConnections()
	}

	t.streamsMu.Lock()
	for _, s := range t.streams {
		s.Close()
	}
	t.streams = make(map[uint32]*ttStream)
	t.streamsMu.Unlock()

	return nil
}

// ttStream methods

func (s *ttStream) Read(p []byte) (n int, err error) {
	if s.closed.Load() {
		return 0, io.EOF
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	// Check buffered data first
	if s.readOffset < len(s.readBuf) {
		n = copy(p, s.readBuf[s.readOffset:])
		s.readOffset += n
		if s.readOffset >= len(s.readBuf) {
			s.readBuf = nil
			s.readOffset = 0
		}
		return n, nil
	}

	// Build deadline channel if set
	var deadlineCh <-chan time.Time
	if dl, ok := s.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return 0, fmt.Errorf("read deadline exceeded")
		}
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		deadlineCh = timer.C
	}

	// Read from channel
	select {
	case data := <-s.rxCh:
		n = copy(p, data)
		if n < len(data) {
			s.readBuf = data[n:]
			s.readOffset = 0
		}
		return n, nil
	case <-deadlineCh:
		return 0, fmt.Errorf("read deadline exceeded")
	case <-s.closeCh:
		return 0, fmt.Errorf("stream closed")
	}
}

func (s *ttStream) Write(p []byte) (n int, err error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("stream closed")
	}

	// Copy data to avoid modification
	data := make([]byte, len(p))
	copy(data, p)

	// Build deadline channel if set
	var deadlineCh <-chan time.Time
	if dl, ok := s.writeDeadline.Load().(time.Time); ok && !dl.IsZero() {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return 0, fmt.Errorf("write deadline exceeded")
		}
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		deadlineCh = timer.C
	}

	select {
	case s.txCh <- data:
		return len(p), nil
	case <-deadlineCh:
		return 0, fmt.Errorf("write deadline exceeded")
	case <-s.closeCh:
		return 0, fmt.Errorf("stream closed")
	}
}

func (s *ttStream) drain(timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		if len(s.txCh) == 0 {
			return
		}
		select {
		case <-timer.C:
			return
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func (s *ttStream) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(s.closeCh)

	s.tunnel.streamsMu.Lock()
	delete(s.tunnel.streams, s.id)
	s.tunnel.streamsMu.Unlock()

	return nil
}

func (s *ttStream) LocalAddr() net.Addr {
	if s.localAddr != nil {
		return s.localAddr
	}
	return &net.TCPAddr{}
}

func (s *ttStream) RemoteAddr() net.Addr {
	if s.remoteAddr != nil {
		return s.remoteAddr
	}
	return &net.TCPAddr{}
}

func (s *ttStream) SetDeadline(t time.Time) error {
	s.readDeadline.Store(t)
	s.writeDeadline.Store(t)
	return nil
}

func (s *ttStream) SetReadDeadline(t time.Time) error {
	s.readDeadline.Store(t)
	return nil
}

func (s *ttStream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Store(t)
	return nil
}

// GetStats returns tunnel statistics
func (t *TrustTunnel) GetStats() TTStats {
	t.streamsMu.RLock()
	streamCount := len(t.streams)
	t.streamsMu.RUnlock()

	return TTStats{
		BytesIn:      t.bytesIn.Load(),
		BytesOut:     t.bytesOut.Load(),
		Streams:      uint64(streamCount),
		StreamsTotal: t.streamsIn.Load(),
		Version:      string(t.version),
	}
}

// TTStats contains TrustTunnel statistics
type TTStats struct {
	BytesIn      uint64
	BytesOut     uint64
	Streams      uint64
	StreamsTotal uint64
	Version      string
}

// Dialer implements TrustTunnel dialer
type Dialer struct {
	config *Config
	smux   *smux.Config
}

// NewDialer creates a new TrustTunnel dialer
func NewDialer(config *Config, smuxCfg *smux.Config) *Dialer {
	return &Dialer{
		config: config,
		smux:   smuxCfg,
	}
}

// Dial connects to a TrustTunnel server and returns a smux session
func (d *Dialer) Dial(ctx context.Context) (*smux.Session, error) {
	// Create TrustTunnel connection
	tunnel, err := Dial(ctx, d.config)
	if err != nil {
		return nil, fmt.Errorf("trusttunnel dial: %w", err)
	}

	// Open the first stream which will be used for the smux session
	stream, err := tunnel.OpenStream()
	if err != nil {
		_ = tunnel.Close()
		return nil, fmt.Errorf("trusttunnel open stream: %w", err)
	}

	// Create smux session over the stream
	session, err := smux.Client(stream, d.smux)
	if err != nil {
		_ = stream.Close()
		_ = tunnel.Close()
		return nil, fmt.Errorf("smux client: %w", err)
	}

	return session, nil
}
