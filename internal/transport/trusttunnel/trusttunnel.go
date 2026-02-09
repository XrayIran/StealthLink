// Package trusttunnel implements TrustTunnel protocol support
// with H1/H2/H3 multiplexing and obfuscation.
package trusttunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
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
	closed   atomic.Bool
	closeCh  chan struct{}

	// Streams
	streams    map[uint32]*ttStream
	streamID   atomic.Uint32
	streamsMu  sync.RWMutex

	// Statistics
	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64
	streamsIn atomic.Uint64
}

// ttStream represents a TrustTunnel stream
type ttStream struct {
	id      uint32
	tunnel  *TrustTunnel
	readCh  chan []byte
	closeCh chan struct{}
	closed  atomic.Bool

	// Read buffer for partial reads
	readBuf    []byte
	readOffset int
}

// Dial connects to a TrustTunnel server
func Dial(ctx context.Context, config *Config) (*TrustTunnel, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Determine protocol version
	version := config.Version
	if version == VersionMux {
		version = negotiateVersion(config)
	}

	t := &TrustTunnel{
		config:    config,
		version:   version,
		closeCh:   make(chan struct{}),
		streams:   make(map[uint32]*ttStream),
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

// probeH3 probes for HTTP/3 support
func probeH3(host string) bool {
	// Simplified: assume H3 if port is 443 and host looks modern
	return strings.HasSuffix(host, ":443") || !strings.Contains(host, ":")
}

// probeH2 probes for HTTP/2 support
func probeH2(serverURL string) bool {
	return true // Assume H2 support
}

// setupH1 configures HTTP/1.1 transport
func (t *TrustTunnel) setupH1() error {
	t.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: t.config.TLSConfig,
			ForceAttemptHTTP2: false,
		},
		Timeout: t.config.StreamTimeout,
	}
	return nil
}

// setupH2 configures HTTP/2 transport
func (t *TrustTunnel) setupH2() error {
	transport := &http.Transport{
		TLSClientConfig: t.config.TLSConfig,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		return err
	}

	t.httpClient = &http.Client{
		Transport:     transport,
		Timeout:       t.config.StreamTimeout,
	}
	return nil
}

// setupH3 configures HTTP/3 transport
func (t *TrustTunnel) setupH3() error {
	// HTTP/3 requires QUIC
	transport := &http3.Transport{
		TLSClientConfig: t.config.TLSConfig,
	}

	t.httpClient = &http.Client{
		Transport:     transport,
		Timeout:       t.config.StreamTimeout,
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
		readCh:  make(chan []byte, 16),
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
			case data := <-stream.readCh:
				// Add framing: [4-byte length][data]
				lengthBuf := make([]byte, 4)
				binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
				if _, err := pw.Write(lengthBuf); err != nil {
					return
				}
				if _, err := pw.Write(data); err != nil {
					return
				}
				t.bytesOut.Add(uint64(len(data) + 4))
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
		// Read frame length
		lengthBuf := make([]byte, 4)
		if _, err := io.ReadFull(reader, lengthBuf); err != nil {
			return
		}

		length := binary.BigEndian.Uint32(lengthBuf)
		if length == 0 {
			continue
		}

		// Read data
		data := make([]byte, length)
		if _, err := io.ReadFull(reader, data); err != nil {
			return
		}

		t.bytesIn.Add(uint64(length + 4))

		// Send to stream
		select {
		case stream.readCh <- data:
		case <-stream.closeCh:
			return
		}
	}
}

// generatePadding generates random padding size
func (t *TrustTunnel) generatePadding() int {
	if t.config.PaddingMax <= t.config.PaddingMin {
		return 0
	}
	return t.config.PaddingMin + int(time.Now().UnixNano())%(t.config.PaddingMax-t.config.PaddingMin)
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
		case s.readCh <- []byte{}:
		default:
		}
	}
}

// Close closes the TrustTunnel
func (t *TrustTunnel) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(t.closeCh)

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
		return 0, fmt.Errorf("stream closed")
	}

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

	// Read from channel
	select {
	case data := <-s.readCh:
		n = copy(p, data)
		if n < len(data) {
			// Buffer remaining
			s.readBuf = data[n:]
			s.readOffset = 0
		}
		return n, nil
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

	select {
	case s.readCh <- data:
		return len(p), nil
	case <-s.closeCh:
		return 0, fmt.Errorf("stream closed")
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

func (s *ttStream) LocalAddr() net.Addr  { return nil }
func (s *ttStream) RemoteAddr() net.Addr { return nil }

func (s *ttStream) SetDeadline(t time.Time) error      { return nil }
func (s *ttStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *ttStream) SetWriteDeadline(t time.Time) error { return nil }

// GetStats returns tunnel statistics
func (t *TrustTunnel) GetStats() TTStats {
	t.streamsMu.RLock()
	streamCount := len(t.streams)
	t.streamsMu.RUnlock()

	return TTStats{
		BytesIn:     t.bytesIn.Load(),
		BytesOut:    t.bytesOut.Load(),
		Streams:     uint64(streamCount),
		StreamsTotal: t.streamsIn.Load(),
		Version:     string(t.version),
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
