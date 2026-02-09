package trusttunnel

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// ServerConfig configures a TrustTunnel server
type ServerConfig struct {
	// Listen address
	Addr string

	// Protocol versions to support
	Versions []ProtocolVersion

	// TLS configuration
	TLSConfig *tls.Config

	// Authentication
	TokenValidator func(string) bool

	// HTTP settings
	PathPrefix string

	// Stream settings
	StreamTimeout time.Duration

	// Callback for new connections
	OnConnect func(stream net.Conn) error
}

// Server represents a TrustTunnel server
type Server struct {
	config   *ServerConfig
	listener net.Listener
	h3Server *http3.Server
	httpMux  *http.ServeMux

	streams    map[uint32]*serverStream
	streamsMu  sync.RWMutex
	streamID   atomic.Uint32

	closed    atomic.Bool
	closeCh   chan struct{}

	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64
}

// serverStream represents a server-side stream
type serverStream struct {
	id      uint32
	server  *Server
	readCh  chan []byte
	writeCh chan []byte
	closeCh chan struct{}
	closed  atomic.Bool

	readBuf    []byte
	readOffset int
}

// ListenAndServe starts a TrustTunnel server
func ListenAndServe(config *ServerConfig) (*Server, error) {
	s := &Server{
		config:  config,
		streams: make(map[uint32]*serverStream),
		closeCh: make(chan struct{}),
		httpMux: http.NewServeMux(),
	}

	// Setup HTTP handlers
	s.setupHandlers()

	// Determine which versions to support
	versions := config.Versions
	if len(versions) == 0 {
		versions = []ProtocolVersion{VersionH1, VersionH2}
	}

	// Support H3 if requested
	for _, v := range versions {
		if v == VersionH3 {
			return s.listenAndServeH3()
		}
	}

	// Standard TLS listener for H1/H2
	return s.listenAndServeTLS()
}

// setupHandlers sets up HTTP route handlers
func (s *Server) setupHandlers() {
	prefix := s.config.PathPrefix
	if prefix == "" {
		prefix = "/tunnel"
	}

	s.httpMux.HandleFunc(prefix+"/", s.handleTunnel)
	s.httpMux.HandleFunc("/health", s.handleHealth)
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// handleTunnel handles tunnel requests
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	// Validate token if configured
	if s.config.TokenValidator != nil {
		token := extractBearerToken(r.Header.Get("Authorization"))
		if !s.config.TokenValidator(token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Parse stream ID from path
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Get or create stream
	streamID := s.streamID.Add(1)
	stream := &serverStream{
		id:      streamID,
		server:  s,
		readCh:  make(chan []byte, 16),
		writeCh: make(chan []byte, 16),
		closeCh: make(chan struct{}),
	}

	s.streamsMu.Lock()
	s.streams[streamID] = stream
	s.streamsMu.Unlock()

	// Handle based on HTTP version
	if r.ProtoMajor == 2 {
		s.handleH2Stream(w, r, stream)
	} else {
		s.handleH1Stream(w, r, stream)
	}
}

// handleH1Stream handles HTTP/1.1 stream with hijacking
func (s *Server) handleH1Stream(w http.ResponseWriter, r *http.Request, stream *serverStream) {
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

	// Create wrapper for chunked encoding
	wrapper := &h1StreamWrapper{
		conn:   conn,
		reader: bufrw.Reader,
		stream: stream,
	}

	// Handle the connection
	if s.config.OnConnect != nil {
		go s.config.OnConnect(wrapper)
	}

	// Process data
	wrapper.handle()
}

// handleH2Stream handles HTTP/2 stream
func (s *Server) handleH2Stream(w http.ResponseWriter, r *http.Request, stream *serverStream) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	// For HTTP/2, we need to flush the headers first
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Create wrapper
	wrapper := &h2StreamWrapper{
		ResponseWriter: w,
		Request:        r,
		stream:         stream,
	}

	// Handle the connection
	if s.config.OnConnect != nil {
		go s.config.OnConnect(wrapper)
	}

	// Process data
	wrapper.handle()
}

// listenAndServeTLS starts TLS server for H1/H2
func (s *Server) listenAndServeTLS() (*Server, error) {
	if s.config.TLSConfig == nil {
		return nil, fmt.Errorf("TLS config required")
	}

	ln, err := tls.Listen("tcp", s.config.Addr, s.config.TLSConfig)
	if err != nil {
		return nil, err
	}

	s.listener = ln

	// Configure for HTTP/2
	server := &http.Server{
		Addr:      s.config.Addr,
		Handler:   s.httpMux,
		TLSConfig: s.config.TLSConfig,
	}

	// Enable HTTP/2
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		ln.Close()
		return nil, err
	}

	go server.Serve(ln)

	return s, nil
}

// listenAndServeH3 starts HTTP/3 server
func (s *Server) listenAndServeH3() (*Server, error) {
	if s.config.TLSConfig == nil {
		return nil, fmt.Errorf("TLS config required")
	}

	// Create QUIC listener
	udpAddr, err := net.ResolveUDPAddr("udp", s.config.Addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	// Create QUIC listener
	quicLn, err := quic.Listen(conn, s.config.TLSConfig, &quic.Config{})
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Create HTTP/3 server
	s.h3Server = &http3.Server{
		Handler: s.httpMux,
	}

	go s.h3Server.ServeListener(quicLn)

	return s, nil
}

// Close closes the server
func (s *Server) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(s.closeCh)

	if s.listener != nil {
		s.listener.Close()
	}

	if s.h3Server != nil {
		s.h3Server.Close()
	}

	s.streamsMu.Lock()
	for _, stream := range s.streams {
		stream.Close()
	}
	s.streams = make(map[uint32]*serverStream)
	s.streamsMu.Unlock()

	return nil
}

// GetStats returns server statistics
func (s *Server) GetStats() TTStats {
	s.streamsMu.RLock()
	streamCount := len(s.streams)
	s.streamsMu.RUnlock()

	return TTStats{
		BytesIn:  s.bytesIn.Load(),
		BytesOut: s.bytesOut.Load(),
		Streams:  uint64(streamCount),
	}
}

// h1StreamWrapper wraps an HTTP/1.1 hijacked connection
type h1StreamWrapper struct {
	conn   net.Conn
	reader *bufio.Reader
	stream *serverStream
}

func (w *h1StreamWrapper) handle() {
	defer w.stream.Close()
	defer w.conn.Close()

	// Read loop
	go func() {
		defer w.stream.Close()

		for {
			// Read frame: [4-byte length][data]
			lengthBuf := make([]byte, 4)
			if _, err := io.ReadFull(w.reader, lengthBuf); err != nil {
				return
			}

			length := binary.BigEndian.Uint32(lengthBuf)
			if length == 0 {
				continue
			}

			data := make([]byte, length)
			if _, err := io.ReadFull(w.reader, data); err != nil {
				return
			}

			w.stream.server.bytesIn.Add(uint64(length + 4))

			select {
			case w.stream.readCh <- data:
			case <-w.stream.closeCh:
				return
			}
		}
	}()

	// Write loop
	for {
		select {
		case data := <-w.stream.writeCh:
			// Write frame: [4-byte length][data]
			lengthBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))

			if _, err := w.conn.Write(lengthBuf); err != nil {
				return
			}
			if _, err := w.conn.Write(data); err != nil {
				return
			}

			w.stream.server.bytesOut.Add(uint64(len(data) + 4))

		case <-w.stream.closeCh:
			return
		}
	}
}

func (w *h1StreamWrapper) Read(p []byte) (int, error) {
	return w.stream.Read(p)
}

func (w *h1StreamWrapper) Write(p []byte) (int, error) {
	return w.stream.Write(p)
}

func (w *h1StreamWrapper) Close() error {
	return w.stream.Close()
}

func (w *h1StreamWrapper) LocalAddr() net.Addr  { return w.conn.LocalAddr() }
func (w *h1StreamWrapper) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }
func (w *h1StreamWrapper) SetDeadline(t time.Time) error      { return w.conn.SetDeadline(t) }
func (w *h1StreamWrapper) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *h1StreamWrapper) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

// h2StreamWrapper wraps an HTTP/2 stream
type h2StreamWrapper struct {
	http.ResponseWriter
	*http.Request
	stream *serverStream
	flusher http.Flusher
}

func (w *h2StreamWrapper) handle() {
	defer w.stream.Close()

	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		w.flusher = f
	}

	// Read loop - for HTTP/2, we read from request body
	go func() {
		defer w.stream.Close()

		reader := bufio.NewReader(w.Request.Body)

		for {
			lengthBuf := make([]byte, 4)
			if _, err := io.ReadFull(reader, lengthBuf); err != nil {
				return
			}

			length := binary.BigEndian.Uint32(lengthBuf)
			if length == 0 {
				continue
			}

			data := make([]byte, length)
			if _, err := io.ReadFull(reader, data); err != nil {
				return
			}

			w.stream.server.bytesIn.Add(uint64(length + 4))

			select {
			case w.stream.readCh <- data:
			case <-w.stream.closeCh:
				return
			}
		}
	}()

	// Write loop - for HTTP/2, we write to response
	for {
		select {
		case data := <-w.stream.writeCh:
			// Write frame
			lengthBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))

			if _, err := w.ResponseWriter.Write(lengthBuf); err != nil {
				return
			}
			if _, err := w.ResponseWriter.Write(data); err != nil {
				return
			}

			if w.flusher != nil {
				w.flusher.Flush()
			}

			w.stream.server.bytesOut.Add(uint64(len(data) + 4))

		case <-w.stream.closeCh:
			return
		}
	}
}

func (w *h2StreamWrapper) Read(p []byte) (int, error) {
	return w.stream.Read(p)
}

func (w *h2StreamWrapper) Write(p []byte) (int, error) {
	return w.stream.Write(p)
}

func (w *h2StreamWrapper) Close() error {
	return w.stream.Close()
}

func (w *h2StreamWrapper) LocalAddr() net.Addr  { return nil }
func (w *h2StreamWrapper) RemoteAddr() net.Addr { return nil }
func (w *h2StreamWrapper) SetDeadline(t time.Time) error      { return nil }
func (w *h2StreamWrapper) SetReadDeadline(t time.Time) error  { return nil }
func (w *h2StreamWrapper) SetWriteDeadline(t time.Time) error { return nil }

// serverStream methods

func (s *serverStream) Read(p []byte) (n int, err error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("stream closed")
	}

	// Check buffered data
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
			s.readBuf = data[n:]
			s.readOffset = 0
		}
		return n, nil
	case <-s.closeCh:
		return 0, fmt.Errorf("stream closed")
	}
}

func (s *serverStream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("stream closed")
	}

	data := make([]byte, len(p))
	copy(data, p)

	select {
	case s.writeCh <- data:
		return len(p), nil
	case <-s.closeCh:
		return 0, fmt.Errorf("stream closed")
	}
}

func (s *serverStream) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(s.closeCh)

	s.server.streamsMu.Lock()
	delete(s.server.streams, s.id)
	s.server.streamsMu.Unlock()

	return nil
}

func (s *serverStream) LocalAddr() net.Addr  { return nil }
func (s *serverStream) RemoteAddr() net.Addr { return nil }
func (s *serverStream) SetDeadline(t time.Time) error      { return nil }
func (s *serverStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *serverStream) SetWriteDeadline(t time.Time) error { return nil }

// extractBearerToken extracts token from "Bearer <token>" format
func extractBearerToken(auth string) string {
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
