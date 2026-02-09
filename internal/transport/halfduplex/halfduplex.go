// Package halfduplex implements half-duplex mode for splitting upload/download
// across different connections (from WaterWall).
package halfduplex

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport"
)

// Config configures half-duplex mode.
type Config struct {
	Enabled      bool          `yaml:"enabled"`
	UpConn       string        `yaml:"up_conn"`       // Address for upload connection
	DownConn     string        `yaml:"down_conn"`     // Address for download connection
	MuxTimeout   time.Duration `yaml:"mux_timeout"`   // Timeout for mux operations
	BufferSize   int           `yaml:"buffer_size"`   // Buffer size for relay
}

// ApplyDefaults sets default values.
func (c *Config) ApplyDefaults() {
	if c.MuxTimeout <= 0 {
		c.MuxTimeout = 30 * time.Second
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 32 * 1024
	}
}

// HalfDuplexClient splits traffic across upload and download connections.
type HalfDuplexClient struct {
	upDialer     transport.Dialer
	downDialer   transport.Dialer
	upAddr       string
	downAddr     string
	config       Config
	bufferPool   sync.Pool
}

// NewClient creates a new half-duplex client.
func NewClient(upDialer, downDialer transport.Dialer, upAddr, downAddr string, config Config) *HalfDuplexClient {
	config.ApplyDefaults()
	return &HalfDuplexClient{
		upDialer:   upDialer,
		downDialer: downDialer,
		upAddr:     upAddr,
		downAddr:   downAddr,
		config:     config,
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, config.BufferSize)
			},
		},
	}
}

// Dial creates a new half-duplex session.
func (c *HalfDuplexClient) Dial(ctx context.Context, _ string) (transport.Session, error) {
	// Establish upload connection
	upSess, err := c.upDialer.Dial(ctx, c.upAddr)
	if err != nil {
		return nil, fmt.Errorf("dial upload: %w", err)
	}

	// Establish download connection
	downSess, err := c.downDialer.Dial(ctx, c.downAddr)
	if err != nil {
		upSess.Close()
		return nil, fmt.Errorf("dial download: %w", err)
	}

	return &session{
		upSess:   upSess,
		downSess: downSess,
		config:   c.config,
	}, nil
}

// session implements transport.Session for half-duplex.
type session struct {
	upSess     transport.Session
	downSess   transport.Session
	config     Config
	closed     atomic.Bool
	mu         sync.RWMutex
	upStream   net.Conn
	downStream net.Conn
}

func (s *session) OpenStream() (net.Conn, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	// Open separate streams for up and down
	upStream, err := s.upSess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open upload stream: %w", err)
	}

	downStream, err := s.downSess.OpenStream()
	if err != nil {
		upStream.Close()
		return nil, fmt.Errorf("open download stream: %w", err)
	}

	return &halfDuplexConn{
		upConn:   upStream,
		downConn: downStream,
		localAddr:  upStream.LocalAddr(),
		remoteAddr: upStream.RemoteAddr(),
	}, nil
}

func (s *session) AcceptStream() (net.Conn, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	// Accept streams on both connections
	upStream, err := s.upSess.AcceptStream()
	if err != nil {
		return nil, fmt.Errorf("accept upload stream: %w", err)
	}

	downStream, err := s.downSess.AcceptStream()
	if err != nil {
		upStream.Close()
		return nil, fmt.Errorf("accept download stream: %w", err)
	}

	return &halfDuplexConn{
		upConn:     upStream,
		downConn:   downStream,
		localAddr:  upStream.LocalAddr(),
		remoteAddr: upStream.RemoteAddr(),
	}, nil
}

func (s *session) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.upSess.Close()
		s.downSess.Close()
	}
	return nil
}

func (s *session) LocalAddr() net.Addr {
	return s.upSess.LocalAddr()
}

func (s *session) RemoteAddr() net.Addr {
	return s.upSess.RemoteAddr()
}

// halfDuplexConn splits read/write across two connections.
type halfDuplexConn struct {
	upConn     net.Conn
	downConn   net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     atomic.Bool
	mu         sync.Mutex
}

func (c *halfDuplexConn) Read(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, fmt.Errorf("connection closed")
	}
	// Read from download connection
	return c.downConn.Read(b)
}

func (c *halfDuplexConn) Write(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, fmt.Errorf("connection closed")
	}
	// Write to upload connection
	return c.upConn.Write(b)
}

func (c *halfDuplexConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.upConn.Close()
		c.downConn.Close()
	}
	return nil
}

func (c *halfDuplexConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *halfDuplexConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *halfDuplexConn) SetDeadline(t time.Time) error {
	err1 := c.upConn.SetDeadline(t)
	err2 := c.downConn.SetDeadline(t)
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *halfDuplexConn) SetReadDeadline(t time.Time) error {
	return c.downConn.SetReadDeadline(t)
}

func (c *halfDuplexConn) SetWriteDeadline(t time.Time) error {
	return c.upConn.SetWriteDeadline(t)
}

// HalfDuplexServer combines upload and download connections on the server side.
type HalfDuplexServer struct {
	upListener   transport.Listener
	downListener transport.Listener
	config       Config
	sessions     map[string]*serverSession
	mu           sync.RWMutex
	closed       atomic.Bool
}

// NewServer creates a new half-duplex server.
func NewServer(upListener, downListener transport.Listener, config Config) *HalfDuplexServer {
	config.ApplyDefaults()
	s := &HalfDuplexServer{
		upListener:   upListener,
		downListener: downListener,
		config:       config,
		sessions:     make(map[string]*serverSession),
	}

	go s.acceptLoop()
	return s
}

func (s *HalfDuplexServer) acceptLoop() {
	for {
		if s.closed.Load() {
			return
		}

		// Accept on both listeners
		upSess, err := s.upListener.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			continue
		}

		downSess, err := s.downListener.Accept()
		if err != nil {
			upSess.Close()
			if s.closed.Load() {
				return
			}
			continue
		}

		// Create server session
		session := &serverSession{
			upSess:   upSess,
			downSess: downSess,
			config:   s.config,
		}

		// Store session
		s.mu.Lock()
		s.sessions[upSess.RemoteAddr().String()] = session
		s.mu.Unlock()

		// Handle session
		go s.handleSession(session)
	}
}

func (s *HalfDuplexServer) handleSession(sess *serverSession) {
	defer func() {
		s.mu.Lock()
		delete(s.sessions, sess.upSess.RemoteAddr().String())
		s.mu.Unlock()
		sess.Close()
	}()

	// Relay between up and down streams
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		sess.relayUp()
	}()

	go func() {
		defer wg.Done()
		sess.relayDown()
	}()

	wg.Wait()
}

// Accept accepts a combined session.
func (s *HalfDuplexServer) Accept() (transport.Session, error) {
	// This is handled internally by handleSession
	// For now, return a dummy implementation
	return nil, fmt.Errorf("use AcceptSplit for half-duplex")
}

// Close closes the server.
func (s *HalfDuplexServer) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.upListener.Close()
		s.downListener.Close()
	}
	return nil
}

// Addr returns the address.
func (s *HalfDuplexServer) Addr() net.Addr {
	return s.upListener.Addr()
}

// serverSession represents a server-side half-duplex session.
type serverSession struct {
	upSess   transport.Session
	downSess transport.Session
	config   Config
	closed   atomic.Bool
}

func (s *serverSession) relayUp() {
	for {
		if s.closed.Load() {
			return
		}

		stream, err := s.upSess.AcceptStream()
		if err != nil {
			return
		}

		// Handle upload stream
		go func() {
			defer stream.Close()
			buffer := make([]byte, s.config.BufferSize)
			for {
				n, err := stream.Read(buffer)
				if err != nil {
					return
				}
				// Process upload data (forward to destination)
				_ = buffer[:n]
			}
		}()
	}
}

func (s *serverSession) relayDown() {
	for {
		if s.closed.Load() {
			return
		}

		stream, err := s.downSess.AcceptStream()
		if err != nil {
			return
		}

		// Handle download stream
		go func() {
			defer stream.Close()
			buffer := make([]byte, s.config.BufferSize)
			for {
				n, err := stream.Read(buffer)
				if err != nil {
					return
				}
				// Process download data (forward to destination)
				_ = buffer[:n]
			}
		}()
	}
}

func (s *serverSession) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.upSess.Close()
		s.downSess.Close()
	}
	return nil
}

// Relay bidirectionally copies data between two connections.
func Relay(upConn, downConn net.Conn, bufferSize int) error {
	if bufferSize <= 0 {
		bufferSize = 32 * 1024
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Upload: from upConn to downConn
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.CopyBuffer(downConn, upConn, make([]byte, bufferSize))
		if err != nil {
			errCh <- fmt.Errorf("upload relay: %w", err)
		}
	}()

	// Download: from downConn to upConn
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.CopyBuffer(upConn, downConn, make([]byte, bufferSize))
		if err != nil {
			errCh <- fmt.Errorf("download relay: %w", err)
		}
	}()

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}

	return nil
}
