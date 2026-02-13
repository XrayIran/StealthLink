package dtls

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
)

type FallbackState int

const (
	StateTCP FallbackState = iota
	StateDTLS
	StateTransitioning
)

type DTLSFallbackConfig struct {
	Enabled         bool
	TransitionAfter time.Duration
	DTLSPort        int
	Timeout         time.Duration
	MaxRetries      int
}

type DTLSFallback struct {
	config       DTLSFallbackConfig
	tcpConn      net.Conn
	dtlsConn     net.Conn
	state        atomic.Int32
	listener     net.Listener
	transitionAt time.Time
	sessionKey   []byte
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewDTLSFallback(cfg DTLSFallbackConfig) *DTLSFallback {
	if cfg.TransitionAfter == 0 {
		cfg.TransitionAfter = 30 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &DTLSFallback{
		config:     cfg,
		sessionKey: make([]byte, 32),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (f *DTLSFallback) Connect(ctx context.Context, addr string) (net.Conn, error) {
	var lastErr error

	for i := 0; i < f.config.MaxRetries; i++ {
		conn, err := f.tryConnect(ctx, addr)
		if err == nil {
			metrics.IncTransportSession("dtls_fallback")
			return conn, nil
		}
		lastErr = err

		if f.shouldTransition() {
			conn, err = f.transitionToDTLS(ctx, addr)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}

		time.Sleep(time.Second * time.Duration(i+1))
	}

	return nil, fmt.Errorf("connection failed after retries: %w", lastErr)
}

func (f *DTLSFallback) tryConnect(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: f.config.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	f.tcpConn = conn
	f.transitionAt = time.Now().Add(f.config.TransitionAfter)
	f.mu.Unlock()

	f.state.Store(int32(StateTCP))

	return &fallbackConn{
		fallback: f,
		Conn:     conn,
	}, nil
}

func (f *DTLSFallback) shouldTransition() bool {
	if !f.config.Enabled {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return time.Now().After(f.transitionAt)
}

func (f *DTLSFallback) transitionToDTLS(ctx context.Context, addr string) (net.Conn, error) {
	f.state.Store(int32(StateTransitioning))

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	dtlsAddr := fmt.Sprintf("%s:%d", host, f.config.DTLSPort)
	if f.config.DTLSPort == 0 {
		_, port, _ := net.SplitHostPort(addr)
		dtlsAddr = fmt.Sprintf("%s:%s", host, port)
	}

	dialer := &net.Dialer{
		Timeout: f.config.Timeout,
	}

	udpConn, err := dialer.DialContext(ctx, "udp", dtlsAddr)
	if err != nil {
		f.state.Store(int32(StateTCP))
		return nil, fmt.Errorf("udp dial: %w", err)
	}

	f.mu.Lock()
	f.dtlsConn = udpConn
	f.mu.Unlock()

	f.state.Store(int32(StateDTLS))

	if f.tcpConn != nil {
		go f.gracefulCloseTCP()
	}

	return &fallbackConn{
		fallback: f,
		Conn:     udpConn,
	}, nil
}

func (f *DTLSFallback) gracefulCloseTCP() {
	time.Sleep(5 * time.Second)
	f.mu.Lock()
	if f.tcpConn != nil {
		f.tcpConn.Close()
		f.tcpConn = nil
	}
	f.mu.Unlock()
}

func (f *DTLSFallback) Listen(addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	f.listener = listener
	f.state.Store(int32(StateTCP))

	return &fallbackListener{
		Listener: listener,
		fallback: f,
	}, nil
}

func (f *DTLSFallback) AcceptDTLS() (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", f.listener.Addr().String())
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (f *DTLSFallback) Close() error {
	f.cancel()
	f.mu.Lock()
	defer f.mu.Unlock()

	var err error
	if f.tcpConn != nil {
		if e := f.tcpConn.Close(); e != nil {
			err = e
		}
	}
	if f.dtlsConn != nil {
		if e := f.dtlsConn.Close(); e != nil && err == nil {
			err = e
		}
	}
	if f.listener != nil {
		if e := f.listener.Close(); e != nil && err == nil {
			err = e
		}
	}

	metrics.DecTransportSession("dtls_fallback")
	return err
}

type fallbackConn struct {
	net.Conn
	fallback *DTLSFallback
	closed   atomic.Bool
}

func (c *fallbackConn) Read(b []byte) (n int, err error) {
	state := c.fallback.state.Load()
	if state == int32(StateDTLS) {
		return c.readDTLS(b)
	}
	return c.Conn.Read(b)
}

func (c *fallbackConn) readDTLS(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil {
		return n, err
	}

	if len(b) < 13 {
		return n, nil
	}

	contentType := b[0]
	version := binary.BigEndian.Uint16(b[1:3])
	_ = version
	_ = contentType

	return n, nil
}

func (c *fallbackConn) Write(b []byte) (n int, err error) {
	state := c.fallback.state.Load()
	if state == int32(StateDTLS) {
		return c.writeDTLS(b)
	}
	return c.Conn.Write(b)
}

func (c *fallbackConn) writeDTLS(b []byte) (n int, err error) {
	packet := make([]byte, 13+len(b))
	packet[0] = 23
	binary.BigEndian.PutUint16(packet[1:3], 0xfefb)
	binary.BigEndian.PutUint16(packet[3:5], 0x0000)
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(b)))
	binary.BigEndian.PutUint16(packet[7:9], 0x0000)
	binary.BigEndian.PutUint16(packet[9:11], 0x0000)
	binary.BigEndian.PutUint16(packet[11:13], 0x0000)
	copy(packet[13:], b)

	return c.Conn.Write(packet)
}

func (c *fallbackConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	metrics.DecTransportSession("dtls_fallback")
	return c.Conn.Close()
}

type fallbackListener struct {
	net.Listener
	fallback *DTLSFallback
}

func (l *fallbackListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &fallbackConn{
		Conn:     conn,
		fallback: l.fallback,
	}, nil
}

type TransitionDetector struct {
	failureCount int
	successCount int
	lastCheck    time.Time
	threshold    int
	window       time.Duration
}

func NewTransitionDetector(threshold int, window time.Duration) *TransitionDetector {
	if threshold == 0 {
		threshold = 5
	}
	if window == 0 {
		window = 30 * time.Second
	}
	return &TransitionDetector{
		threshold: threshold,
		window:    window,
		lastCheck: time.Now(),
	}
}

func (d *TransitionDetector) RecordFailure() {
	d.failureCount++
	d.successCount = 0
}

func (d *TransitionDetector) RecordSuccess() {
	d.successCount++
	if d.successCount > 3 {
		d.failureCount = 0
	}
}

func (d *TransitionDetector) ShouldTransition() bool {
	now := time.Now()
	if now.Sub(d.lastCheck) > d.window {
		d.failureCount = 0
		d.lastCheck = now
	}
	return d.failureCount >= d.threshold
}
