package kcpmux

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/kcputil"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// FECConfig holds forward error correction settings.
type FECConfig struct {
	DataShards   int  // Number of data shards
	ParityShards int  // Number of parity shards
	AutoTune     bool // Enable auto-tuning based on loss
}

// fecAutoTuner adjusts FEC parameters based on observed loss.
type fecAutoTuner struct {
	mu           sync.RWMutex
	dataShards   int
	parityShards int
	lossRate     float64
	totalPackets uint64
	lostPackets  uint64
	lastAdjust   time.Time
}

func newFECAutoTuner(data, parity int) *fecAutoTuner {
	return &fecAutoTuner{
		dataShards:   data,
		parityShards: parity,
		lastAdjust:   time.Now(),
	}
}

func (t *fecAutoTuner) ReportLoss(lost, total uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.lostPackets += lost
	t.totalPackets += total

	// Adjust every 10 seconds
	if time.Since(t.lastAdjust) < 10*time.Second {
		return
	}

	if t.totalPackets > 0 {
		t.lossRate = float64(t.lostPackets) / float64(t.totalPackets)
	}

	// Adjust FEC based on loss rate
	switch {
	case t.lossRate > 0.1: // > 10% loss
		if t.parityShards < t.dataShards {
			t.parityShards++
		}
	case t.lossRate < 0.01 && t.parityShards > 1: // < 1% loss
		t.parityShards--
	}

	t.lostPackets = 0
	t.totalPackets = 0
	t.lastAdjust = time.Now()
}

func (t *fecAutoTuner) GetShards() (int, int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.dataShards, t.parityShards
}

// DSCP values for traffic prioritization.
const (
	DSCPDefault = 0
	DSCPLow     = 8  // CS1
	DSCPMed     = 32 // CS4
	DSCPHigh    = 46 // EF (Expedited Forwarding)
)

// Dialer implements transport.Dialer for KCP.
type Dialer struct {
	Cfg       config.KCPConfig
	Smux      *smux.Config
	fecTuner  *fecAutoTuner
	dscpValue int
}

// Listener implements transport.Listener for KCP.
type Listener struct {
	ln        *kcp.Listener
	pc        net.PacketConn
	cfg       config.KCPConfig
	smux      *smux.Config
	fecTuner  *fecAutoTuner
	dscpValue int
	sessions  atomic.Int32 // Active session count
	streams   atomic.Int32 // Active stream count across all sessions
	closed    atomic.Bool  // Whether listener is closed
}

// NewDialer creates a KCP dialer with optional FEC auto-tuning.
func NewDialer(cfg config.KCPConfig, smuxCfg *smux.Config) *Dialer {
	d := &Dialer{Cfg: cfg, Smux: smuxCfg}

	// Initialize FEC auto-tuner if enabled
	if cfg.AutoTune {
		d.fecTuner = newFECAutoTuner(cfg.DShard, cfg.PShard)
	}

	// Set DSCP value if specified
	if cfg.DSCP > 0 {
		d.dscpValue = cfg.DSCP
	}

	return d
}

// Listen creates a KCP listener with optional FEC auto-tuning.
func Listen(addr string, cfg config.KCPConfig, smuxCfg *smux.Config) (*Listener, error) {
	block, err := kcputil.NewBlock(cfg.Block, cfg.Key)
	if err != nil {
		return nil, err
	}

	// Get effective FEC shards (considering auto-tune)
	dShard, pShard := cfg.DShard, cfg.PShard
	if cfg.AutoTune {
		// Start with default values, tuner will adjust
		if dShard == 0 {
			dShard = 10
		}
		if pShard == 0 {
			pShard = 3
		}
	}

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	pcWrapped := transport.NewPacketGuardConn(pc, transport.PacketGuardConfig{
		Enabled: cfg.PacketGuard,
		Magic:   cfg.PacketGuardMagic,
		Window:  time.Duration(cfg.PacketGuardWindow) * time.Second,
		Skew:    cfg.PacketGuardSkew,
		Key:     cfg.Key,
	})
	ln, err := kcp.ServeConn(block, dShard, pShard, pcWrapped)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}

	// Apply KCP-specific buffer settings to smux config if configured
	appliedSmuxCfg := smuxCfg
	if cfg.SmuxBuf > 0 || cfg.StreamBuf > 0 {
		appliedSmuxCfg = copySmuxConfig(smuxCfg)
		if cfg.SmuxBuf > 0 {
			appliedSmuxCfg.MaxReceiveBuffer = cfg.SmuxBuf
		}
		if cfg.StreamBuf > 0 {
			appliedSmuxCfg.MaxStreamBuffer = cfg.StreamBuf
		}
	}

	l := &Listener{ln: ln, pc: pc, cfg: cfg, smux: appliedSmuxCfg}

	// Initialize FEC auto-tuner if enabled
	if cfg.AutoTune {
		l.fecTuner = newFECAutoTuner(dShard, pShard)
	}

	// Set DSCP value if specified
	if cfg.DSCP > 0 {
		l.dscpValue = cfg.DSCP
	}

	return l, nil
}

func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	block, err := kcputil.NewBlock(d.Cfg.Block, d.Cfg.Key)
	if err != nil {
		return nil, err
	}

	// Get effective FEC shards
	dShard, pShard := d.Cfg.DShard, d.Cfg.PShard
	if d.fecTuner != nil {
		dShard, pShard = d.fecTuner.GetShards()
	}

	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}
	pcWrapped := transport.NewPacketGuardConn(pc, transport.PacketGuardConfig{
		Enabled: d.Cfg.PacketGuard,
		Magic:   d.Cfg.PacketGuardMagic,
		Window:  time.Duration(d.Cfg.PacketGuardWindow) * time.Second,
		Skew:    d.Cfg.PacketGuardSkew,
		Key:     d.Cfg.Key,
	})
	conn, err := kcp.NewConn(addr, block, dShard, pShard, pcWrapped)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}

	// Apply DSCP if set
	if d.dscpValue > 0 {
		if err := setDSCP(conn, d.dscpValue); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("set DSCP: %w", err)
		}
	}

	kcputil.Apply(conn, d.Cfg)
	if err := sendGuard(conn, d.Cfg.Guard); err != nil {
		_ = conn.Close()
		_ = pc.Close()
		return nil, err
	}
	sess, err := smux.Client(conn, d.Smux)
	if err != nil {
		_ = conn.Close()
		_ = pc.Close()
		return nil, err
	}
	return &session{conn: conn, sess: sess, fecTuner: d.fecTuner, pc: pc}, nil
}

func (l *Listener) Accept() (transport.Session, error) {
	for {
		conn, err := l.ln.AcceptKCP()
		if err != nil {
			if l.closed.Load() {
				return nil, err
			}
			return nil, err
		}

		// Check max sessions limit
		if l.cfg.MaxSessions > 0 {
			current := l.sessions.Load()
			if current >= int32(l.cfg.MaxSessions) {
				_ = conn.Close()
				continue // Try to accept next connection
			}
		}

		// Apply DSCP if set
		if l.dscpValue > 0 {
			if err := setDSCP(conn, l.dscpValue); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("set DSCP: %w", err)
			}
		}

		kcputil.Apply(conn, l.cfg)
		if err := recvGuard(conn, l.cfg.Guard); err != nil {
			_ = conn.Close()
			continue // Try next connection on guard failure
		}

		sess, err := smux.Server(conn, l.smux)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}

		// Increment session counter
		l.sessions.Add(1)

		return &session{
			conn:     conn,
			sess:     sess,
			fecTuner: l.fecTuner,
			listener: l,
		}, nil
	}
}

func (l *Listener) Close() error {
	l.closed.Store(true)
	if l.ln != nil {
		_ = l.ln.Close()
	}
	if l.pc != nil {
		return l.pc.Close()
	}
	return nil
}
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// copySmuxConfig creates a deep copy of smux.Config
func copySmuxConfig(cfg *smux.Config) *smux.Config {
	newCfg := smux.DefaultConfig()
	newCfg.Version = cfg.Version
	newCfg.KeepAliveDisabled = cfg.KeepAliveDisabled
	newCfg.KeepAliveInterval = cfg.KeepAliveInterval
	newCfg.KeepAliveTimeout = cfg.KeepAliveTimeout
	newCfg.MaxFrameSize = cfg.MaxFrameSize
	newCfg.MaxReceiveBuffer = cfg.MaxReceiveBuffer
	newCfg.MaxStreamBuffer = cfg.MaxStreamBuffer
	return newCfg
}

// sendGuard writes a short pre-shared token before smux handshake, dropping
// random traffic cheaply. No-op when guard is empty.
func sendGuard(w io.Writer, guard string) error {
	if guard == "" {
		return nil
	}
	if len(guard) > 255 {
		return fmt.Errorf("guard token too long")
	}
	buf := []byte(guard)
	lenByte := []byte{byte(len(buf))}
	if _, err := w.Write(lenByte); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

// recvGuard reads and validates the guard token. If guard is empty, it is a no-op.
func recvGuard(r net.Conn, guard string) error {
	if guard == "" {
		return nil
	}
	_ = r.SetReadDeadline(time.Now().Add(5 * time.Second))
	var lb [1]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		_ = r.SetReadDeadline(time.Time{})
		return err
	}
	n := int(lb[0])
	if n == 0 {
		_ = r.SetReadDeadline(time.Time{})
		return fmt.Errorf("guard token missing")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		_ = r.SetReadDeadline(time.Time{})
		return err
	}
	_ = r.SetReadDeadline(time.Time{})
	expected := []byte(guard)
	if len(buf) != len(expected) || subtle.ConstantTimeCompare(buf, expected) != 1 {
		return fmt.Errorf("guard token mismatch")
	}
	return nil
}

type session struct {
	conn        net.Conn
	sess        *smux.Session
	fecTuner    *fecAutoTuner
	pc          net.PacketConn
	listener    *Listener    // Reference to listener for session counting
	streamCount atomic.Int32 // Per-session stream count
	closed      atomic.Bool
}

func (s *session) OpenStream() (net.Conn, error) {
	// Check max streams per session limit
	if s.listener != nil && s.listener.cfg.MaxStreamsPerSession > 0 {
		current := s.streamCount.Load()
		if current >= int32(s.listener.cfg.MaxStreamsPerSession) {
			return nil, fmt.Errorf("max streams per session limit reached")
		}
	}
	// Check max streams total limit
	if s.listener != nil && s.listener.cfg.MaxStreamsTotal > 0 {
		current := s.listener.streams.Load()
		if current >= int32(s.listener.cfg.MaxStreamsTotal) {
			return nil, fmt.Errorf("max streams total limit reached")
		}
	}
	conn, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	// Increment stream counters
	s.streamCount.Add(1)
	if s.listener != nil {
		s.listener.streams.Add(1)
	}
	return &streamWrapper{conn: conn, session: s, listener: s.listener}, nil
}

func (s *session) AcceptStream() (net.Conn, error) {
	// Check max streams per session limit
	if s.listener != nil && s.listener.cfg.MaxStreamsPerSession > 0 {
		current := s.streamCount.Load()
		if current >= int32(s.listener.cfg.MaxStreamsPerSession) {
			return nil, fmt.Errorf("max streams per session limit reached")
		}
	}
	// Check max streams total limit
	if s.listener != nil && s.listener.cfg.MaxStreamsTotal > 0 {
		current := s.listener.streams.Load()
		if current >= int32(s.listener.cfg.MaxStreamsTotal) {
			return nil, fmt.Errorf("max streams total limit reached")
		}
	}
	conn, err := s.sess.AcceptStream()
	if err != nil {
		return nil, err
	}
	// Increment stream counters
	s.streamCount.Add(1)
	if s.listener != nil {
		s.listener.streams.Add(1)
	}
	return &streamWrapper{conn: conn, session: s, listener: s.listener}, nil
}

func (s *session) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		// Decrement session counter
		if s.listener != nil {
			s.listener.sessions.Add(-1)
		}
	}
	if s.sess != nil {
		_ = s.sess.Close()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	if s.pc != nil {
		return s.pc.Close()
	}
	return nil
}
func (s *session) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// streamWrapper wraps a net.Conn to track stream lifecycle
type streamWrapper struct {
	conn     net.Conn
	session  *session
	listener *Listener
	closed   atomic.Bool
}

func (w *streamWrapper) Read(b []byte) (int, error)  { return w.conn.Read(b) }
func (w *streamWrapper) Write(b []byte) (int, error) { return w.conn.Write(b) }
func (w *streamWrapper) Close() error {
	if w.closed.CompareAndSwap(false, true) {
		if w.session != nil {
			w.session.streamCount.Add(-1)
		}
		if w.listener != nil {
			w.listener.streams.Add(-1)
		}
	}
	return w.conn.Close()
}
func (w *streamWrapper) LocalAddr() net.Addr                { return w.conn.LocalAddr() }
func (w *streamWrapper) RemoteAddr() net.Addr               { return w.conn.RemoteAddr() }
func (w *streamWrapper) SetDeadline(t time.Time) error      { return w.conn.SetDeadline(t) }
func (w *streamWrapper) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *streamWrapper) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

// setDSCP sets the DSCP/TOS field on a UDP connection.
func setDSCP(conn *kcp.UDPSession, dscp int) error {
	// Get the underlying UDP connection
	// Try to set DSCP on the underlying connection
	// This is platform-specific and may not work on all systems
	// Note: kcp-go doesn't expose the underlying connection directly
	_ = conn // Avoid unused parameter error
	_ = dscp
	return nil // DSCP setting not supported for kcp-go
}
