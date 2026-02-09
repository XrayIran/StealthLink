package rawtcp

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/kcputil"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// Dialer implements transport.Dialer for raw TCP (pcap) + KCP.
type Dialer struct {
	Raw  config.RawTCPConfig
	KCP  config.KCPConfig
	Smux *smux.Config
}

// Listener implements transport.Listener for raw TCP (pcap) + KCP.
type Listener struct {
	ln       *kcp.Listener
	pc       *PacketConn
	raw      config.RawTCPConfig
	kcp      config.KCPConfig
	smux     *smux.Config
	sessions atomic.Int32 // Active session count
	streams  atomic.Int32 // Active stream count across all sessions
	closed   atomic.Bool  // Whether listener is closed
}

// NewDialer creates a raw TCP dialer.
func NewDialer(raw config.RawTCPConfig, kcpCfg config.KCPConfig, smuxCfg *smux.Config) *Dialer {
	return &Dialer{Raw: raw, KCP: kcpCfg, Smux: smuxCfg}
}

// Listen creates a raw TCP listener bound to the configured interface/addr.
func Listen(raw config.RawTCPConfig, kcpCfg config.KCPConfig, smuxCfg *smux.Config) (*Listener, error) {
	pc, err := newPacketConn(context.Background(), raw)
	if err != nil {
		return nil, err
	}
	block, err := kcputil.NewBlock(kcpCfg.Block, kcpCfg.Key)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	dShard, pShard := kcpCfg.DShard, kcpCfg.PShard
	pcWrapped := transport.NewPacketGuardConn(pc, transport.PacketGuardConfig{
		Enabled: kcpCfg.PacketGuard,
		Magic:   kcpCfg.PacketGuardMagic,
		Window:  timeSeconds(kcpCfg.PacketGuardWindow),
		Skew:    kcpCfg.PacketGuardSkew,
		Key:     kcpCfg.Key,
	})

	ln, err := kcp.ServeConn(block, dShard, pShard, pcWrapped)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}

	// Apply KCP-specific buffer settings to smux config if configured
	appliedSmuxCfg := smuxCfg
	if kcpCfg.SmuxBuf > 0 || kcpCfg.StreamBuf > 0 {
		appliedSmuxCfg = copySmuxConfig(smuxCfg)
		if kcpCfg.SmuxBuf > 0 {
			appliedSmuxCfg.MaxReceiveBuffer = kcpCfg.SmuxBuf
		}
		if kcpCfg.StreamBuf > 0 {
			appliedSmuxCfg.MaxStreamBuffer = kcpCfg.StreamBuf
		}
	}

	return &Listener{ln: ln, pc: pc, raw: raw, kcp: kcpCfg, smux: appliedSmuxCfg}, nil
}

func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := newPacketConn(ctx, d.Raw)
	if err != nil {
		return nil, err
	}
	block, err := kcputil.NewBlock(d.KCP.Block, d.KCP.Key)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	dShard, pShard := d.KCP.DShard, d.KCP.PShard
	pcWrapped := transport.NewPacketGuardConn(pc, transport.PacketGuardConfig{
		Enabled: d.KCP.PacketGuard,
		Magic:   d.KCP.PacketGuardMagic,
		Window:  timeSeconds(d.KCP.PacketGuardWindow),
		Skew:    d.KCP.PacketGuardSkew,
		Key:     d.KCP.Key,
	})
	conn, err := kcp.NewConn(raddr.String(), block, dShard, pShard, pcWrapped)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	kcputil.Apply(conn, d.KCP)
	if err := transport.SendGuard(conn, d.KCP.Guard); err != nil {
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
	return &session{conn: conn, sess: sess, pc: pc}, nil
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
		if l.kcp.MaxSessions > 0 {
			current := l.sessions.Load()
			if current >= int32(l.kcp.MaxSessions) {
				_ = conn.Close()
				continue // Try to accept next connection
			}
		}

		kcputil.Apply(conn, l.kcp)
		if len(l.raw.TCP.RemoteParsed()) > 0 {
			l.pc.SetClientTCPF(conn.RemoteAddr(), l.raw.TCP.RemoteParsed())
		}
		if err := transport.RecvGuard(conn, l.kcp.Guard); err != nil {
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

type session struct {
	conn        net.Conn
	sess        *smux.Session
	pc          net.PacketConn
	listener    *Listener // Reference to listener for session counting
	streamCount atomic.Int32 // Per-session stream count
	closed      atomic.Bool
}

func (s *session) OpenStream() (net.Conn, error) {
	// Check max streams per session limit
	if s.listener != nil && s.listener.kcp.MaxStreamsPerSession > 0 {
		current := s.streamCount.Load()
		if current >= int32(s.listener.kcp.MaxStreamsPerSession) {
			return nil, fmt.Errorf("max streams per session limit reached")
		}
	}
	// Check max streams total limit
	if s.listener != nil && s.listener.kcp.MaxStreamsTotal > 0 {
		current := s.listener.streams.Load()
		if current >= int32(s.listener.kcp.MaxStreamsTotal) {
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
	if s.listener != nil && s.listener.kcp.MaxStreamsPerSession > 0 {
		current := s.streamCount.Load()
		if current >= int32(s.listener.kcp.MaxStreamsPerSession) {
			return nil, fmt.Errorf("max streams per session limit reached")
		}
	}
	// Check max streams total limit
	if s.listener != nil && s.listener.kcp.MaxStreamsTotal > 0 {
		current := s.listener.streams.Load()
		if current >= int32(s.listener.kcp.MaxStreamsTotal) {
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

func timeSeconds(v int) time.Duration {
	if v <= 0 {
		return 0
	}
	return time.Duration(v) * time.Second
}
