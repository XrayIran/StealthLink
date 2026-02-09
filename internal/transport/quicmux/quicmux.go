// Package quicmux implements a QUIC-based transport with stream multiplexing.
package quicmux

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"stealthlink/internal/transport"

	quic "github.com/quic-go/quic-go"
	"github.com/xtaci/smux"
)

const defaultALPN = "h3"

// Config holds QUIC transport configuration.
type Config struct {
	Obfs struct {
		Type     string // "salamander" or ""
		Password string // Obfuscation password
	}
	Masquerade struct {
		Type   string // "http" or ""
		Listen string // Masquerade listen address
	}
	Padding struct {
		Min int // Minimum padding bytes
		Max int // Maximum padding bytes
	}
	Enable0RTT            bool
	HandshakeTimeout      time.Duration
	MaxIdleTimeout        time.Duration
	KeepAlivePeriod       time.Duration
	MaxIncomingStreams    int64
	MaxIncomingUniStreams int64
}

// ApplyDefaults fills missing QUIC values with throughput-safe defaults.
func (c *Config) ApplyDefaults() {
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = 8 * time.Second
	}
	if c.MaxIdleTimeout <= 0 {
		c.MaxIdleTimeout = 45 * time.Second
	}
	if c.KeepAlivePeriod <= 0 {
		c.KeepAlivePeriod = 15 * time.Second
	}
	if c.MaxIncomingStreams == 0 {
		c.MaxIncomingStreams = 1024
	}
	if c.MaxIncomingUniStreams == 0 {
		c.MaxIncomingUniStreams = 128
	}
}

func cloneConfig(cfg *Config) *Config {
	if cfg == nil {
		cfg = &Config{}
	}
	cp := *cfg
	cp.ApplyDefaults()
	return &cp
}

func (c *Config) quicConfig(server bool) *quic.Config {
	qc := &quic.Config{
		HandshakeIdleTimeout: c.HandshakeTimeout,
		MaxIdleTimeout:       c.MaxIdleTimeout,
		KeepAlivePeriod:      c.KeepAlivePeriod,
		MaxIncomingStreams:   c.MaxIncomingStreams,
	}
	if server {
		qc.MaxIncomingUniStreams = c.MaxIncomingUniStreams
		qc.Allow0RTT = c.Enable0RTT
	}
	return qc
}

// Dialer implements transport.Dialer for QUIC.
type Dialer struct {
	Config    *Config
	TLSConfig *tls.Config
	Smux      *smux.Config
	Guard     string
}

// Listener implements transport.Listener for QUIC.
type Listener struct {
	ln     *quic.Listener
	config *Config
	smux   *smux.Config
	guard  string
}

// NewDialer creates a new QUIC dialer.
func NewDialer(cfg *Config, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string) *Dialer {
	return &Dialer{
		Config:    cloneConfig(cfg),
		TLSConfig: tlsCfg,
		Smux:      smuxCfg,
		Guard:     guard,
	}
}

// Listen creates a QUIC listener.
func Listen(addr string, cfg *Config, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	if tlsCfg == nil {
		return nil, fmt.Errorf("quic listener requires tls config")
	}

	cfg = cloneConfig(cfg)
	tlsConf := serverTLSConfig(tlsCfg)
	ln, err := quic.ListenAddr(addr, tlsConf, cfg.quicConfig(true))
	if err != nil {
		return nil, fmt.Errorf("quic listen: %w", err)
	}

	return &Listener{ln: ln, config: cfg, smux: smuxCfg, guard: guard}, nil
}

// Accept accepts a QUIC connection.
func (l *Listener) Accept() (transport.Session, error) {
	conn, err := l.ln.Accept(context.Background())
	if err != nil {
		return nil, err
	}

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(0, "accept")
		return nil, err
	}
	wrapped := &quicStreamConn{stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}

	if l.config.HandshakeTimeout > 0 {
		_ = wrapped.SetDeadline(time.Now().Add(l.config.HandshakeTimeout))
	}
	if err := transport.RecvGuard(wrapped, l.guard); err != nil {
		_ = stream.Close()
		_ = conn.CloseWithError(0, "guard")
		return nil, fmt.Errorf("quic guard recv: %w", err)
	}
	_ = wrapped.SetDeadline(time.Time{})

	sess, err := smux.Server(wrapped, l.smux)
	if err != nil {
		_ = stream.Close()
		_ = conn.CloseWithError(0, "smux")
		return nil, fmt.Errorf("quic smux server: %w", err)
	}
	return &session{conn: conn, sess: sess}, nil
}

// Close closes the listener.
func (l *Listener) Close() error {
	if l.ln == nil {
		return nil
	}
	return l.ln.Close()
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr {
	if l.ln == nil {
		return nil
	}
	return l.ln.Addr()
}

// Dial connects to a QUIC server.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	if d.TLSConfig == nil {
		return nil, fmt.Errorf("quic dialer requires tls config")
	}

	cfg := cloneConfig(d.Config)
	tlsConf := clientTLSConfig(d.TLSConfig, addr)

	var (
		conn *quic.Conn
		err  error
	)
	if cfg.Enable0RTT {
		conn, err = quic.DialAddrEarly(ctx, addr, tlsConf, cfg.quicConfig(false))
	} else {
		conn, err = quic.DialAddr(ctx, addr, tlsConf, cfg.quicConfig(false))
	}
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "open")
		return nil, fmt.Errorf("quic open stream: %w", err)
	}
	wrapped := &quicStreamConn{stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}

	if cfg.HandshakeTimeout > 0 {
		_ = wrapped.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	}
	if err := transport.SendGuard(wrapped, d.Guard); err != nil {
		_ = stream.Close()
		_ = conn.CloseWithError(0, "guard")
		return nil, fmt.Errorf("quic guard send: %w", err)
	}
	_ = wrapped.SetDeadline(time.Time{})

	sess, err := smux.Client(wrapped, d.Smux)
	if err != nil {
		_ = stream.Close()
		_ = conn.CloseWithError(0, "smux")
		return nil, fmt.Errorf("quic smux client: %w", err)
	}

	return &session{conn: conn, sess: sess}, nil
}

// session wraps a QUIC connection and smux session.
type session struct {
	conn *quic.Conn
	sess *smux.Session
}

func (s *session) OpenStream() (net.Conn, error) {
	return s.sess.OpenStream()
}

func (s *session) AcceptStream() (net.Conn, error) {
	return s.sess.AcceptStream()
}

func (s *session) Close() error {
	if s.sess != nil {
		_ = s.sess.Close()
	}
	if s.conn != nil {
		return s.conn.CloseWithError(0, "")
	}
	return nil
}

func (s *session) LocalAddr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *session) RemoteAddr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.RemoteAddr()
}

type quicStreamConn struct {
	stream *quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *quicStreamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *quicStreamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *quicStreamConn) Close() error {
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
	return c.stream.Close()
}
func (c *quicStreamConn) LocalAddr() net.Addr                { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *quicStreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *quicStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

func serverTLSConfig(base *tls.Config) *tls.Config {
	tlsConf := base.Clone()
	tlsConf.NextProtos = ensureALPN(tlsConf.NextProtos)
	return tlsConf
}

func clientTLSConfig(base *tls.Config, addr string) *tls.Config {
	tlsConf := base.Clone()
	tlsConf.NextProtos = ensureALPN(tlsConf.NextProtos)
	if tlsConf.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			tlsConf.ServerName = host
		}
	}
	return tlsConf
}

func ensureALPN(existing []string) []string {
	for _, p := range existing {
		if p == defaultALPN {
			return existing
		}
	}
	out := make([]string, 0, len(existing)+1)
	out = append(out, existing...)
	out = append(out, defaultALPN)
	return out
}
