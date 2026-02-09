// Package dtls provides a DTLS-mode transport for StealthLink.
//
// This implementation focuses on operational stability and throughput:
// it uses UDP + encrypted KCP sessions + smux, exposed behind a DTLS-style
// configuration surface.
package dtls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"stealthlink/internal/transport"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

const (
	DTLSVersion12 = 0xfefd
	DTLSVersion13 = 0xfeff
)

// Config configures DTLS mode.
type Config struct {
	Version          uint16        `yaml:"version"`
	PSK              string        `yaml:"psk"`
	PSKIdentity      string        `yaml:"psk_identity"`
	MTU              int           `yaml:"mtu"`
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`
	Retransmit       bool          `yaml:"retransmit"`
	ReplayWindow     int           `yaml:"replay_window"`
}

func (c *Config) ApplyDefaults() {
	if c.Version == 0 {
		c.Version = DTLSVersion12
	}
	if c.MTU <= 0 {
		c.MTU = 1350
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = 10 * time.Second
	}
	if c.ReplayWindow <= 0 {
		c.ReplayWindow = 64
	}
}

type Dialer struct {
	cfg   *Config
	smux  *smux.Config
	guard string
	block kcp.BlockCrypt
}

func NewDialer(cfg *Config, smuxCfg *smux.Config, guard string) (*Dialer, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	cfg.ApplyDefaults()

	block, err := deriveBlock(cfg.PSK)
	if err != nil {
		return nil, err
	}

	return &Dialer{cfg: cfg, smux: smuxCfg, guard: guard, block: block}, nil
}

func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("dtls listen packet: %w", err)
	}

	conn, err := kcp.NewConn(addr, d.block, 0, 0, pc)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("dtls dial: %w", err)
	}

	applyTuning(conn, d.cfg)

	if err := transport.SendGuard(conn, d.guard); err != nil {
		_ = conn.Close()
		_ = pc.Close()
		return nil, fmt.Errorf("dtls guard send: %w", err)
	}

	sess, err := smux.Client(conn, d.smux)
	if err != nil {
		_ = conn.Close()
		_ = pc.Close()
		return nil, fmt.Errorf("dtls smux client: %w", err)
	}

	return &session{conn: conn, sess: sess, pc: pc}, nil
}

type Listener struct {
	ln    *kcp.Listener
	pc    net.PacketConn
	cfg   *Config
	smux  *smux.Config
	guard string
}

func Listen(addr string, cfg *Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	cfg.ApplyDefaults()

	block, err := deriveBlock(cfg.PSK)
	if err != nil {
		return nil, err
	}

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dtls listen packet: %w", err)
	}

	ln, err := kcp.ServeConn(block, 0, 0, pc)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("dtls serve: %w", err)
	}

	return &Listener{ln: ln, pc: pc, cfg: cfg, smux: smuxCfg, guard: guard}, nil
}

func (l *Listener) Accept() (transport.Session, error) {
	conn, err := l.ln.AcceptKCP()
	if err != nil {
		return nil, err
	}

	applyTuning(conn, l.cfg)

	if l.cfg.HandshakeTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(l.cfg.HandshakeTimeout))
	}
	if err := transport.RecvGuard(conn, l.guard); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dtls guard recv: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	sess, err := smux.Server(conn, l.smux)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dtls smux server: %w", err)
	}

	return &session{conn: conn, sess: sess}, nil
}

func (l *Listener) Close() error {
	if l.ln != nil {
		_ = l.ln.Close()
	}
	if l.pc != nil {
		return l.pc.Close()
	}
	return nil
}

func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

type session struct {
	conn *kcp.UDPSession
	sess *smux.Session
	pc   net.PacketConn
}

func (s *session) OpenStream() (net.Conn, error)   { return s.sess.OpenStream() }
func (s *session) AcceptStream() (net.Conn, error) { return s.sess.AcceptStream() }
func (s *session) LocalAddr() net.Addr             { return s.conn.LocalAddr() }
func (s *session) RemoteAddr() net.Addr            { return s.conn.RemoteAddr() }

func (s *session) Close() error {
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

func deriveBlock(psk string) (kcp.BlockCrypt, error) {
	psk = strings.TrimSpace(psk)
	if psk == "" {
		return nil, fmt.Errorf("transport.dtls.psk is required")
	}

	raw := []byte(psk)
	if dec, err := hex.DecodeString(psk); err == nil && len(dec) > 0 {
		raw = dec
	}

	sum := sha256.Sum256(raw)
	// AES-GCM in kcp-go requires 16-byte key.
	return kcp.NewAESGCMCrypt(sum[:16])
}

func applyTuning(conn *kcp.UDPSession, cfg *Config) {
	if conn == nil || cfg == nil {
		return
	}
	if cfg.MTU > 0 {
		conn.SetMtu(cfg.MTU)
	}
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetACKNoDelay(true)

	if cfg.Retransmit {
		conn.SetNoDelay(1, 10, 2, 1)
	} else {
		conn.SetNoDelay(0, 30, 0, 1)
	}
}
