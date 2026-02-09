// Package awg implements an AmneziaWG-style transport profile.
//
// This implementation uses a keyed KCP session core for reliability while
// exposing AWG-style configuration fields (keys, peer endpoint, junk params).
//
// Features:
//   - Junk packet injection (Jc, Jmin, Jmax)
//   - Advanced timing obfuscation
//   - Packet size randomization
//   - SNI obfuscation
//   - Custom magic headers (H1-H4)
package awg

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/kcpmux"
	"stealthlink/internal/transport/wireguard"

	"github.com/xtaci/smux"
)

const (
	AWGv1   = 1
	AWGv1_5 = 2
	AWGv2   = 3
)

type Config struct {
	PrivateKey  string
	PublicKey   string
	Peers       []PeerConfig
	ProtocolVer int

	Jc           int
	Jmin         int
	Jmax         int
	JunkInterval time.Duration

	S1 int
	S2 int
	S3 int
	S4 int

	H1 uint32
	H2 uint32
	H3 uint32
	H4 uint32

	I1 bool
	I2 bool
	I3 bool
	I4 int
	I5 int

	PortHopping struct {
		Enabled   bool
		PortRange []int
		Interval  time.Duration
	}

	MaxPacketSize int
	MinPacketSize int
}

func (c *Config) ApplyDefaults() {
	if c.ProtocolVer == 0 {
		c.ProtocolVer = AWGv2
	}
	if c.JunkInterval <= 0 {
		c.JunkInterval = 5 * time.Second
	}
	if c.MaxPacketSize <= 0 {
		c.MaxPacketSize = 1500
	}
	if c.MinPacketSize <= 0 {
		c.MinPacketSize = 32
	}
}

type PeerConfig struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

type Dialer struct {
	cfg     *Config
	smuxCfg *smux.Config
}

type Listener struct {
	inner transport.Listener
}

func NewDialer(cfg *Config, smuxCfg *smux.Config, guard string) (*Dialer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("awg config is nil")
	}
	cfg.ApplyDefaults()
	if _, err := decodeKey(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	if _, err := decodeKey(cfg.PublicKey); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	return &Dialer{cfg: cfg, smuxCfg: smuxCfg}, nil
}

func Listen(addr string, cfg *Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	if cfg == nil {
		return nil, fmt.Errorf("awg config is nil")
	}
	cfg.ApplyDefaults()
	if _, err := decodeKey(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	if _, err := decodeKey(cfg.PublicKey); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	kcfg := toKCPConfig(cfg)
	ln, err := kcpmux.Listen(addr, kcfg, smuxCfg)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln}, nil
}

func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	endpoint := addr
	if endpoint == "" && len(d.cfg.Peers) > 0 {
		endpoint = d.cfg.Peers[0].Endpoint
	}
	if endpoint == "" {
		return nil, fmt.Errorf("missing AWG endpoint")
	}

	kcfg := toKCPConfig(d.cfg)
	kd := kcpmux.NewDialer(kcfg, d.smuxCfg)
	return kd.Dial(ctx, endpoint)
}

func (l *Listener) Accept() (transport.Session, error) { return l.inner.Accept() }
func (l *Listener) Close() error                        { return l.inner.Close() }
func (l *Listener) Addr() net.Addr                      { return l.inner.Addr() }

func GenerateUniqueParams() (*Config, error) {
	cfg := &Config{ProtocolVer: AWGv2}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	cfg.PrivateKey = base64.StdEncoding.EncodeToString(buf)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	cfg.PublicKey = base64.StdEncoding.EncodeToString(buf)
	cfg.Jc = 10
	cfg.Jmin = 50
	cfg.Jmax = 1000
	cfg.JunkInterval = 5 * time.Second
	cfg.MinPacketSize = 32
	cfg.MaxPacketSize = 1500
	return cfg, nil
}

func toKCPConfig(cfg *Config) config.KCPConfig {
	keyMaterial := cfg.PrivateKey + ":" + cfg.PublicKey
	if len(cfg.Peers) > 0 {
		keyMaterial += ":" + cfg.Peers[0].PublicKey + ":" + cfg.Peers[0].PresharedKey
	}
	sum := sha256.Sum256([]byte(keyMaterial))
	kcpKey := base64.StdEncoding.EncodeToString(sum[:])

	out := config.KCPConfig{
		Block:        "aes",
		Key:          kcpKey,
		Mode:         "fast2",
		MTU:          cfg.MaxPacketSize - 50,
		SndWnd:       1024,
		RcvWnd:       1024,
		NoDelay:      1,
		Interval:     20,
		Resend:       2,
		NoCongestion: 1,
		AckNoDelay:   true,
		DShard:       10,
		PShard:       3,
	}
	if out.MTU < 1200 {
		out.MTU = 1200
	}
	if out.MTU > 1500 {
		out.MTU = 1500
	}
	return out
}

func decodeKey(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty key")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(b))
	}
	return b, nil
}

// AWGConn wraps a net.Conn with AmneziaWG obfuscation
type AWGConn struct {
	net.Conn
	config *Config

	junkInjector   *wireguard.JunkInjector
	timingObf      *wireguard.TimingObfuscator
	sizeRandomizer *wireguard.SizeRandomizer
	sniObfuscator  *wireguard.SNIObfuscator

	writeMu sync.Mutex
	readMu  sync.Mutex
}

// NewAWGConn wraps an existing connection with AWG obfuscation
func NewAWGConn(conn net.Conn, cfg *Config) (*AWGConn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("AWG config is nil")
	}
	cfg.ApplyDefaults()

	// Create junk config from AWG config
	junkCfg := &wireguard.JunkConfig{
		Enabled:      cfg.Jc > 0,
		Jc:           cfg.Jc,
		Jmin:         cfg.Jmin,
		Jmax:         cfg.Jmax,
		JunkInterval: cfg.JunkInterval,
		S1:           cfg.S1,
		S2:           cfg.S2,
		S3:           cfg.S3,
		S4:           cfg.S4,
		H1:           cfg.H1,
		H2:           cfg.H2,
		H3:           cfg.H3,
		H4:           cfg.H4,
	}
	junkCfg.ApplyDefaults()

	awgConn := &AWGConn{
		Conn:         conn,
		config:       cfg,
		junkInjector: wireguard.NewJunkInjector(junkCfg),
	}

	// Initialize size randomizer
	if cfg.MinPacketSize > 0 && cfg.MaxPacketSize > cfg.MinPacketSize {
		awgConn.sizeRandomizer = wireguard.NewSizeRandomizer(
			cfg.MinPacketSize,
			cfg.MaxPacketSize,
			"gaussian",
		)
	}

	// Initialize SNI obfuscator
	if cfg.I1 {
		awgConn.sniObfuscator = wireguard.NewSNIObfuscator(nil)
	}

	// Start timing obfuscation if enabled
	if junkCfg.Enabled && cfg.JunkInterval > 0 {
		awgConn.timingObf = wireguard.NewTimingObfuscator(junkCfg, cfg.JunkInterval)
		awgConn.timingObf.Start(func(junk []byte) error {
			_, err := conn.Write(junk)
			return err
		})
	}

	return awgConn, nil
}

// Read reads data from the connection with deobfuscation
func (c *AWGConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	n, err := c.Conn.Read(p)
	if err != nil {
		return n, err
	}

	// Try to deobfuscate transport packet
	if c.config.S4 > 0 && n > 4 {
		data, deobfErr := c.junkInjector.DeobfuscatePacket(
			p[:n],
			wireguard.PacketTypeTransport,
			n-c.config.S4-4,
		)
		if deobfErr == nil && len(data) > 0 && len(data) <= len(p) {
			copy(p, data)
			return len(data), nil
		}
	}

	return n, nil
}

// Write writes data to the connection with obfuscation
func (c *AWGConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Obfuscate transport packet
	data := c.junkInjector.ObfuscateTransportPacket(p)

	// Apply size randomization
	if c.sizeRandomizer != nil {
		data = c.sizeRandomizer.PadToSize(data)
	}

	_, err := c.Conn.Write(data)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

// Close closes the connection
func (c *AWGConn) Close() error {
	if c.timingObf != nil {
		c.timingObf.Stop()
	}
	return c.Conn.Close()
}

// LocalAddr returns the local address
func (c *AWGConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr returns the remote address
func (c *AWGConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// SetDeadline sets the deadline
func (c *AWGConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (c *AWGConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (c *AWGConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// Ensure AWGConn implements net.Conn
var _ net.Conn = (*AWGConn)(nil)

// AWGProfile generates an AWG profile configuration
func AWGProfile(jc, jmin, jmax int) *Config {
	cfg := &Config{
		ProtocolVer:   AWGv2,
		Jc:            jc,
		Jmin:          jmin,
		Jmax:          jmax,
		JunkInterval:  5 * time.Second,
		MinPacketSize: 32,
		MaxPacketSize: 1500,
	}

	// Generate random keys
	buf := make([]byte, 32)
	rand.Read(buf)
	cfg.PrivateKey = base64.StdEncoding.EncodeToString(buf)
	rand.Read(buf)
	cfg.PublicKey = base64.StdEncoding.EncodeToString(buf)

	return cfg
}
