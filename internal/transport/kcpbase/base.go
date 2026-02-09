// Package kcpbase provides a unified KCP transport base that consolidates
// KCP-based protocols including standard KCP, DTLS, AmneziaWG, and brutal CC.
package kcpbase

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// Mode represents the KCP operation mode
type Mode string

const (
	// ModeStandard uses standard KCP congestion control
	ModeStandard Mode = "standard"
	// ModeBrutal uses brutal congestion control (Hysteria2-style)
	ModeBrutal Mode = "brutal"
	// ModeAWG uses AmneziaWG mode with junk injection
	ModeAWG Mode = "awg"
	// ModeDTLS uses DTLS-compatible KCP settings
	ModeDTLS Mode = "dtls"
)

// BlockCrypt represents the block encryption type
type BlockCrypt string

const (
	BlockNone   BlockCrypt = "none"
	BlockAES    BlockCrypt = "aes"
	BlockAES128 BlockCrypt = "aes-128"
	BlockBlowfish BlockCrypt = "blowfish"
	BlockCast5  BlockCrypt = "cast5"
	Block3DES   BlockCrypt = "3des"
	BlockTEA    BlockCrypt = "tea"
	BlockXTEA   BlockCrypt = "xtea"
	BlockSalsa20 BlockCrypt = "salsa20"
)

// Config holds the unified KCP configuration
type Config struct {
	// Mode selects the KCP operation mode
	Mode Mode

	// Block encryption
	Block BlockCrypt
	Key   string

	// Forward Error Correction
	DataShards   int
	ParityShards int
	AutoTuneFEC  bool

	// DSCP marking
	DSCP int

	// Mode-specific configurations
	Brutal BrutalConfig
	AWG    AWGConfig
	DTLS   DTLSConfig
}

// BrutalConfig holds brutal congestion control settings
type BrutalConfig struct {
	Enabled    bool
	Bandwidth  int // Mbps
	PacingMode string // adaptive, aggressive, conservative
}

// AWGConfig holds AmneziaWG-specific settings
type AWGConfig struct {
	JunkEnabled   bool
	JunkInterval  time.Duration
	JunkMinSize   int
	JunkMaxSize   int
	PacketObfuscate bool
}

// DTLSConfig holds DTLS-specific settings
type DTLSConfig struct {
	MTU           int
	HandshakeTimeout time.Duration
	FlightInterval time.Duration
}

// DefaultConfig returns default KCP configuration
func DefaultConfig() *Config {
	return &Config{
		Mode:         ModeStandard,
		Block:        BlockNone,
		DataShards:   10,
		ParityShards: 3,
		AutoTuneFEC:  true,
		DSCP:         0,
		Brutal: BrutalConfig{
			Enabled:    false,
			Bandwidth:  100,
			PacingMode: "adaptive",
		},
		AWG: AWGConfig{
			JunkEnabled:     false,
			JunkInterval:    5 * time.Second,
			JunkMinSize:     64,
			JunkMaxSize:     1024,
			PacketObfuscate: true,
		},
		DTLS: DTLSConfig{
			MTU:              1350,
			HandshakeTimeout: 10 * time.Second,
			FlightInterval:   100 * time.Millisecond,
		},
	}
}

// Dialer creates KCP connections with unified configuration
type Dialer struct {
	cfg  *Config
	smux *smux.Config
}

// NewDialer creates a new KCP dialer
func NewDialer(cfg *Config, smuxCfg *smux.Config) *Dialer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Dialer{
		cfg:  cfg,
		smux: smuxCfg,
	}
}

// Dial connects to a KCP server
func (d *Dialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	// Resolve address
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve addr: %w", err)
	}

	// Create block crypt if needed
	block, err := d.createBlockCrypt()
	if err != nil {
		return nil, fmt.Errorf("create block crypt: %w", err)
	}

	// Create KCP connection
	conn, err := kcp.DialWithOptions(raddr.String(), block, d.cfg.DataShards, d.cfg.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("kcp dial: %w", err)
	}

	// Apply mode-specific settings
	if err := d.applyModeSettings(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Set DSCP if specified
	if d.cfg.DSCP > 0 {
		conn.SetDSCP(d.cfg.DSCP)
	}

	return conn, nil
}

// Listener wraps a KCP listener with unified configuration
type Listener struct {
	ln   net.Listener
	cfg  *Config
	smux *smux.Config
}

// Listen creates a KCP listener
func Listen(addr string, cfg *Config, smuxCfg *smux.Config) (*Listener, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Resolve address
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve addr: %w", err)
	}

	// Create block crypt if needed
	var block kcp.BlockCrypt
	if cfg.Key != "" {
		block, err = createBlockCrypt(cfg.Block, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("create block crypt: %w", err)
		}
	}

	// Create KCP listener
	ln, err := kcp.ListenWithOptions(laddr.String(), block, cfg.DataShards, cfg.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("kcp listen: %w", err)
	}

	return &Listener{
		ln:   ln,
		cfg:  cfg,
		smux: smuxCfg,
	}, nil
}

// Accept accepts a KCP connection
func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}

	// Apply mode-specific settings
	if kcpConn, ok := conn.(*kcp.UDPSession); ok {
		if err := l.applyModeSettings(kcpConn); err != nil {
			conn.Close()
			return nil, err
		}

		if l.cfg.DSCP > 0 {
			kcpConn.SetDSCP(l.cfg.DSCP)
		}
	}

	return conn, nil
}

// Close closes the listener
func (l *Listener) Close() error {
	return l.ln.Close()
}

// Addr returns the listener address
func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}

// createBlockCrypt creates a block crypt from config
func (d *Dialer) createBlockCrypt() (kcp.BlockCrypt, error) {
	if d.cfg.Block == BlockNone || d.cfg.Key == "" {
		return nil, nil
	}
	return createBlockCrypt(d.cfg.Block, d.cfg.Key)
}

// createBlockCrypt creates a block crypt
func createBlockCrypt(block BlockCrypt, key string) (kcp.BlockCrypt, error) {
	// Derive key using SHA-256
	hash := sha256.Sum256([]byte(key))

	switch block {
	case BlockAES:
		return kcp.NewAESBlockCrypt(hash[:32])
	case BlockAES128:
		return kcp.NewAESBlockCrypt(hash[:16])
	case BlockBlowfish:
		return kcp.NewBlowfishBlockCrypt(hash[:])
	case BlockCast5:
		return kcp.NewCast5BlockCrypt(hash[:16])
	case Block3DES:
		return kcp.NewTripleDESBlockCrypt(hash[:24])
	case BlockTEA:
		return kcp.NewTEABlockCrypt(hash[:16])
	case BlockXTEA:
		return kcp.NewXTEABlockCrypt(hash[:16])
	case BlockSalsa20:
		return kcp.NewSalsa20BlockCrypt(hash[:32])
	default:
		return nil, fmt.Errorf("unsupported block crypt: %s", block)
	}
}

// applyModeSettings applies mode-specific KCP settings
func (d *Dialer) applyModeSettings(conn *kcp.UDPSession) error {
	switch d.cfg.Mode {
	case ModeStandard:
		return d.applyStandardMode(conn)
	case ModeBrutal:
		return d.applyBrutalMode(conn)
	case ModeAWG:
		return d.applyAWGMode(conn)
	case ModeDTLS:
		return d.applyDTLSMode(conn)
	default:
		return fmt.Errorf("unknown mode: %s", d.cfg.Mode)
	}
}

// applyModeSettings applies mode-specific KCP settings (listener)
func (l *Listener) applyModeSettings(conn *kcp.UDPSession) error {
	switch l.cfg.Mode {
	case ModeStandard:
		return applyStandardModeSettings(conn)
	case ModeBrutal:
		return applyBrutalModeSettings(conn, l.cfg.Brutal)
	case ModeAWG:
		return applyAWGModeSettings(conn, l.cfg.AWG)
	case ModeDTLS:
		return applyDTLSModeSettings(conn, l.cfg.DTLS)
	default:
		return fmt.Errorf("unknown mode: %s", l.cfg.Mode)
	}
}

// applyStandardMode applies standard KCP settings
func (d *Dialer) applyStandardMode(conn *kcp.UDPSession) error {
	return applyStandardModeSettings(conn)
}

func applyStandardModeSettings(conn *kcp.UDPSession) error {
	// Standard KCP settings optimized for general use
	conn.SetWindowSize(128, 128)
	conn.SetNoDelay(0, 40, 0, 0)
	conn.SetStreamMode(true)
	return nil
}

// applyBrutalMode applies brutal congestion control settings
func (d *Dialer) applyBrutalMode(conn *kcp.UDPSession) error {
	return applyBrutalModeSettings(conn, d.cfg.Brutal)
}

func applyBrutalModeSettings(conn *kcp.UDPSession, cfg BrutalConfig) error {
	// Brutal mode: aggressive settings for high bandwidth
	conn.SetWindowSize(1024, 1024)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetStreamMode(true)

	// Calculate bandwidth in bytes per second
	bandwidthBps := cfg.Bandwidth * 125000 // Mbps to Bps

	// Apply pacing based on mode
	switch cfg.PacingMode {
	case "aggressive":
		conn.SetWriteDelay(false)
	case "conservative":
		conn.SetWriteDelay(true)
	default: // adaptive
		conn.SetWriteDelay(bandwidthBps > 50*125000)
	}

	return nil
}

// applyAWGMode applies AmneziaWG-specific settings
func (d *Dialer) applyAWGMode(conn *kcp.UDPSession) error {
	return applyAWGModeSettings(conn, d.cfg.AWG)
}

func applyAWGModeSettings(conn *kcp.UDPSession, cfg AWGConfig) error {
	// AWG mode: settings optimized for obfuscation
	conn.SetWindowSize(256, 256)
	conn.SetNoDelay(1, 20, 2, 1)
	conn.SetStreamMode(true)
	return nil
}

// applyDTLSMode applies DTLS-compatible settings
func (d *Dialer) applyDTLSMode(conn *kcp.UDPSession) error {
	return applyDTLSModeSettings(conn, d.cfg.DTLS)
}

func applyDTLSModeSettings(conn *kcp.UDPSession, cfg DTLSConfig) error {
	// DTLS mode: settings optimized for DTLS handshake simulation
	conn.SetWindowSize(64, 64)
	conn.SetNoDelay(1, 10, 0, 0)
	conn.SetStreamMode(false) // Message mode for DTLS compatibility
	conn.SetMtu(cfg.MTU)
	return nil
}

// KCPConn wraps a KCP connection with additional features
type KCPConn struct {
	*kcp.UDPSession
	mode Mode
	cfg  *Config
}

// NewKCPConn wraps a KCP session
func NewKCPConn(sess *kcp.UDPSession, mode Mode, cfg *Config) *KCPConn {
	return &KCPConn{
		UDPSession: sess,
		mode:       mode,
		cfg:        cfg,
	}
}

// Mode returns the KCP mode
func (c *KCPConn) Mode() Mode {
	return c.mode
}

// IsBrutal returns true if using brutal congestion control
func (c *KCPConn) IsBrutal() bool {
	return c.mode == ModeBrutal
}

// IsAWG returns true if using AWG mode
func (c *KCPConn) IsAWG() bool {
	return c.mode == ModeAWG
}

// IsDTLS returns true if using DTLS mode
func (c *KCPConn) IsDTLS() bool {
	return c.mode == ModeDTLS
}
