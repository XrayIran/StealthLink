package kcputil

import (
	"crypto/sha256"
	"fmt"

	"stealthlink/internal/config"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

// ModePreset defines KCP tuning presets.
type ModePreset struct {
	NoDelay      int
	Interval     int
	Resend       int
	NoCongestion int
	Description  string
}

// Preset modes adapted from kcptun and kcp-go.
// These control the trade-off between latency and throughput.
var Modes = map[string]ModePreset{
	// normal: Conservative mode, suitable for stable networks
	// Lower CPU usage, good for long-lived connections
	"normal": {NoDelay: 0, Interval: 40, Resend: 2, NoCongestion: 1, Description: "Conservative - good for stable networks"},

	// fast: Balanced mode, default for most use cases
	// Good balance between latency and throughput
	"fast": {NoDelay: 0, Interval: 30, Resend: 2, NoCongestion: 1, Description: "Balanced - default for most cases"},

	// fast2: Aggressive mode, lower latency
	// Better for interactive applications
	"fast2": {NoDelay: 1, Interval: 20, Resend: 2, NoCongestion: 1, Description: "Aggressive - lower latency"},

	// fast3: Maximum throughput mode
	// Highest performance but more CPU usage
	"fast3": {NoDelay: 1, Interval: 10, Resend: 2, NoCongestion: 1, Description: "Maximum throughput - highest performance"},

	// brutal: Brutal congestion control (Hysteria-style)
	// Maximizes bandwidth usage, requires bandwidth parameter
	"brutal": {NoDelay: 1, Interval: 5, Resend: 1, NoCongestion: 0, Description: "Brutal - Hysteria-style bandwidth maximization"},

	// responsive: Optimized for interactive traffic (gaming, VoIP)
	// Minimal delay, frequent resends
	"responsive": {NoDelay: 1, Interval: 10, Resend: 1, NoCongestion: 1, Description: "Responsive - optimized for gaming/VoIP"},

	// throughput: Optimized for bulk transfers
	// Higher window sizes, less aggressive resend
	"throughput": {NoDelay: 0, Interval: 50, Resend: 3, NoCongestion: 1, Description: "Throughput - optimized for bulk transfers"},
}

// Apply configures a KCP session with tuning parameters.
func Apply(conn *kcp.UDPSession, cfg config.KCPConfig) {
	noDelay, interval, resend, noCongestion := cfg.NoDelay, cfg.Interval, cfg.Resend, cfg.NoCongestion
	if cfg.Mode != "" {
		if mode, ok := Modes[cfg.Mode]; ok {
			noDelay = mode.NoDelay
			interval = mode.Interval
			resend = mode.Resend
			noCongestion = mode.NoCongestion
		}
	}
	conn.SetNoDelay(noDelay, interval, resend, noCongestion)

	// Set window sizes with defaults based on mode
	sndWnd, rcvWnd := cfg.SndWnd, cfg.RcvWnd
	if sndWnd <= 0 || rcvWnd <= 0 {
		// Default window sizes based on mode
		switch cfg.Mode {
		case "fast3", "brutal":
			if sndWnd <= 0 {
				sndWnd = 1024
			}
			if rcvWnd <= 0 {
				rcvWnd = 1024
			}
		case "fast2", "responsive":
			if sndWnd <= 0 {
				sndWnd = 512
			}
			if rcvWnd <= 0 {
				rcvWnd = 512
			}
		case "throughput":
			if sndWnd <= 0 {
				sndWnd = 2048
			}
			if rcvWnd <= 0 {
				rcvWnd = 2048
			}
		default: // normal, fast
			if sndWnd <= 0 {
				sndWnd = 256
			}
			if rcvWnd <= 0 {
				rcvWnd = 256
			}
		}
	}
	conn.SetWindowSize(sndWnd, rcvWnd)

	if cfg.MTU > 0 {
		conn.SetMtu(cfg.MTU)
	}
	conn.SetWriteDelay(cfg.WDelay)
	conn.SetACKNoDelay(cfg.AckNoDelay)

	// Apply DSCP if configured
	if cfg.DSCP > 0 {
		conn.SetDSCP(cfg.DSCP)
	}
}

type blockCrypt struct {
	keySize int
	build   func(key []byte) (kcp.BlockCrypt, error)
}

var blockCrypts = map[string]blockCrypt{
	"aes":         {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewAESBlockCrypt(key) }},
	"aes-128":     {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewAESBlockCrypt(key) }},
	"aes-128-gcm": {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewAESGCMCrypt(key) }},
	"aes-192":     {24, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewAESBlockCrypt(key) }},
	"aes-256":     {32, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewAESBlockCrypt(key) }},
	"salsa20":     {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewSalsa20BlockCrypt(key) }},
	"blowfish":    {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewBlowfishBlockCrypt(key) }},
	"twofish":     {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewTwofishBlockCrypt(key) }},
	"cast5":       {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewCast5BlockCrypt(key) }},
	"3des":        {24, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewTripleDESBlockCrypt(key) }},
	"tea":         {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewTEABlockCrypt(key) }},
	"xtea":        {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewXTEABlockCrypt(key) }},
	"xor":         {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewSimpleXORBlockCrypt(key) }},
	"sm4":         {16, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewSM4BlockCrypt(key) }},
	"none":        {0, func(key []byte) (kcp.BlockCrypt, error) { return kcp.NewNoneBlockCrypt(key) }},
	"null":        {0, func(key []byte) (kcp.BlockCrypt, error) { return nil, nil }},
}

// NewBlock derives and constructs the requested KCP block cipher.
func NewBlock(block, key string) (kcp.BlockCrypt, error) {
	if block == "" {
		return nil, fmt.Errorf("kcp block required")
	}
	dkey := pbkdf2.Key([]byte(key), []byte("stealthlink"), 100_000, 32, sha256.New)

	b, ok := blockCrypts[block]
	if !ok {
		return nil, fmt.Errorf("unsupported kcp block: %s", block)
	}
	bkey := dkey
	if b.keySize > 0 && len(bkey) >= b.keySize {
		bkey = bkey[:b.keySize]
	}
	blockCrypt, err := b.build(bkey)
	if err != nil {
		return nil, err
	}
	return blockCrypt, nil
}
