package carrier

import (
	"context"
	"fmt"
	"net"

	"stealthlink/internal/config"
	"stealthlink/internal/transport/kcpbase"

	"github.com/xtaci/smux"
)

// KCPCarrier exposes kcpbase as a first-class UQSP carrier for mode 4d.
type KCPCarrier struct {
	cfg    *kcpbase.Config
	smux   *smux.Config
	ln     *kcpbase.Listener
	closed bool
}

func NewKCPCarrier(cfg config.KCPBaseCarrierConfig, smuxCfg *smux.Config) Carrier {
	kcfg := kcpbase.DefaultConfig()
	kcfg.Mode = kcpbase.Mode(cfg.Mode)
	kcfg.Block = kcpbase.BlockCrypt(cfg.Block)
	kcfg.Key = cfg.Key
	kcfg.DataShards = cfg.DataShards
	kcfg.ParityShards = cfg.ParityShards
	if cfg.AutoTuneFEC != nil {
		kcfg.AutoTuneFEC = *cfg.AutoTuneFEC
	}
	kcfg.DSCP = cfg.DSCP
	if cfg.BatchEnabled != nil {
		kcfg.BatchEnabled = *cfg.BatchEnabled
	}
	if cfg.BatchSize > 0 {
		kcfg.BatchSize = cfg.BatchSize
	}
	if cfg.Brutal.BandwidthMbps > 0 {
		kcfg.Brutal.Enabled = true
		kcfg.Brutal.Bandwidth = cfg.Brutal.BandwidthMbps
	}
	if cfg.Brutal.PacingMode != "" {
		kcfg.Brutal.PacingMode = cfg.Brutal.PacingMode
	}
	if cfg.AWG.JunkEnabled != nil {
		kcfg.AWG.JunkEnabled = *cfg.AWG.JunkEnabled
	}
	if cfg.AWG.JunkInterval > 0 {
		kcfg.AWG.JunkInterval = cfg.AWG.JunkInterval
	}
	if cfg.AWG.JunkMinSize > 0 {
		kcfg.AWG.JunkMinSize = cfg.AWG.JunkMinSize
	}
	if cfg.AWG.JunkMaxSize > 0 {
		kcfg.AWG.JunkMaxSize = cfg.AWG.JunkMaxSize
	}
	if cfg.AWG.PacketObfuscate != nil {
		kcfg.AWG.PacketObfuscate = *cfg.AWG.PacketObfuscate
	}
	if cfg.DTLS.MTU > 0 {
		kcfg.DTLS.MTU = cfg.DTLS.MTU
	}
	if cfg.DTLS.HandshakeTimeout > 0 {
		kcfg.DTLS.HandshakeTimeout = cfg.DTLS.HandshakeTimeout
	}
	if cfg.DTLS.FlightInterval > 0 {
		kcfg.DTLS.FlightInterval = cfg.DTLS.FlightInterval
	}

	return &KCPCarrier{
		cfg:  kcfg,
		smux: smuxCfg,
	}
}

func (c *KCPCarrier) Network() string { return "udp" }

func (c *KCPCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d := kcpbase.NewDialer(c.cfg, c.smux)
	conn, err := d.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("kcp dial: %w", err)
	}
	return conn, nil
}

func (c *KCPCarrier) Listen(addr string) (Listener, error) {
	ln, err := kcpbase.Listen(addr, c.cfg, c.smux)
	if err != nil {
		return nil, fmt.Errorf("kcp listen: %w", err)
	}
	c.ln = ln
	return &kcpListener{ln: ln}, nil
}

func (c *KCPCarrier) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.ln != nil {
		return c.ln.Close()
	}
	return nil
}

func (c *KCPCarrier) IsAvailable() bool { return true }

type kcpListener struct {
	ln *kcpbase.Listener
}

func (l *kcpListener) Accept() (net.Conn, error) { return l.ln.Accept() }
func (l *kcpListener) Close() error              { return l.ln.Close() }
func (l *kcpListener) Addr() net.Addr            { return l.ln.Addr() }

