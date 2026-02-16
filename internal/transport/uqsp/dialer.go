package uqsp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/metrics"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/uqsp/carrier"

	quic "github.com/quic-go/quic-go"
	"github.com/xtaci/smux"
)

// Deprecated: Dialer is the legacy UQSP dialer. Use RuntimeDialer instead,
// which routes traffic through the unified variant runtime (BuildVariantForRole).
// Set runtime.mode=unified (the default) in your config to use RuntimeDialer.
// This type will be removed in a future release.
type Dialer struct {
	Config       *config.UQSPConfig
	TLSConfig    *tls.Config
	SmuxConfig   *smux.Config
	AuthToken    string
	Capabilities CapabilityFlag
	carrier      carrier.Carrier
}

// Deprecated: NewDialer creates a legacy UQSP dialer. Use NewRuntimeDialer instead.
func NewDialer(cfg *config.UQSPConfig, tlsCfg *tls.Config, smuxCfg *smux.Config, authToken string) *Dialer {
	log.Println("WARNING: using deprecated legacy UQSP Dialer; migrate to runtime.mode=unified (RuntimeDialer) — legacy mode will be removed in a future release")
	metrics.IncDeprecatedLegacyMode()
	metrics.SetActivePathVariant("legacy")
	if cfg == nil {
		cfg = &config.UQSPConfig{}
	}

	caps := CapabilityDatagram | CapabilityCapsule
	if cfg.Handshake.Enable0RTT {
		caps |= Capability0RTT
	}
	if cfg.Congestion.Algorithm == "brutal" {
		caps |= CapabilityBrutalCC
	}
	if cfg.Obfuscation.Profile == "salamander" {
		caps |= CapabilitySalamander
	}
	if cfg.AWGProfile.Enabled {
		caps |= CapabilityAWG
	}
	if cfg.Security.PQKEM {
		caps |= CapabilityPostQuantum
	}
	if cfg.Security.KeyRotation > 0 {
		caps |= CapabilityKeyRotation
	}

	return &Dialer{
		Config:       cfg,
		TLSConfig:    tlsCfg,
		SmuxConfig:   smuxCfg,
		AuthToken:    authToken,
		Capabilities: caps,
	}
}

// Dial connects to a UQSP server
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	// Select carrier based on config
	c, err := d.selectCarrier()
	if err != nil {
		return nil, fmt.Errorf("select carrier: %w", err)
	}

	// If using a non-QUIC carrier, dial over that carrier
	if c != nil {
		return d.dialOverCarrier(ctx, c, addr)
	}

	// Native QUIC dial
	return d.dialQUIC(ctx, addr)
}

// selectCarrier selects the appropriate carrier based on configuration
func (d *Dialer) selectCarrier() (carrier.Carrier, error) {
	// If we already have a cached carrier, return it
	if d.carrier != nil {
		return d.carrier, nil
	}

	cfg := d.Config.Carrier
	carrierType := cfg.Type
	if carrierType == "" {
		carrierType = "quic" // Default to native QUIC
	}

	switch carrierType {
	case "quic":
		return nil, nil // Use native QUIC

	case "trusttunnel":
		c := carrier.NewTrustTunnelCarrier(cfg.TrustTunnel, d.SmuxConfig)
		d.carrier = c
		return c, nil

	case "rawtcp":
		c := carrier.NewRawTCPCarrier(cfg.RawTCP.Raw, cfg.RawTCP.KCP, d.SmuxConfig, d.AuthToken)
		d.carrier = c
		return c, nil

	case "faketcp":
		c := carrier.NewFakeTCPCarrier(cfg.FakeTCP, d.SmuxConfig, d.AuthToken)
		d.carrier = c
		return c, nil

	case "icmptun":
		c := carrier.NewICMPCarrier(cfg.ICMPTun, d.SmuxConfig, d.AuthToken)
		d.carrier = c
		return c, nil

	case "webtunnel":
		wtCfg := carrier.WebTunnelConfig{
			Server:                cfg.WebTunnel.Server,
			Path:                  cfg.WebTunnel.Path,
			Version:               cfg.WebTunnel.Version,
			Headers:               cfg.WebTunnel.Headers,
			UserAgent:             cfg.WebTunnel.UserAgent,
			TLSInsecureSkipVerify: cfg.WebTunnel.TLSInsecureSkipVerify,
			TLSServerName:         cfg.WebTunnel.TLSServerName,
			TLSFingerprint:        cfg.WebTunnel.TLSFingerprint,
		}
		c := carrier.NewWebTunnelCarrier(wtCfg, d.TLSConfig, d.SmuxConfig)
		d.carrier = c
		return c, nil

	case "chisel":
		chCfg := carrier.ChiselConfig{
			Server:                cfg.Chisel.Server,
			Path:                  cfg.Chisel.Path,
			Auth:                  cfg.Chisel.Auth,
			Fingerprint:           cfg.Chisel.Fingerprint,
			Headers:               cfg.Chisel.Headers,
			UserAgent:             cfg.Chisel.UserAgent,
			TLSInsecureSkipVerify: cfg.Chisel.TLSInsecureSkipVerify,
			TLSServerName:         cfg.Chisel.TLSServerName,
			TLSFingerprint:        cfg.Chisel.TLSFingerprint,
		}
		c := carrier.NewChiselCarrier(chCfg, d.SmuxConfig)
		d.carrier = c
		return c, nil

	case "xhttp":
		xhCfg := carrier.XHTTPConfig{
			Server:                cfg.XHTTP.Server,
			Path:                  cfg.XHTTP.Path,
			Mode:                  cfg.XHTTP.Mode,
			Headers:               cfg.XHTTP.Headers,
			MaxConns:              cfg.XHTTP.MaxConns,
			TLSInsecureSkipVerify: cfg.XHTTP.TLSInsecureSkipVerify,
			TLSServerName:         cfg.XHTTP.TLSServerName,
			TLSFingerprint:        cfg.XHTTP.TLSFingerprint,
			Metadata: carrier.XHTTPMetadataConfig{
				Session: carrier.XHTTPMetadataFieldConfig{
					Placement: cfg.XHTTP.Metadata.Session.Placement,
					Key:       cfg.XHTTP.Metadata.Session.Key,
				},
				Seq: carrier.XHTTPMetadataFieldConfig{
					Placement: cfg.XHTTP.Metadata.Seq.Placement,
					Key:       cfg.XHTTP.Metadata.Seq.Key,
				},
				Mode: carrier.XHTTPMetadataFieldConfig{
					Placement: cfg.XHTTP.Metadata.Mode.Placement,
					Key:       cfg.XHTTP.Metadata.Mode.Key,
				},
			},
		}
		c := carrier.NewXHTTPCarrier(xhCfg, d.SmuxConfig)
		d.carrier = c
		return c, nil

	default:
		return nil, fmt.Errorf("unknown carrier type: %s", carrierType)
	}
}

// dialOverCarrier dials UQSP over a non-QUIC carrier
func (d *Dialer) dialOverCarrier(ctx context.Context, c carrier.Carrier, addr string) (transport.Session, error) {
	// Use the carrier to establish the underlying connection
	conn, err := c.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("carrier dial: %w", err)
	}

	// For non-QUIC carriers, we wrap the connection with UQSP protocol layer
	// This involves performing the UQSP handshake over the carrier connection

	// Send guard token
	timeout := 5 * time.Second
	if d.Config.Handshake.AntiReplayWindow > 0 {
		timeout = time.Duration(d.Config.Handshake.AntiReplayWindow) * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := transport.SendGuard(conn, d.AuthToken); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("UQSP guard send: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	conn, err = d.applyCarrierOverlays(conn, false)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("apply carrier overlays: %w", err)
	}

	// Create smux session over the carrier connection
	smuxSess, err := smux.Client(conn, d.SmuxConfig)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("UQSP smux client: %w", err)
	}

	// Create a mock QUIC connection info for the session manager
	// Since we're not using QUIC, we use the carrier connection's addresses
	smConfig := d.buildSessionConfig(d.Capabilities)
	smConfig.Capabilities = d.Capabilities

	// Create session manager with carrier-based session
	sm := NewCarrierSessionManager(conn, smuxSess, smConfig)

	// Start session manager
	if err := sm.Start(); err != nil {
		_ = smuxSess.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("UQSP session start: %w", err)
	}

	return sm.Session(), nil
}

// dialQUIC dials using native QUIC
func (d *Dialer) dialQUIC(ctx context.Context, addr string) (transport.Session, error) {
	if d.TLSConfig == nil {
		return nil, fmt.Errorf("UQSP dialer requires TLS config")
	}

	// Clone TLS config for this connection
	tlsConf := d.TLSConfig.Clone()
	tlsConf.NextProtos = d.ensureALPN(tlsConf.NextProtos)

	// Set server name if not set
	if tlsConf.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			tlsConf.ServerName = host
		}
	}

	// Build QUIC config
	quicConf := d.buildQUICConfig()

	// Dial QUIC connection
	var conn *quic.Conn
	var err error

	if d.Config.Handshake.Enable0RTT {
		conn, err = quic.DialAddrEarly(ctx, addr, tlsConf, quicConf)
	} else {
		conn, err = quic.DialAddr(ctx, addr, tlsConf, quicConf)
	}
	if err != nil {
		return nil, fmt.Errorf("UQSP dial: %w", err)
	}

	// Perform handshake
	handshakeCfg := &HandshakeConfig{
		AuthMode:         d.Config.Handshake.AuthMode,
		AuthToken:        d.AuthToken,
		Enable0RTT:       d.Config.Handshake.Enable0RTT,
		AntiReplayWindow: d.Config.Handshake.AntiReplayWindow,
		Capabilities:     d.Capabilities,
		Timeout:          time.Duration(d.Config.Handshake.AntiReplayWindow) * time.Second,
	}

	handler := NewHandshakeHandler(handshakeCfg)
	result, err := handler.ClientHandshake(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(0, "handshake failed")
		return nil, fmt.Errorf("UQSP handshake: %w", err)
	}

	if !result.AuthSuccess {
		_ = conn.CloseWithError(0, "auth failed")
		return nil, fmt.Errorf("UQSP authentication failed")
	}

	// Open control stream for smux
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "open stream")
		return nil, fmt.Errorf("UQSP open stream: %w", err)
	}

	// Send guard token
	wrapped := &quicStreamConn{stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
	timeout := 5 * time.Second
	if d.Config.Handshake.AntiReplayWindow > 0 {
		timeout = time.Duration(d.Config.Handshake.AntiReplayWindow) * time.Second
	}
	_ = wrapped.SetDeadline(time.Now().Add(timeout))

	if err := transport.SendGuard(wrapped, d.AuthToken); err != nil {
		_ = stream.Close()
		_ = conn.CloseWithError(0, "guard")
		return nil, fmt.Errorf("UQSP guard send: %w", err)
	}
	_ = wrapped.SetDeadline(time.Time{})

	// Create smux session
	smuxSess, err := smux.Client(wrapped, d.SmuxConfig)
	if err != nil {
		_ = stream.Close()
		_ = conn.CloseWithError(0, "smux")
		return nil, fmt.Errorf("UQSP smux client: %w", err)
	}

	// Create session manager
	smConfig := d.buildSessionConfig(result.Capabilities)
	sm := NewSessionManager(conn, smuxSess, smConfig)

	// Start session manager
	if err := sm.Start(); err != nil {
		_ = smuxSess.Close()
		_ = conn.CloseWithError(0, "session")
		return nil, fmt.Errorf("UQSP session start: %w", err)
	}

	return sm.Session(), nil
}

// buildQUICConfig builds QUIC configuration from UQSP config
func (d *Dialer) buildQUICConfig() *quic.Config {
	handshakeTimeout := time.Duration(d.Config.Handshake.AntiReplayWindow) * time.Second
	if handshakeTimeout <= 0 {
		handshakeTimeout = 10 * time.Second
	}

	maxIdle := d.Config.Security.KeyRotation
	if maxIdle <= 0 {
		maxIdle = 30 * time.Second
	}

	cfg := &quic.Config{
		HandshakeIdleTimeout:  handshakeTimeout,
		MaxIdleTimeout:        maxIdle,
		MaxIncomingStreams:    d.Config.Streams.MaxIncomingStreams,
		MaxIncomingUniStreams: d.Config.Streams.MaxIncomingUniStreams,
		EnableDatagrams:       true,
		Allow0RTT:             d.Config.Handshake.Enable0RTT,
		KeepAlivePeriod:       DefaultKeepAlivePeriod,
	}

	// Note: Brutal CC for native QUIC requires a quic-go fork (e.g., apernet/quic-go)
	// that exposes CongestionControllerFactory. With standard quic-go, Brutal CC
	// is applied at the application layer for carrier-based (non-QUIC) sessions
	// via our BrutalController in congestion.go.

	return cfg
}

// buildSessionConfig builds session configuration
func (d *Dialer) buildSessionConfig(negotiatedCaps CapabilityFlag) *Config {
	return &Config{
		MaxConcurrentStreams:  d.Config.Streams.MaxConcurrent,
		FlowControlWindow:     d.Config.Streams.FlowControlWindow,
		MaxIncomingStreams:    d.Config.Streams.MaxIncomingStreams,
		MaxIncomingUniStreams: d.Config.Streams.MaxIncomingUniStreams,
		MaxDatagramSize:       d.Config.Datagrams.MaxSize,
		EnableFragmentation:   d.Config.Datagrams.EnableFragmentation,
		MaxIncomingDatagrams:  d.Config.Datagrams.MaxIncomingDatagrams,
		HandshakeTimeout:      time.Duration(d.Config.Handshake.AntiReplayWindow) * time.Second,
		MaxIdleTimeout:        d.Config.Security.KeyRotation,
		KeepAlivePeriod:       DefaultKeepAlivePeriod,
		Capabilities:          negotiatedCaps,
	}
}

// ensureALPN ensures the ALPN includes UQSP
func (d *Dialer) ensureALPN(existing []string) []string {
	for _, p := range existing {
		if p == DefaultALPN {
			return existing
		}
	}
	out := make([]string, 0, len(existing)+1)
	out = append(out, existing...)
	out = append(out, DefaultALPN)
	return out
}

// quicStreamConn adapts quic.Stream to net.Conn
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
