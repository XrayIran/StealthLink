package uqsp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/uqsp/carrier"

	quic "github.com/quic-go/quic-go"
	"github.com/xtaci/smux"
)

// Deprecated: Listener is the legacy UQSP listener. Use RuntimeListener instead,
// which routes traffic through the unified variant runtime (BuildVariantForRole).
// Set runtime.mode=unified (the default) in your config to use RuntimeListener.
// This type will be removed in a future release.
type Listener struct {
	// ln is the underlying QUIC listener (for native QUIC)
	ln *quic.Listener

	// carrierLn is the carrier-specific listener (for non-QUIC carriers)
	carrierLn carrier.Listener

	// Config is the UQSP configuration
	Config *config.UQSPConfig

	// TLSConfig is the TLS configuration
	TLSConfig *tls.Config

	// SmuxConfig is the smux configuration
	SmuxConfig *smux.Config

	// AuthToken is the authentication token
	AuthToken string

	// Capabilities are the supported capabilities
	Capabilities CapabilityFlag

	// ctx for lifecycle management
	ctx    context.Context
	cancel context.CancelFunc

	// carrier is the underlying transport carrier (if not using native QUIC)
	carrier carrier.Carrier
}

// Deprecated: NewListener creates a legacy UQSP listener. Use NewRuntimeListener instead.
func NewListener(addr string, cfg *config.UQSPConfig, tlsCfg *tls.Config, smuxCfg *smux.Config, authToken string) (*Listener, error) {
	log.Println("WARNING: using deprecated legacy UQSP Listener; migrate to runtime.mode=unified (RuntimeListener) — legacy mode will be removed in a future release")
	if cfg == nil {
		cfg = &config.UQSPConfig{}
	}

	// Build capabilities from config
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

	ctx, cancel := context.WithCancel(context.Background())

	l := &Listener{
		Config:       cfg,
		TLSConfig:    tlsCfg,
		SmuxConfig:   smuxCfg,
		AuthToken:    authToken,
		Capabilities: caps,
		ctx:          ctx,
		cancel:       cancel,
	}

	// Select carrier based on config
	c, err := l.selectCarrier()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("select carrier: %w", err)
	}

	// If using a non-QUIC carrier, listen on that carrier
	if c != nil {
		if err := l.listenOnCarrier(addr, c); err != nil {
			cancel()
			return nil, err
		}
		return l, nil
	}

	// Native QUIC listen
	if err := l.listenQUIC(addr); err != nil {
		cancel()
		return nil, err
	}

	return l, nil
}

// selectCarrier selects the appropriate carrier based on configuration
func (l *Listener) selectCarrier() (carrier.Carrier, error) {
	// If we already have a cached carrier, return it
	if l.carrier != nil {
		return l.carrier, nil
	}

	cfg := l.Config.Carrier
	carrierType := cfg.Type
	if carrierType == "" {
		carrierType = "quic" // Default to native QUIC
	}

	switch carrierType {
	case "quic":
		return nil, nil // Use native QUIC

	case "trusttunnel":
		c := carrier.NewTrustTunnelCarrier(cfg.TrustTunnel, l.SmuxConfig)
		l.carrier = c
		return c, nil

	case "rawtcp":
		c := carrier.NewRawTCPCarrier(cfg.RawTCP.Raw, cfg.RawTCP.KCP, l.SmuxConfig, l.AuthToken)
		l.carrier = c
		return c, nil

	case "faketcp":
		c := carrier.NewFakeTCPCarrier(cfg.FakeTCP, l.SmuxConfig, l.AuthToken)
		l.carrier = c
		return c, nil

	case "icmptun":
		c := carrier.NewICMPCarrier(cfg.ICMPTun, l.SmuxConfig, l.AuthToken)
		l.carrier = c
		return c, nil

	default:
		return nil, fmt.Errorf("unknown carrier type: %s", carrierType)
	}
}

// listenOnCarrier listens on a non-QUIC carrier
func (l *Listener) listenOnCarrier(addr string, c carrier.Carrier) error {
	carrierLn, err := c.Listen(addr)
	if err != nil {
		return fmt.Errorf("carrier listen: %w", err)
	}
	l.carrierLn = carrierLn
	return nil
}

// listenQUIC listens using native QUIC
func (l *Listener) listenQUIC(addr string) error {
	if l.TLSConfig == nil {
		return fmt.Errorf("UQSP listener requires TLS config")
	}

	// Clone TLS config
	tlsConf := l.TLSConfig.Clone()
	tlsConf.NextProtos = ensureALPN(tlsConf.NextProtos)

	// Build QUIC config
	quicConf := buildQUICConfig(l.Config, true)

	// Listen
	ln, err := quic.ListenAddr(addr, tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("UQSP listen: %w", err)
	}

	l.ln = ln
	return nil
}

// Accept accepts a new UQSP connection
func (l *Listener) Accept() (transport.Session, error) {
	// If using a carrier listener, accept from there
	if l.carrierLn != nil {
		return l.acceptFromCarrier()
	}

	// Native QUIC accept
	return l.acceptQUIC()
}

// acceptFromCarrier accepts from a non-QUIC carrier
func (l *Listener) acceptFromCarrier() (transport.Session, error) {
	for {
		conn, err := l.carrierLn.Accept()
		if err != nil {
			if l.ctx.Err() != nil {
				return nil, l.ctx.Err()
			}
			return nil, err
		}

		// Handle connection
		session, err := l.handleCarrierConnection(conn)
		if err != nil {
			// Log error and continue to next connection
			_ = conn.Close()
			continue
		}

		return session, nil
	}
}

// handleCarrierConnection handles a connection from a carrier
func (l *Listener) handleCarrierConnection(conn net.Conn) (transport.Session, error) {
	// Receive guard token
	timeout := 5 * time.Second
	if l.Config.Handshake.AntiReplayWindow > 0 {
		timeout = time.Duration(l.Config.Handshake.AntiReplayWindow) * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := transport.RecvGuard(conn, l.AuthToken); err != nil {
		return nil, fmt.Errorf("guard recv: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	conn, err := l.applyCarrierOverlays(conn, true)
	if err != nil {
		return nil, fmt.Errorf("apply carrier overlays: %w", err)
	}

	// Create smux session
	smuxSess, err := smux.Server(conn, l.SmuxConfig)
	if err != nil {
		return nil, fmt.Errorf("smux server: %w", err)
	}

	// Create session manager
	smConfig := l.buildSessionConfig(l.Capabilities)
	sm := NewCarrierSessionManager(conn, smuxSess, smConfig)

	// Start session manager
	if err := sm.Start(); err != nil {
		_ = smuxSess.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("session start: %w", err)
	}

	return sm.Session(), nil
}

// acceptQUIC accepts from native QUIC
func (l *Listener) acceptQUIC() (transport.Session, error) {
	for {
		conn, err := l.ln.Accept(l.ctx)
		if err != nil {
			if l.ctx.Err() != nil {
				return nil, l.ctx.Err()
			}
			return nil, err
		}

		// Handle connection in background
		session, err := l.handleConnection(conn)
		if err != nil {
			// Log error and continue to next connection
			_ = conn.CloseWithError(0, err.Error())
			continue
		}

		return session, nil
	}
}

// Close closes the listener
func (l *Listener) Close() error {
	l.cancel()
	if l.ln != nil {
		return l.ln.Close()
	}
	if l.carrierLn != nil {
		return l.carrierLn.Close()
	}
	return nil
}

// Addr returns the listener address
func (l *Listener) Addr() net.Addr {
	if l.ln != nil {
		return l.ln.Addr()
	}
	if l.carrierLn != nil {
		return l.carrierLn.Addr()
	}
	return nil
}

// handleConnection handles a new QUIC connection
func (l *Listener) handleConnection(conn *quic.Conn) (transport.Session, error) {
	// Perform handshake
	handshakeCfg := &HandshakeConfig{
		AuthMode:         l.Config.Handshake.AuthMode,
		AuthToken:        l.AuthToken,
		Enable0RTT:       l.Config.Handshake.Enable0RTT,
		AntiReplayWindow: l.Config.Handshake.AntiReplayWindow,
		Capabilities:     l.Capabilities,
		Timeout:          time.Duration(l.Config.Handshake.AntiReplayWindow) * time.Second,
	}

	handler := NewHandshakeHandler(handshakeCfg)
	result, err := handler.ServerHandshake(l.ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}

	if !result.AuthSuccess {
		return nil, fmt.Errorf("authentication failed")
	}

	// Accept control stream for smux
	stream, err := conn.AcceptStream(l.ctx)
	if err != nil {
		return nil, fmt.Errorf("accept stream: %w", err)
	}

	// Receive guard token
	wrapped := &quicStreamConn{stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
	timeout := 5 * time.Second
	if l.Config.Handshake.AntiReplayWindow > 0 {
		timeout = time.Duration(l.Config.Handshake.AntiReplayWindow) * time.Second
	}
	_ = wrapped.SetDeadline(time.Now().Add(timeout))

	if err := transport.RecvGuard(wrapped, l.AuthToken); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("guard recv: %w", err)
	}
	_ = wrapped.SetDeadline(time.Time{})

	// Create smux session
	smuxSess, err := smux.Server(wrapped, l.SmuxConfig)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("smux server: %w", err)
	}

	// Create session manager
	smConfig := l.buildSessionConfig(result.Capabilities)
	sm := NewSessionManager(conn, smuxSess, smConfig)

	// Start session manager
	if err := sm.Start(); err != nil {
		_ = smuxSess.Close()
		_ = conn.CloseWithError(0, "session")
		return nil, fmt.Errorf("session start: %w", err)
	}

	return sm.Session(), nil
}

// buildSessionConfig builds session configuration
func (l *Listener) buildSessionConfig(negotiatedCaps CapabilityFlag) *Config {
	return &Config{
		MaxConcurrentStreams:  l.Config.Streams.MaxConcurrent,
		FlowControlWindow:     l.Config.Streams.FlowControlWindow,
		MaxIncomingStreams:    l.Config.Streams.MaxIncomingStreams,
		MaxIncomingUniStreams: l.Config.Streams.MaxIncomingUniStreams,
		MaxDatagramSize:       l.Config.Datagrams.MaxSize,
		EnableFragmentation:   l.Config.Datagrams.EnableFragmentation,
		MaxIncomingDatagrams:  l.Config.Datagrams.MaxIncomingDatagrams,
		HandshakeTimeout:      time.Duration(l.Config.Handshake.AntiReplayWindow) * time.Second,
		MaxIdleTimeout:        l.Config.Security.KeyRotation,
		KeepAlivePeriod:       DefaultKeepAlivePeriod,
		Capabilities:          negotiatedCaps,
	}
}

// buildQUICConfig builds QUIC configuration from UQSP config
func buildQUICConfig(cfg *config.UQSPConfig, server bool) *quic.Config {
	qcfg := &quic.Config{
		HandshakeIdleTimeout:  time.Duration(cfg.Handshake.AntiReplayWindow) * time.Second,
		MaxIdleTimeout:        cfg.Security.KeyRotation,
		MaxIncomingStreams:    cfg.Streams.MaxIncomingStreams,
		MaxIncomingUniStreams: cfg.Streams.MaxIncomingUniStreams,
	}

	if server {
		qcfg.Allow0RTT = cfg.Handshake.Enable0RTT
	}

	return qcfg
}

// ensureALPN ensures the ALPN includes UQSP
func ensureALPN(existing []string) []string {
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

// Deprecated: Listen is a convenience function for the legacy UQSP listener.
// Use NewRuntimeListener instead.
func Listen(addr string, cfg *config.UQSPConfig, tlsCfg *tls.Config, smuxCfg *smux.Config, authToken string) (*Listener, error) {
	return NewListener(addr, cfg, tlsCfg, smuxCfg, authToken)
}
