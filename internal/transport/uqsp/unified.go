// Package uqsp provides the Unified QUIC Superset Protocol implementation.
// This file implements unified protocol integrations that combine the best
// features of competing protocols into five optimized variants.
package uqsp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
	"stealthlink/internal/tlsutil"
	"stealthlink/internal/transport/underlay"
	"stealthlink/internal/transport/uqsp/behavior"
	"stealthlink/internal/transport/uqsp/carrier"
	"stealthlink/internal/warp"
)

// ProtocolVariant represents one of the five unified protocol variants.
// Each variant is optimized for different scenarios and threat models.
type ProtocolVariant int

const (
	// VariantXHTTP_TLS represents category 4a:
	// XHTTP + TLS + Domain Fronting + XTLS Vision + ECH
	// Best for: Maximum stealth with CDN cover
	VariantXHTTP_TLS ProtocolVariant = iota

	// VariantRawTCP represents category 4b:
	// RawTCP/FakeTCP + KCP/smux + obfs4/TUIC-style obfuscation
	// Best for: Low-latency, high-throughput scenarios
	VariantRawTCP

	// VariantTLSMirror represents category 4c:
	// REALITY/ShadowTLS/TLSMirror + XTLS Vision + PQ signatures
	// Best for: TLS fingerprint resistance with quantum security
	VariantTLSMirror

	// VariantUDP represents category 4d:
	// QUIC/UDP + Hysteria2-style CC + AmneziaWG + udp2raw-style obfuscation
	// Best for: UDP-based protocols and anti-DPI
	VariantUDP

	// VariantTrust represents category 4e:
	// TrustTunnel/Chisel + HTTP/2 + HTTP/3 multiplexing
	// Best for: HTTP-constrained environments and maximum compatibility
	VariantTrust
)

// VariantConfig configures a specific protocol variant.
type VariantConfig struct {
	Variant        ProtocolVariant
	Carrier        carrier.Carrier
	Behaviors      []behavior.Overlay
	TLSConfig      *tls.Config
	EnableWARP     bool         // Hide server IP behind WARP
	WARPConfig     *warp.Config // WARP runtime config when enabled
	UnderlayDialer underlay.Dialer
	EnableReverse  bool         // Server initiates connection
	ReverseMode    *ReverseMode // Reverse mode tuning and addressing
}

// UnifiedProtocol implements the unified protocol with all variants.
type UnifiedProtocol struct {
	variant VariantConfig
	session *uqspSession
	warpMu  sync.Mutex
	warp    *warp.StealthWrap
	warpErr error
	warpOn  bool
}

// Overlays returns the configured behavior overlays for this protocol instance.
func (u *UnifiedProtocol) Overlays() []behavior.Overlay {
	return u.variant.Behaviors
}

// UnderlayDialer returns the configured underlay dialer (direct/warp/socks).
// This is primarily exposed for observability and integration tests.
func (u *UnifiedProtocol) UnderlayDialer() underlay.Dialer {
	return u.variant.UnderlayDialer
}

// uqspSession represents a unified protocol session with optional SessionManager.
type uqspSession struct {
	variant    ProtocolVariant
	conn       net.Conn
	behaviors  []behavior.Overlay
	sessionMgr *SessionManager // nil when carrier doesn't support QUIC multiplexing
}

// NewUnifiedProtocol creates a new unified protocol instance.
func NewUnifiedProtocol(config VariantConfig) (*UnifiedProtocol, error) {
	if config.Carrier == nil {
		return nil, fmt.Errorf("carrier is required")
	}

	return &UnifiedProtocol{
		variant: config,
	}, nil
}

// Dial establishes a connection using the configured variant.
func (u *UnifiedProtocol) Dial(ctx context.Context, addr string) (conn net.Conn, err error) {
	carrierName := carrierMetricName(u.variant.Carrier)
	start := time.Now()
	defer finalizeHandshakeMetrics(start, carrierName, &err)

	if err := u.ensureWARP(ctx); err != nil {
		return nil, fmt.Errorf("warp start: %w", err)
	}

	for _, overlay := range u.variant.Behaviors {
		if !overlay.Enabled() {
			continue
		}
		if preparer, ok := overlay.(behavior.ContextPreparer); ok {
			ctx, err = preparer.PrepareContext(ctx)
			if err != nil {
				return nil, fmt.Errorf("prepare overlay %s context: %w", overlay.Name(), err)
			}
		}
	}

	if u.variant.UnderlayDialer != nil {
		ctx = tlsutil.WithBaseDialFunc(ctx, func(ctx context.Context, network, addr string) (net.Conn, error) {
			return u.variant.UnderlayDialer.Dial(ctx, network, addr)
		})
	}

	// Get base connection from carrier
	conn, err = u.variant.Carrier.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("carrier dial: %w", err)
	}

	// Apply behavior overlays in sequence
	for _, overlay := range u.variant.Behaviors {
		if overlay.Enabled() {
			conn, err = overlay.Apply(conn)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("apply overlay %s: %w", overlay.Name(), err)
			}
			metrics.IncUQSPobfuscationOps()
		}
	}
	conn = u.wrapWARPConn(conn)

	// Track the session; if the carrier supports QUIC muxing, a SessionManager
	// will be attached later via AttachSessionManager.
	u.session = &uqspSession{
		variant:   u.variant.Variant,
		conn:      conn,
		behaviors: u.variant.Behaviors,
	}

	recordConnectionEstablished(carrierName)
	return wrapMetricsConn(conn, carrierName), nil
}

// Close releases resources owned by this protocol instance (carriers, underlay dialers, WARP).
func (u *UnifiedProtocol) Close() error {
	var firstErr error
	if u.variant.Carrier != nil {
		if err := u.variant.Carrier.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if u.variant.UnderlayDialer != nil {
		if err := u.variant.UnderlayDialer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	u.warpMu.Lock()
	w := u.warp
	u.warp = nil
	u.warpMu.Unlock()
	if w != nil {
		if err := w.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Listen creates a listener using the configured variant.
func (u *UnifiedProtocol) Listen(addr string) (net.Listener, error) {
	if err := u.ensureWARP(context.Background()); err != nil {
		return nil, fmt.Errorf("warp start: %w", err)
	}

	// For reverse mode, the server acts as dialer
	if u.variant.EnableReverse {
		return u.listenReverse(addr)
	}

	// Standard mode: carrier listens
	listener, err := u.variant.Carrier.Listen(addr)
	if err != nil {
		return nil, fmt.Errorf("carrier listen: %w", err)
	}

	return &unifiedListener{
		Listener:    listener,
		behaviors:   u.variant.Behaviors,
		carrierName: carrierMetricName(u.variant.Carrier),
		wrapConn:    u.wrapWARPConn,
	}, nil
}

// listenReverse creates a reverse-mode listener
func (u *UnifiedProtocol) listenReverse(addr string) (net.Listener, error) {
	mode := &ReverseMode{
		Enabled:   true,
		Role:      "listener",
		TLSConfig: u.variant.TLSConfig,
	}
	if u.variant.ReverseMode != nil {
		cp := *u.variant.ReverseMode
		cp.Enabled = true
		if cp.Role == "" {
			cp.Role = "listener"
		}
		cp.TLSConfig = u.variant.TLSConfig
		mode = &cp
	}

	// In reverse mode, we create a listener that waits for incoming
	// connections from the peer (who acts as the "server")
	var dialFn func(ctx context.Context, network, addr string) (net.Conn, error)
	if u.variant.UnderlayDialer != nil {
		dialFn = u.variant.UnderlayDialer.Dial
	}
	reverse := NewReverseDialerWithDialFunc(mode, u.variant.TLSConfig, dialFn)

	ctx := context.Background()
	if err := reverse.Start(ctx); err != nil {
		return nil, fmt.Errorf("start reverse listener: %w", err)
	}

	ln, err := NewReverseListener(reverse, addr)
	if err != nil {
		return nil, err
	}
	if u.variant.EnableWARP {
		return &warpNetListener{Listener: ln, wrapConn: u.wrapWARPConn}, nil
	}
	return ln, nil
}

func (u *UnifiedProtocol) ensureWARP(ctx context.Context) error {
	if !u.variant.EnableWARP {
		return nil
	}
	u.warpMu.Lock()
	defer u.warpMu.Unlock()
	if u.warpOn {
		return u.warpErr
	}
	cfg := warp.DefaultConfig()
	if u.variant.WARPConfig != nil {
		cfg = *u.variant.WARPConfig
	}
	if !cfg.Enabled {
		cfg.Enabled = true
	}
	w, err := warp.NewStealthWrap(cfg)
	if err != nil {
		u.warpErr = err
		u.warpOn = true
		if cfg.Required {
			return fmt.Errorf("warp required but failed to initialize: %w", err)
		}
		return err
	}
	if err := w.Start(ctx); err != nil {
		u.warpErr = err
		u.warpOn = true
		if cfg.Required {
			return fmt.Errorf("warp required but failed to start: %w", err)
		}
		return err
	}
	if cfg.RoutingMode == "vpn_only" && cfg.VPNSubnet != "" && w.IsEnabled() {
		if t := w.GetTunnel(); t != nil {
			_ = warp.RegisterWithGateway(t, cfg.VPNSubnet)
		}
	}
	u.warp = w
	u.warpOn = true
	return nil
}

func (u *UnifiedProtocol) wrapWARPConn(conn net.Conn) net.Conn {
	if conn == nil || !u.variant.EnableWARP {
		return conn
	}
	u.warpMu.Lock()
	defer u.warpMu.Unlock()
	if u.warp == nil || !u.warp.IsEnabled() {
		return conn
	}
	return u.warp.WrapConn(conn)
}

// unifiedListener wraps a carrier listener to apply behaviors.
type unifiedListener struct {
	carrier.Listener
	behaviors   []behavior.Overlay
	carrierName string
	wrapConn    func(net.Conn) net.Conn
}

// Accept accepts a connection and applies behavior overlays.
func (l *unifiedListener) Accept() (conn net.Conn, err error) {
	start := time.Now()
	defer finalizeHandshakeMetrics(start, l.carrierName, &err)

	conn, err = l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Apply behavior overlays in sequence
	for _, overlay := range l.behaviors {
		if overlay.Enabled() {
			conn, err = overlay.Apply(conn)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("apply overlay %s: %w", overlay.Name(), err)
			}
			metrics.IncUQSPobfuscationOps()
		}
	}
	if l.wrapConn != nil {
		conn = l.wrapConn(conn)
	}

	recordConnectionEstablished(l.carrierName)
	return wrapMetricsConn(conn, l.carrierName), nil
}

type warpNetListener struct {
	net.Listener
	wrapConn func(net.Conn) net.Conn
}

func (l *warpNetListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.wrapConn != nil {
		conn = l.wrapConn(conn)
	}
	return conn, nil
}

type metricsConn struct {
	net.Conn
	carrierName string
	closed      atomic.Bool
}

func wrapMetricsConn(conn net.Conn, carrierName string) net.Conn {
	if conn == nil {
		return nil
	}
	if _, ok := conn.(*metricsConn); ok {
		return conn
	}
	return &metricsConn{
		Conn:        conn,
		carrierName: carrierName,
	}
}

func (c *metricsConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		metrics.AddTrafficInbound(int64(n))
		metrics.RecordCarrierTraffic(c.carrierName, 0, int64(n))
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		metrics.IncErrors()
		metrics.RecordCarrierError(c.carrierName)
	}
	return n, err
}

func (c *metricsConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		metrics.AddTrafficOutbound(int64(n))
		metrics.RecordCarrierTraffic(c.carrierName, int64(n), 0)
	}
	if err != nil && !errors.Is(err, net.ErrClosed) {
		metrics.IncErrors()
		metrics.RecordCarrierError(c.carrierName)
	}
	return n, err
}

func (c *metricsConn) Close() error {
	err := c.Conn.Close()
	if c.closed.CompareAndSwap(false, true) {
		metrics.DecSessions()
		metrics.DecTransportSession(c.carrierName)
		metrics.RecordCarrierDisconnection(c.carrierName)
	}
	return err
}

func finalizeHandshakeMetrics(start time.Time, carrierName string, errp *error) {
	metrics.IncUQSPhandshake()
	metrics.AddUQSPhandshakeDuration(time.Since(start))
	if errp != nil && *errp != nil {
		metrics.IncErrors()
		metrics.RecordCarrierError(carrierName)
	}
}

func recordConnectionEstablished(carrierName string) {
	metrics.IncSessions()
	metrics.IncUQSPSessions()
	metrics.IncTransportSession(carrierName)
	metrics.RecordCarrierConnection(carrierName)
}

func carrierMetricName(c carrier.Carrier) string {
	if c == nil {
		return "uqsp"
	}

	if named, ok := c.(interface{ Name() string }); ok {
		if name := strings.TrimSpace(named.Name()); name != "" {
			return name
		}
	}

	if network := strings.TrimSpace(c.Network()); network != "" {
		return "uqsp_" + network
	}

	return "uqsp"
}

// AttachSessionManager attaches a SessionManager to the protocol for
// QUIC-backed carriers that support multiplexed streams and UDP relay.
func (u *UnifiedProtocol) AttachSessionManager(mgr *SessionManager) {
	if u.session == nil {
		u.session = &uqspSession{variant: u.variant.Variant}
	}
	u.session.sessionMgr = mgr
}

// SessionManager returns the attached SessionManager, or nil if the carrier
// does not support QUIC multiplexing.
func (u *UnifiedProtocol) SessionManager() *SessionManager {
	if u.session == nil {
		return nil
	}
	return u.session.sessionMgr
}

// ProtocolBuilder helps build protocol variants with the recommended settings.
type ProtocolBuilder struct {
	variant         ProtocolVariant
	carrierType     string
	carrierInstance carrier.Carrier
	behaviors       []behavior.Overlay
	tlsConfig       *tls.Config
	warpEnabled     bool
	reverseMode     bool
}

// NewProtocolBuilder creates a new protocol builder.
func NewProtocolBuilder(variant ProtocolVariant) *ProtocolBuilder {
	return &ProtocolBuilder{
		variant:   variant,
		behaviors: []behavior.Overlay{},
	}
}

// WithCarrier sets the carrier type string. The carrier will be resolved
// from the DefaultRegistry when Build() is called.
func (b *ProtocolBuilder) WithCarrier(carrierType string) *ProtocolBuilder {
	b.carrierType = carrierType
	return b
}

// WithCarrierInstance sets the carrier directly, bypassing the registry.
func (b *ProtocolBuilder) WithCarrierInstance(c carrier.Carrier) *ProtocolBuilder {
	b.carrierInstance = c
	return b
}

// WithTLS sets the TLS configuration.
func (b *ProtocolBuilder) WithTLS(config *tls.Config) *ProtocolBuilder {
	b.tlsConfig = config
	return b
}

// WithWARP enables WARP for server IP hiding.
func (b *ProtocolBuilder) WithWARP(enabled bool) *ProtocolBuilder {
	b.warpEnabled = enabled
	return b
}

// WithReverse enables reverse mode.
func (b *ProtocolBuilder) WithReverse(enabled bool) *ProtocolBuilder {
	b.reverseMode = enabled
	return b
}

// AddBehavior adds a behavior overlay.
func (b *ProtocolBuilder) AddBehavior(overlay behavior.Overlay) *ProtocolBuilder {
	b.behaviors = append(b.behaviors, overlay)
	return b
}

// Build builds the protocol variant configuration.
func (b *ProtocolBuilder) Build() (VariantConfig, error) {
	config := VariantConfig{
		Variant:       b.variant,
		TLSConfig:     b.tlsConfig,
		EnableWARP:    b.warpEnabled,
		EnableReverse: b.reverseMode,
		Behaviors:     b.behaviors,
	}

	// Resolve carrier: prefer explicit instance, then lookup by type string.
	switch {
	case b.carrierInstance != nil:
		config.Carrier = b.carrierInstance
	case b.carrierType != "":
		c, ok := carrier.DefaultRegistry.Get(b.carrierType)
		if ok && c != nil {
			config.Carrier = c
		} else if b.carrierType == "quic" {
			// QUIC is built-in and doesn't need registry lookup
			config.Carrier = buildVariantQUICCarrier(b.tlsConfig)
		} else {
			return VariantConfig{}, fmt.Errorf("carrier type %q not found in registry", b.carrierType)
		}
	default:
		return VariantConfig{}, fmt.Errorf("carrier not configured: use WithCarrier or WithCarrierInstance")
	}

	return config, nil
}

// RecommendedVariant returns the recommended protocol variant for the given scenario.
func RecommendedVariant(scenario string) ProtocolVariant {
	switch scenario {
	case "cdn", "domain_front", "cloudflare":
		return VariantXHTTP_TLS
	case "low_latency", "gaming", "realtime":
		return VariantRawTCP
	case "tls_mimic", "fingerprint_resistance":
		return VariantTLSMirror
	case "udp", "quic", "hysteria":
		return VariantUDP
	case "http_compatible", "corporate":
		return VariantTrust
	default:
		return VariantUDP // Default to UDP variant (QUIC-based)
	}
}

// VariantDescription returns a description of the protocol variant.
func VariantDescription(v ProtocolVariant) string {
	switch v {
	case VariantXHTTP_TLS:
		return "XHTTP + TLS + Domain Fronting + XTLS Vision + ECH - Maximum stealth with CDN cover"
	case VariantRawTCP:
		return "RawTCP/FakeTCP + KCP/smux + obfs4 - Low latency, high throughput"
	case VariantTLSMirror:
		return "REALITY/ShadowTLS + XTLS Vision + PQ signatures - TLS fingerprint resistance"
	case VariantUDP:
		return "QUIC/UDP + Hysteria2 CC + AmneziaWG - UDP-based with anti-DPI"
	case VariantTrust:
		return "TrustTunnel + HTTP/2 + HTTP/3 - HTTP-constrained environments"
	default:
		return "Unknown variant"
	}
}

// ProtocolStats tracks statistics for the unified protocol.
type ProtocolStats struct {
	BytesIn          uint64
	BytesOut         uint64
	PacketsIn        uint64
	PacketsOut       uint64
	Connections      uint64
	FailedHandshakes uint64
	LatencyMs        int64
}

// ProtocolOptimizer provides dynamic optimization for the protocol.
type ProtocolOptimizer struct {
	currentVariant ProtocolVariant
	stats          *ProtocolStats
	adaptiveMode   bool
}

// NewProtocolOptimizer creates a new protocol optimizer.
func NewProtocolOptimizer(adaptive bool) *ProtocolOptimizer {
	return &ProtocolOptimizer{
		currentVariant: VariantUDP,
		stats:          &ProtocolStats{},
		adaptiveMode:   adaptive,
	}
}

// Optimize evaluates current conditions and suggests optimizations.
func (o *ProtocolOptimizer) Optimize() OptimizationSuggestion {
	if !o.adaptiveMode {
		return OptimizationSuggestion{
			Action: "maintain",
			Reason: "Adaptive mode disabled",
		}
	}

	// Evaluate conditions and suggest optimizations
	// This is a simplified version - real implementation would use
	// machine learning or heuristics

	if o.stats.FailedHandshakes > 10 {
		return OptimizationSuggestion{
			Action: "switch_variant",
			Target: VariantTLSMirror,
			Reason: "High handshake failure rate - try TLS mirror variant",
		}
	}

	if o.stats.LatencyMs > 200 {
		return OptimizationSuggestion{
			Action: "switch_variant",
			Target: VariantRawTCP,
			Reason: "High latency - try raw TCP variant",
		}
	}

	return OptimizationSuggestion{
		Action: "maintain",
		Reason: "Current variant performing well",
	}
}

// OptimizationSuggestion represents an optimization recommendation.
type OptimizationSuggestion struct {
	Action string
	Target ProtocolVariant
	Reason string
}

// ProtocolChain allows chaining multiple protocol variants for fallback.
type ProtocolChain struct {
	variants []ProtocolVariant
	current  int
	fallback bool
}

// NewProtocolChain creates a new protocol chain with fallback support.
func NewProtocolChain(fallback bool, variants ...ProtocolVariant) *ProtocolChain {
	if len(variants) == 0 {
		// Default chain: UDP -> RawTCP -> Trust
		variants = []ProtocolVariant{VariantUDP, VariantRawTCP, VariantTrust}
	}

	return &ProtocolChain{
		variants: variants,
		current:  0,
		fallback: fallback,
	}
}

// Current returns the current variant.
func (c *ProtocolChain) Current() ProtocolVariant {
	if c.current < len(c.variants) {
		return c.variants[c.current]
	}
	return VariantUDP
}

// Next advances to the next variant in the chain.
func (c *ProtocolChain) Next() bool {
	if !c.fallback || c.current >= len(c.variants)-1 {
		return false
	}
	c.current++
	return true
}

// Reset resets the chain to the first variant.
func (c *ProtocolChain) Reset() {
	c.current = 0
}

// All returns all variants in the chain.
func (c *ProtocolChain) All() []ProtocolVariant {
	return c.variants
}
