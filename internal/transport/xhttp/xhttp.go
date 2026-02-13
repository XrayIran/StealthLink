// Package xhttp implements XHTTP (SplitHTTP) transport for StealthLink.
//
// This implementation maps XHTTP profiles onto a hardened HTTP/2 stream tunnel,
// while preserving XHTTP-specific shaping headers and config surfaces.
package xhttp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"stealthlink/internal/transport"
	"stealthlink/internal/transport/h2mux"
	"stealthlink/internal/transport/padding"
	"stealthlink/internal/transport/xhttpmeta"

	"github.com/xtaci/smux"
)

// Mode defines the XHTTP operation mode.
type Mode string

const (
	ModeStreamOne  Mode = "stream-one"
	ModeStreamUp   Mode = "stream-up"
	ModeStreamDown Mode = "stream-down"
	ModePacketUp   Mode = "packet-up"
)

// MetadataPlacement controls where XHTTP session metadata is placed.
type MetadataPlacement string

const (
	PlacementHeader MetadataPlacement = "header"
	PlacementPath   MetadataPlacement = "path"
	PlacementQuery  MetadataPlacement = "query"
	PlacementCookie MetadataPlacement = "cookie"
)

// Config configures XHTTP transport.
type Config struct {
	Mode              Mode                   `yaml:"mode"`
	Path              string                 `yaml:"path"`
	Headers           map[string]string      `yaml:"headers"`
	XPadding          padding.XPaddingConfig `yaml:"xpadding"`
	MaxConnections    int                    `yaml:"max_connections"`
	PacketSize        int                    `yaml:"packet_size"`
	KeepAlive         time.Duration          `yaml:"keep_alive"`
	XMux              XMuxConfig             `yaml:"xmux"`
	
	SessionPlacement  MetadataPlacement      `yaml:"session_placement"`
	SessionKey        string                 `yaml:"session_key"`
	SequencePlacement MetadataPlacement      `yaml:"sequence_placement"`
	SequenceKey       string                 `yaml:"sequence_key"`
	MetadataPlacement MetadataPlacement      `yaml:"metadata_placement"` // Backward compatibility
}

// ApplyDefaults sets default values.
func (c *Config) ApplyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeStreamOne
	}
	if c.Path == "" {
		c.Path = "/_sl"
	}
	if !strings.HasPrefix(c.Path, "/") {
		c.Path = "/" + c.Path
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 2
	}
	if c.PacketSize <= 0 {
		c.PacketSize = 1024
	}
	if c.KeepAlive <= 0 {
		c.KeepAlive = 30 * time.Second
	}
	if c.MetadataPlacement == "" && c.SessionPlacement == "" && c.SequencePlacement == "" {
		c.MetadataPlacement = PlacementHeader
	}
	
	// Default placements to MetadataPlacement if not specified
	if c.SessionPlacement == "" {
		if c.MetadataPlacement != "" {
			c.SessionPlacement = c.MetadataPlacement
		} else {
			c.SessionPlacement = PlacementHeader
		}
	}
	if c.SequencePlacement == "" {
		if c.MetadataPlacement != "" {
			c.SequencePlacement = c.MetadataPlacement
		} else {
			c.SequencePlacement = PlacementHeader
		}
	}
	
	if c.SessionKey == "" {
		c.SessionKey = "X-Session-ID"
	}
	if c.SequenceKey == "" {
		c.SequenceKey = "X-Seq"
	}
	
	c.XPadding.ApplyDefaults()
}

// Dialer implements transport.Dialer for XHTTP.
type Dialer struct {
	config      Config
	tlsConfig   *tls.Config
	smuxConfig  *smux.Config
	fingerprint string
	connectAddr string
	guard       string
	proxyDial   func(ctx context.Context, network, addr string) (net.Conn, error)
	xmuxDialer  *XMuxDialer
}

// NewDialer creates a new XHTTP dialer.
func NewDialer(config Config, tlsConfig *tls.Config, smuxCfg *smux.Config, fingerprint, connectAddr, guard string) *Dialer {
	config.ApplyDefaults()
	d := &Dialer{
		config:      config,
		tlsConfig:   tlsConfig,
		smuxConfig:  smuxCfg,
		fingerprint: fingerprint,
		connectAddr: connectAddr,
		guard:       guard,
	}

	// Initialize XMux if enabled
	if config.XMux.Enabled {
		baseDialer := &baseDialer{
			tlsConfig:   tlsConfig,
			smuxConfig:  smuxCfg,
			fingerprint: fingerprint,
			connectAddr: connectAddr,
			guard:       guard,
			config:      config,
		}
		d.xmuxDialer = NewXMuxDialer(config.XMux, baseDialer)
	}

	return d
}

// baseDialer implements transport.Dialer for XMux pooling
type baseDialer struct {
	tlsConfig   *tls.Config
	smuxConfig  *smux.Config
	fingerprint string
	connectAddr string
	guard       string
	config      Config
	proxyDial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d *baseDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	cfg := d.config
	
	// Generate a session ID for the connection
	sessionID := generateSessionID()
	
	metaCfg := xhttpmeta.MetadataConfig{
		Session: xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(cfg.SessionPlacement), Key: cfg.SessionKey},
		Seq:     xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(cfg.SequencePlacement), Key: cfg.SequenceKey},
		Mode:    xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(cfg.MetadataPlacement), Key: "X-Stealthlink-Mode"},
	}
	metaValues := xhttpmeta.MetadataValues{
		SessionID: sessionID,
		Seq:       1, // First request
		Mode:      string(cfg.Mode),
	}

	rawURL := "https://" + addr + cfg.Path
	u, err := xhttpmeta.BuildURL(rawURL, metaCfg, metaValues)
	if err != nil {
		u = rawURL
	}

	base := h2mux.NewDialer(u, d.tlsConfig, d.smuxConfig, d.fingerprint, firstNonEmpty(d.connectAddr, addr), d.guard)
	base.Headers = buildHeaders(cfg, metaCfg, metaValues)
	base.Cookies = buildCookies(cfg, metaCfg, metaValues)
	base.ProxyDial = d.proxyDial
	
	// We use a context that won't be cancelled when the dial timeout expires
	// for the persistent HTTP/2 session.
	sessionCtx := context.WithoutCancel(ctx)
	return base.Dial(sessionCtx, addr)
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SetProxyDial sets a custom TCP dial function (for upstream proxy/fronting shaping).
func (d *Dialer) SetProxyDial(proxyDial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	d.proxyDial = proxyDial
}

// Dial implements transport.Dialer.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	// Use XMux pooling if enabled
	if d.xmuxDialer != nil {
		return d.xmuxDialer.Dial(ctx, addr)
	}

	bd := &baseDialer{
		tlsConfig:   d.tlsConfig,
		smuxConfig:  d.smuxConfig,
		fingerprint: d.fingerprint,
		connectAddr: d.connectAddr,
		guard:       d.guard,
		config:      d.config,
		proxyDial:   d.proxyDial,
	}
	return bd.Dial(ctx, addr)
}

// Stats returns XMux statistics if XMux is enabled.
func (d *Dialer) Stats() (XMuxStats, bool) {
	if d.xmuxDialer == nil {
		return XMuxStats{}, false
	}
	return d.xmuxDialer.Stats(), true
}

// Listener is an alias over the hardened H2 mux listener.
type Listener = h2mux.Listener

// Listen creates a new XHTTP listener.
func Listen(addr string, config Config, tlsConfig *tls.Config, smuxCfg *smux.Config, guard string) (transport.Listener, error) {
	config.ApplyDefaults()

	padMin, padMax := 0, 0
	if config.XPadding.Enabled {
		padMin, padMax = config.XPadding.Min, config.XPadding.Max
	}

	metaCfg := xhttpmeta.MetadataConfig{
		Session: xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(config.SessionPlacement), Key: config.SessionKey},
		Seq:     xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(config.SequencePlacement), Key: config.SequenceKey},
		Mode:    xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(config.MetadataPlacement), Key: "X-Stealthlink-Mode"},
	}

	return h2mux.Listen(addr, config.Path, tlsConfig, smuxCfg, guard, padMin, padMax, metaCfg)
}

// GenerateRandomPath generates a random path token using crypto/rand.
func GenerateRandomPath(prefix string, length int) string {
	if length <= 0 {
		length = 8
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	max := big.NewInt(int64(len(chars)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			n = big.NewInt(0)
		}
		b[i] = chars[n.Int64()]
	}
	return strings.TrimSuffix(prefix, "/") + "/" + string(b)
}

func buildHeaders(cfg Config, metaCfg xhttpmeta.MetadataConfig, values xhttpmeta.MetadataValues) map[string]string {
	h := make(http.Header)
	for k, v := range cfg.Headers {
		h.Set(k, v)
	}
	
	// Apply metadata using xhttpmeta
	req, _ := http.NewRequest(http.MethodPost, "http://dummy", nil)
	_ = xhttpmeta.ApplyToRequest(req, metaCfg, values)
	for k, v := range req.Header {
		h[k] = v
	}

	// Internal metadata
	h.Set("X-XHTTP-Packet-Size", strconv.Itoa(cfg.PacketSize) )
	h.Set("X-XHTTP-KeepAlive", cfg.KeepAlive.String())
	
	if cfg.XPadding.Enabled {
		h.Set(cfg.XPadding.GetHeaderName(), cfg.XPadding.GetHeaderValue())
	}

	// Copy back to map
	out := make(map[string]string)
	for k, v := range h {
		out[k] = v[0]
	}
	return out
}

func buildCookies(cfg Config, metaCfg xhttpmeta.MetadataConfig, values xhttpmeta.MetadataValues) []*http.Cookie {
	req, _ := http.NewRequest(http.MethodPost, "http://dummy", nil)
	_ = xhttpmeta.ApplyToRequest(req, metaCfg, values)
	
	cookies := req.Cookies()
	
	// If path or query contains pkt/ka, they are already in the URL
	// If they should be in cookies, we'd need more logic in xhttpmeta
	// For now, let's keep it simple as before for pkt/ka if placement is cookie
	if cfg.MetadataPlacement == PlacementCookie {
		cookies = append(cookies,
			&http.Cookie{Name: "x-pkt", Value: strconv.Itoa(cfg.PacketSize)},
			&http.Cookie{Name: "x-ka", Value: cfg.KeepAlive.String()},
		)
	}
	
	return cookies
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ValidateMode validates mode values supported by this implementation.
func ValidateMode(mode string) error {
	switch Mode(strings.ToLower(strings.TrimSpace(mode))) {
	case ModeStreamOne, ModeStreamUp, ModeStreamDown, ModePacketUp:
		return nil
	default:
		return fmt.Errorf("unsupported xhttp mode: %s", mode)
	}
}

// ValidatePlacement validates metadata placement values.
func ValidatePlacement(placement string) error {
	switch MetadataPlacement(strings.ToLower(strings.TrimSpace(placement))) {
	case PlacementHeader, PlacementPath, PlacementQuery, PlacementCookie, "":
		return nil
	default:
		return fmt.Errorf("unsupported metadata placement: %s", placement)
	}
}
