// Package xhttp implements XHTTP (SplitHTTP) transport for StealthLink.
//
// This implementation maps XHTTP profiles onto a hardened HTTP/2 stream tunnel,
// while preserving XHTTP-specific shaping headers and config surfaces.
package xhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"stealthlink/internal/transport"
	"stealthlink/internal/transport/h2mux"
	"stealthlink/internal/transport/padding"

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

// Config configures XHTTP transport.
type Config struct {
	Mode           Mode                   `yaml:"mode"`
	Path           string                 `yaml:"path"`
	Headers        map[string]string      `yaml:"headers"`
	XPadding       padding.XPaddingConfig `yaml:"xpadding"`
	MaxConnections int                    `yaml:"max_connections"`
	PacketSize     int                    `yaml:"packet_size"`
	KeepAlive      time.Duration          `yaml:"keep_alive"`
	XMux           XMuxConfig             `yaml:"xmux"`
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
	url := buildURL(addr, cfg.Path)
	base := h2mux.NewDialer(url, d.tlsConfig, d.smuxConfig, d.fingerprint, firstNonEmpty(d.connectAddr, addr), d.guard)
	base.Headers = buildHeaders(cfg)
	base.ProxyDial = d.proxyDial
	return base.Dial(ctx, addr)
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

	cfg := d.config
	cfg.ApplyDefaults()

	url := buildURL(addr, cfg.Path)
	base := h2mux.NewDialer(url, d.tlsConfig, d.smuxConfig, d.fingerprint, firstNonEmpty(d.connectAddr, addr), d.guard)
	base.Headers = buildHeaders(cfg)
	base.ProxyDial = d.proxyDial
	return base.Dial(ctx, addr)
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

	return h2mux.Listen(addr, config.Path, tlsConfig, smuxCfg, guard, padMin, padMax)
}

// GenerateRandomPath generates a random path token.
func GenerateRandomPath(prefix string, length int) string {
	if length <= 0 {
		length = 8
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	seed := time.Now().UnixNano()
	for i := range b {
		seed = seed*1664525 + 1013904223
		if seed < 0 {
			seed = -seed
		}
		b[i] = chars[seed%int64(len(chars))]
	}
	return strings.TrimSuffix(prefix, "/") + "/" + string(b)
}

func buildHeaders(cfg Config) map[string]string {
	headers := make(map[string]string, len(cfg.Headers)+5)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["X-XHTTP-Mode"] = string(cfg.Mode)
	headers["X-XHTTP-Packet-Size"] = strconv.Itoa(cfg.PacketSize)
	headers["X-XHTTP-KeepAlive"] = cfg.KeepAlive.String()
	if cfg.XPadding.Enabled {
		headers[cfg.XPadding.GetHeaderName()] = cfg.XPadding.GetHeaderValue()
	}
	return headers
}

func buildURL(addr, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/_sl"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "https://" + addr + path
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
