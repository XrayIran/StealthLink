package tlsmirror

import (
	"context"
	"errors"
	"net"
	"strings"

	"stealthlink/internal/tlsutil"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/tlsmux"
)

// Config controls TLSMirror enrollment behavior.
type Config struct {
	Enabled            bool
	ControlChannel     string
	EnrollmentRequired bool
	AntiLoopback       bool
}

// Dialer wraps a TLS mux dialer with mirror enrollment and cache application.
type Dialer struct {
	base        *tlsmux.Dialer
	cache       *tlsutil.MirrorCache
	serverName  string
	fingerprint string
	config      Config
}

func NewDialer(base *tlsmux.Dialer, cfg Config, serverName, fingerprint string) *Dialer {
	if cfg.ControlChannel == "" {
		cfg.ControlChannel = "/_tlsmirror"
	}
	if !cfg.AntiLoopback {
		cfg.AntiLoopback = true
	}
	return &Dialer{
		base:        base,
		cache:       tlsutil.NewMirrorCache(),
		serverName:  serverName,
		fingerprint: fingerprint,
		config:      cfg,
	}
}

func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	host := firstNonEmpty(d.serverName, hostOnly(addr))
	if host != "" && !d.shouldSkipEnrollment(host) {
		state, err := d.cache.Refresh(host, d.fingerprint)
		if err != nil {
			if d.config.EnrollmentRequired {
				return nil, err
			}
		} else if state != nil {
			cfg := d.base.TLSConfig.Clone()
			state.ApplyToConfig(cfg)
			d.base.TLSConfig = cfg
		}
	}
	return d.base.Dial(ctx, addr)
}

func (d *Dialer) shouldSkipEnrollment(host string) bool {
	if !d.config.Enabled {
		return true
	}
	if !d.config.AntiLoopback {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err == nil {
		return h
	}
	return strings.TrimSpace(addr)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

var ErrEnrollmentRequired = errors.New("tlsmirror enrollment required")
