package masque

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"strings"

	"stealthlink/internal/transport/quicmux"

	"github.com/xtaci/smux"
)

// NewDialer creates a transport dialer for MASQUE over QUIC.
//
// The current implementation tunnels StealthLink multiplexing over QUIC while
// carrying MASQUE-mode identity in the guard channel.
func NewDialer(cfg *Config, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string, quicCfg *quicmux.Config) *quicmux.Dialer {
	c := normalizeConfig(cfg)
	q := withMASQUEProfile(quicCfg, c)
	return quicmux.NewDialer(q, tlsCfg, smuxCfg, masqueGuard(guard, c))
}

// Listen creates a transport listener for MASQUE over QUIC.
func Listen(addr string, cfg *Config, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string, quicCfg *quicmux.Config) (*quicmux.Listener, error) {
	c := normalizeConfig(cfg)
	q := withMASQUEProfile(quicCfg, c)
	return quicmux.Listen(addr, q, tlsCfg, smuxCfg, masqueGuard(guard, c))
}

func normalizeConfig(cfg *Config) *Config {
	if cfg == nil {
		cfg = &Config{}
	}
	cp := *cfg
	if strings.TrimSpace(cp.TunnelType) == "" {
		cp.TunnelType = "udp"
	}
	if cp.Headers != nil {
		cp.Headers = cloneHeaders(cp.Headers)
	}
	return &cp
}

func cloneHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

func withMASQUEProfile(base *quicmux.Config, cfg *Config) *quicmux.Config {
	if base == nil {
		base = &quicmux.Config{}
	}
	cp := *base
	if strings.TrimSpace(cp.Masquerade.Type) == "" {
		cp.Masquerade.Type = "http3"
	}
	if strings.TrimSpace(cp.Masquerade.Listen) == "" {
		cp.Masquerade.Listen = cfg.ServerAddr
	}
	if cp.Padding.Min == 0 && cp.Padding.Max == 0 {
		cp.Padding.Min = 16
		cp.Padding.Max = 128
	}
	return &cp
}

func masqueGuard(base string, cfg *Config) string {
	typeID := strings.ToLower(strings.TrimSpace(cfg.TunnelType))
	if typeID == "" {
		typeID = "udp"
	}
	if base == "" {
		base = "sl1"
	}
	return base + "|masque|" + typeID + "|" + tokenDigest(cfg.AuthToken)
}

func tokenDigest(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return "00000000"
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}
