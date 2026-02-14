package carrier

import (
	"crypto/tls"
	"fmt"
	"sync"

	"stealthlink/internal/config"
	"stealthlink/internal/transport/icmptun"

	"github.com/xtaci/smux"
)

// Registry manages carrier implementations
type Registry struct {
	mu       sync.RWMutex
	carriers map[string]Carrier
}

// DefaultRegistry is the global carrier registry
var DefaultRegistry = NewRegistry()

// NewRegistry creates a new carrier registry
func NewRegistry() *Registry {
	return &Registry{
		carriers: make(map[string]Carrier),
	}
}

// Register registers a carrier implementation
func (r *Registry) Register(name string, carrier Carrier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.carriers[name] = carrier
}

// Get retrieves a carrier by name
func (r *Registry) Get(name string) (Carrier, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.carriers[name]
	return c, ok
}

// Unregister removes a carrier from the registry
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.carriers, name)
}

// AvailableCarriers returns a list of available carrier names
func (r *Registry) AvailableCarriers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name, carrier := range r.carriers {
		if carrier.IsAvailable() {
			names = append(names, name)
		}
	}
	return names
}

// SelectCarrier selects the appropriate carrier based on configuration
func SelectCarrier(cfg config.UQSPCarrierConfig, tlsCfg *tls.Config, smuxCfg *smux.Config, authToken string) (Carrier, error) {
	carrierType := cfg.Type
	if carrierType == "" {
		carrierType = "quic" // Default to native QUIC
	}

	switch carrierType {
	case "quic":
		// Native QUIC - no carrier wrapper needed
		return nil, nil

	case "trusttunnel":
		return NewTrustTunnelCarrier(cfg.TrustTunnel, smuxCfg), nil

	case "rawtcp":
		return NewRawTCPCarrier(cfg.RawTCP.Raw, cfg.RawTCP.KCP, smuxCfg, authToken), nil

	case "faketcp":
		return NewFakeTCPCarrier(cfg.FakeTCP, smuxCfg, authToken), nil
	case "kcp":
		return NewKCPCarrier(cfg.KCP, smuxCfg), nil

	case "icmptun":
		return NewICMPCarrier(cfg.ICMPTun, smuxCfg, authToken), nil

	case "webtunnel":
		wtCfg := WebTunnelConfig{
			Server:                cfg.WebTunnel.Server,
			Path:                  cfg.WebTunnel.Path,
			Version:               cfg.WebTunnel.Version,
			Headers:               cfg.WebTunnel.Headers,
			UserAgent:             cfg.WebTunnel.UserAgent,
			TLSInsecureSkipVerify: cfg.WebTunnel.TLSInsecureSkipVerify,
			TLSServerName:         cfg.WebTunnel.TLSServerName,
			TLSFingerprint:        cfg.WebTunnel.TLSFingerprint,
		}
		return NewWebTunnelCarrier(wtCfg, smuxCfg), nil

	case "chisel":
		chCfg := ChiselConfig{
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
		if authToken != "" {
			if chCfg.Headers == nil {
				chCfg.Headers = map[string]string{}
			}
			chCfg.Headers["X-Stealthlink-Auth"] = authToken
		}
		return NewChiselCarrier(chCfg, smuxCfg), nil

	case "xhttp":
		xhCfg := XHTTPConfig{
			Server:                cfg.XHTTP.Server,
			Path:                  cfg.XHTTP.Path,
			Mode:                  cfg.XHTTP.Mode,
			Headers:               cfg.XHTTP.Headers,
			MaxConns:              cfg.XHTTP.MaxConns,
			TLSInsecureSkipVerify: cfg.XHTTP.TLSInsecureSkipVerify,
			TLSServerName:         cfg.XHTTP.TLSServerName,
			TLSFingerprint:        cfg.XHTTP.TLSFingerprint,
			Metadata: XHTTPMetadataConfig{
				Session: XHTTPMetadataFieldConfig{
					Placement: cfg.XHTTP.Metadata.Session.Placement,
					Key:       cfg.XHTTP.Metadata.Session.Key,
				},
				Seq: XHTTPMetadataFieldConfig{
					Placement: cfg.XHTTP.Metadata.Seq.Placement,
					Key:       cfg.XHTTP.Metadata.Seq.Key,
				},
				Mode: XHTTPMetadataFieldConfig{
					Placement: cfg.XHTTP.Metadata.Mode.Placement,
					Key:       cfg.XHTTP.Metadata.Mode.Key,
				},
			},
			XMux: XMuxConfig{
				Enabled:          cfg.XHTTP.XMux.Enabled,
				MaxConnections:   cfg.XHTTP.XMux.MaxConnections,
				MaxConcurrency:   cfg.XHTTP.XMux.MaxConcurrency,
				MaxConnectionAge: cfg.XHTTP.XMux.MaxConnectionAge,
				CMaxReuseTimes:   cfg.XHTTP.XMux.CMaxReuseTimes,
				HMaxRequestTimes: cfg.XHTTP.XMux.HMaxRequestTimes,
				HMaxReusableSecs: cfg.XHTTP.XMux.HMaxReusableSecs,
				DrainTimeout:     cfg.XHTTP.XMux.DrainTimeout,
			},
		}
		return NewXHTTPCarrier(xhCfg, smuxCfg), nil
	case "anytls":
		c, err := NewAnyTLSCarrier(cfg.AnyTLS, smuxCfg)
		if err != nil {
			return nil, err
		}
		return c, nil
	case "masque":
		return NewMASQUECarrier(cfg.MASQUE, tlsCfg, smuxCfg, authToken), nil

	default:
		return nil, fmt.Errorf("unknown carrier type: %s", carrierType)
	}
}

// IsCarrierAvailable checks if a specific carrier type is available
func IsCarrierAvailable(carrierType string) bool {
	switch carrierType {
	case "quic", "":
		return true // QUIC is always available
	case "trusttunnel":
		return true
	case "rawtcp":
		return IsRawTCPAvailable()
	case "faketcp":
		return true
	case "kcp":
		return true
	case "icmptun":
		return IsICMPTunAvailable()
	case "webtunnel":
		return true
	case "chisel":
		return true
	case "xhttp":
		return true
	case "anytls":
		return true
	case "masque":
		return true
	default:
		return false
	}
}

// SupportsListen reports whether a carrier supports server/listener role.
func SupportsListen(carrierType string) bool {
	switch carrierType {
	case "", "quic", "trusttunnel", "rawtcp", "faketcp", "kcp", "icmptun", "webtunnel", "masque":
		return true
	case "xhttp", "chisel":
		return false
	case "anytls":
		return true
	default:
		return false
	}
}

// SupportsDial reports whether a carrier supports client/dialer role.
func SupportsDial(carrierType string) bool {
	switch carrierType {
	case "", "quic", "trusttunnel", "rawtcp", "faketcp", "kcp", "icmptun", "webtunnel", "xhttp", "chisel", "anytls", "masque":
		return true
	default:
		return false
	}
}

// IsRawTCPAvailable checks if RawTCP is available (requires raw sockets)
func IsRawTCPAvailable() bool {
	// RawTCP requires CAP_NET_RAW or root
	// This is a simplified check - the actual check happens in rawtcp package
	return true // Assume available, actual error occurs at dial time
}

// IsICMPTunAvailable checks if ICMPTun is available (requires raw sockets)
func IsICMPTunAvailable() bool {
	return icmptun.IsAvailable()
}

// CarrierInfo provides information about a carrier
type CarrierInfo struct {
	Name        string
	Network     string
	Available   bool
	Description string
}

// GetCarrierInfo returns information about all carriers
func GetCarrierInfo() []CarrierInfo {
	return []CarrierInfo{
		{
			Name:        "quic",
			Network:     "quic",
			Available:   true,
			Description: "Native QUIC transport (default)",
		},
		{
			Name:        "trusttunnel",
			Network:     "tcp",
			Available:   true,
			Description: "HTTP/1.1, HTTP/2, or HTTP/3 tunnel with obfuscation",
		},
		{
			Name:        "rawtcp",
			Network:     "udp",
			Available:   IsRawTCPAvailable(),
			Description: "Raw TCP packet crafting with KCP (requires CAP_NET_RAW)",
		},
		{
			Name:        "faketcp",
			Network:     "udp",
			Available:   true,
			Description: "TCP-like session semantics over UDP (tcpraw/udp2raw-style)",
		},
		{
			Name:        "icmptun",
			Network:     "icmp",
			Available:   IsICMPTunAvailable(),
			Description: "ICMP echo tunnel with LRU sessions (requires CAP_NET_RAW)",
		},
		{
			Name:        "webtunnel",
			Network:     "tcp",
			Available:   true,
			Description: "HTTP Upgrade/WebSocket tunnel (HTTP/1.1 or HTTP/2)",
		},
		{
			Name:        "chisel",
			Network:     "tcp",
			Available:   true,
			Description: "SSH-over-HTTP CONNECT tunnel",
		},
		{
			Name:        "xhttp",
			Network:     "tcp",
			Available:   true,
			Description: "SplitHTTP/XHTTP transport with request/response splitting",
		},
		{
			Name:        "anytls",
			Network:     "tcp",
			Available:   true,
			Description: "TLS fingerprint-resistant transport with custom padding",
		},
	}
}
