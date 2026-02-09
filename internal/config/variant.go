package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

type VariantConfig struct {
	Variant string `yaml:"variant"`
}

func (c *Config) GetVariant() int {
	behaviors := c.Transport.UQSP.Behaviors

	if behaviors.ECH.Enabled || behaviors.DomainFront.Enabled {
		return 0
	}

	if behaviors.Reality.Enabled || behaviors.ShadowTLS.Enabled || behaviors.TLSMirror.Enabled {
		return 2
	}

	if behaviors.Obfs4.Enabled {
		return 1
	}

	if behaviors.AWG.Enabled || c.Transport.UQSP.Obfuscation.Profile == "salamander" {
		return 3
	}

	carrierType := c.Transport.UQSP.Carrier.Type
	switch carrierType {
	case "xhttp":
		return 0
	case "rawtcp", "icmptun":
		return 1
	case "webtunnel", "chisel", "trusttunnel":
		return 4
	case "quic", "":
		return 3
	default:
		return 3
	}
}

func (c *Config) ValidateVariant() error {
	variant := c.GetVariant()

	if !c.UQSPEnabled() {
		return nil
	}

	switch variant {
	case 0:
		return c.validateVariantXHTTPTLS()
	case 1:
		return c.validateVariantRawTCP()
	case 2:
		return c.validateVariantTLSMirror()
	case 3:
		return c.validateVariantUDP()
	case 4:
		return c.validateVariantTrust()
	default:
		return fmt.Errorf("unknown variant: %d", variant)
	}
}

func (c *Config) validateVariantXHTTPTLS() error {
	behaviors := c.Transport.UQSP.Behaviors

	if behaviors.ECH.Enabled {
		if behaviors.ECH.PublicName == "" {
			return fmt.Errorf("ech.public_name is required when ECH is enabled")
		}
	}

	if behaviors.DomainFront.Enabled {
		if behaviors.DomainFront.FrontDomain == "" {
			return fmt.Errorf("domainfront.front_domain is required when domain fronting is enabled")
		}
		if behaviors.DomainFront.RealHost == "" {
			return fmt.Errorf("domainfront.real_host is required when domain fronting is enabled")
		}
	}

	return nil
}

func (c *Config) validateVariantRawTCP() error {
	behaviors := c.Transport.UQSP.Behaviors

	if behaviors.Obfs4.Enabled {
		if behaviors.Obfs4.NodeID == "" {
			return fmt.Errorf("obfs4.node_id is required when obfs4 is enabled")
		}
		if behaviors.Obfs4.PublicKey == "" {
			return fmt.Errorf("obfs4.public_key is required when obfs4 is enabled")
		}
	}

	carrierType := c.Transport.UQSP.Carrier.Type
	if carrierType != "rawtcp" && carrierType != "icmptun" && carrierType != "" {
		return fmt.Errorf("raw-tcp variant requires carrier.type to be rawtcp or icmptun, got: %s", carrierType)
	}

	return nil
}

func (c *Config) validateVariantTLSMirror() error {
	behaviors := c.Transport.UQSP.Behaviors

	tlsModes := 0
	if behaviors.Reality.Enabled {
		tlsModes++
		if behaviors.Reality.PrivateKey == "" {
			return fmt.Errorf("reality.private_key is required when REALITY is enabled")
		}
		if behaviors.Reality.Dest == "" {
			return fmt.Errorf("reality.dest is required when REALITY is enabled")
		}
		if behaviors.Reality.ServerPublicKey != "" {
			decoded, err := decodeKey32(behaviors.Reality.ServerPublicKey)
			if err != nil {
				return fmt.Errorf("reality.server_public_key must be base64 or hex encoded 32 bytes: %w", err)
			}
			if len(decoded) != 32 {
				return fmt.Errorf("reality.server_public_key must decode to 32 bytes")
			}
		}
	}
	if behaviors.ShadowTLS.Enabled {
		tlsModes++
		if behaviors.ShadowTLS.Password == "" {
			return fmt.Errorf("shadowtls.password is required when ShadowTLS is enabled")
		}
	}
	if behaviors.TLSMirror.Enabled {
		tlsModes++
	}

	if tlsModes == 0 {
		return fmt.Errorf("tls-mirror variant requires at least one TLS behavior (reality, shadowtls, or tlsmirror)")
	}

	if c.Transport.UQSP.Security.PQKEM {
		if c.Role == "gateway" {
		}
	}

	return nil
}

func decodeKey32(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("empty key")
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil {
		return b, nil
	}
	if b, err := hex.DecodeString(v); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("invalid key encoding")
}

func (c *Config) validateVariantUDP() error {
	obfs := c.Transport.UQSP.Obfuscation

	if obfs.Profile == "salamander" && obfs.SalamanderKey == "" {
		return fmt.Errorf("obfuscation.salamander_key is required when profile=salamander")
	}

	cong := c.Transport.UQSP.Congestion
	if cong.Algorithm == "brutal" && cong.BandwidthMbps <= 0 {
		return fmt.Errorf("congestion.bandwidth_mbps must be > 0 when using brutal congestion control")
	}

	return nil
}

func (c *Config) validateVariantTrust() error {
	carrierType := c.Transport.UQSP.Carrier.Type
	if carrierType != "webtunnel" && carrierType != "chisel" && carrierType != "trusttunnel" && carrierType != "" {
		return fmt.Errorf("trust variant requires carrier.type to be webtunnel, chisel, or trusttunnel, got: %s", carrierType)
	}

	return nil
}

func (c *Config) VariantName() string {
	variant := c.GetVariant()
	names := []string{"xhttp-tls", "raw-tcp", "tls-mirror", "udp", "trust"}
	if variant >= 0 && variant < len(names) {
		return names[variant]
	}
	return "unknown"
}

func (c *Config) VariantDescription() string {
	variant := c.GetVariant()
	descs := []string{
		"XHTTP + TLS + Domain Fronting + XTLS Vision + ECH - Maximum stealth with CDN cover",
		"Raw TCP + KCP + smux + obfs4 - Low latency, high throughput",
		"REALITY/ShadowTLS + XTLS Vision + PQ signatures - TLS fingerprint resistance",
		"QUIC/UDP + Hysteria2 CC + AmneziaWG - UDP-based with anti-DPI",
		"TrustTunnel + HTTP/2 + HTTP/3 - HTTP-constrained environments",
	}
	if variant >= 0 && variant < len(descs) {
		return descs[variant]
	}
	return "Unknown variant"
}

func (c *Config) IsReverseModeEnabled() bool {
	return c.Transport.UQSP.Reverse.Enabled
}

func (c *Config) GetReverseRole() string {
	if !c.Transport.UQSP.Reverse.Enabled {
		return ""
	}
	role := strings.TrimSpace(c.Transport.UQSP.Reverse.Role)
	if role == "" {
		if c.Role == "gateway" {
			return "dialer"
		}
		return "listener"
	}
	return role
}

func (c *Config) GetReverseClientAddress() string {
	return c.Transport.UQSP.Reverse.ClientAddress
}

func (c *Config) GetReverseServerAddress() string {
	return c.Transport.UQSP.Reverse.ServerAddress
}

func (c *Config) GetReverseAuthToken() string {
	return c.Transport.UQSP.Reverse.AuthToken
}

func RecommendedVariantForScenario(scenario string) int {
	switch scenario {
	case "cdn", "domain_front", "cloudflare":
		return 0
	case "low_latency", "gaming", "realtime":
		return 1
	case "tls_mimic", "fingerprint_resistance":
		return 2
	case "udp", "quic", "hysteria":
		return 3
	case "http_compatible", "corporate":
		return 4
	default:
		return 3
	}
}

func VariantNames() []string {
	return []string{"xhttp-tls", "raw-tcp", "tls-mirror", "udp", "trust"}
}
