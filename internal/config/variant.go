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

func parseVariantValue(raw string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "0":
		return 0, true
	case "4a", "xhttp-tls", "xhttp_tls":
		return 0, true
	case "1":
		return 1, true
	case "4b", "raw-tcp", "raw_tcp":
		return 1, true
	case "2":
		return 2, true
	case "4c", "tls-mirror", "tls_mirror":
		return 2, true
	case "3":
		return 3, true
	case "4d", "udp":
		return 3, true
	case "4":
		return 4, true
	case "4e", "trust":
		return 4, true
	default:
		return 0, false
	}
}

func (c *Config) selectedVariantRaw() string {
	if v := strings.TrimSpace(c.Variant); v != "" {
		return v
	}
	return strings.TrimSpace(c.Transport.UQSP.VariantProfile)
}

func (c *Config) applyVariantPreset() {
	if !c.UQSPEnabled() {
		return
	}

	variant, ok := parseVariantValue(c.selectedVariantRaw())
	if !ok {
		return
	}

	u := &c.Transport.UQSP
	switch variant {
	case 0: // 4a: XHTTP + gfw_resist_tls + domain fronting + vision + ECH
		// ApplyUQSPDefaults sets carrier.type="quic" as a generic default. For non-4d variants,
		// treat "quic" as "unset" so the variant preset can choose a more appropriate carrier.
		if strings.TrimSpace(u.Carrier.Type) == "" || strings.EqualFold(strings.TrimSpace(u.Carrier.Type), "quic") {
			u.Carrier.Type = "xhttp"
		}
		if strings.TrimSpace(u.Obfuscation.Profile) == "" || strings.EqualFold(strings.TrimSpace(u.Obfuscation.Profile), "none") {
			u.Obfuscation.Profile = "adaptive"
		}
		u.Behaviors.Vision.Enabled = true
		u.Behaviors.Vision.FlowAutoDetect = true
		u.Behaviors.TLSFrag.Enabled = true
		if u.Behaviors.TLSFrag.Strategy == "" {
			u.Behaviors.TLSFrag.Strategy = "sni_split"
		}
	case 1: // 4b: Raw TCP + anti-DPI + obfuscation
		if strings.TrimSpace(u.Carrier.Type) == "" || strings.EqualFold(strings.TrimSpace(u.Carrier.Type), "quic") {
			u.Carrier.Type = "rawtcp"
		}
		if strings.TrimSpace(u.Obfuscation.Profile) == "" || strings.EqualFold(strings.TrimSpace(u.Obfuscation.Profile), "none") {
			u.Obfuscation.Profile = "adaptive"
		}
		u.Obfuscation.MorphingEnabled = true
		u.Behaviors.AWG.Enabled = true
	case 2: // 4c: XHTTP + TLS look-alikes + Vision + ML-DSA-65
		// Allow explicit carrier selection (e.g., AnyTLS) without being overridden by the preset.
		if strings.TrimSpace(u.Carrier.Type) == "" || strings.EqualFold(strings.TrimSpace(u.Carrier.Type), "quic") {
			u.Carrier.Type = "xhttp"
		}
		u.Behaviors.Vision.Enabled = true
		u.Behaviors.Vision.FlowAutoDetect = true
		if !u.Behaviors.Reality.Enabled && !u.Behaviors.ShadowTLS.Enabled && !u.Behaviors.TLSMirror.Enabled {
			u.Behaviors.TLSMirror.Enabled = true
		}
		u.Security.PQKEM = true
	case 3: // 4d: UDP/QUIC + brutal CC + AWG/obfuscation
		if strings.TrimSpace(u.Carrier.Type) == "" {
			u.Carrier.Type = "quic"
		}
		u.Congestion.Algorithm = "brutal"
		if u.Congestion.BandwidthMbps == 0 {
			u.Congestion.BandwidthMbps = 200
		}
		u.Capsules.ConnectUDP = true
		if strings.TrimSpace(u.Obfuscation.Profile) == "" || strings.EqualFold(strings.TrimSpace(u.Obfuscation.Profile), "none") {
			u.Obfuscation.Profile = "adaptive"
		}
		u.Obfuscation.MorphingEnabled = true
		u.Behaviors.AWG.Enabled = true
	case 4: // 4e: TLS-based tunnels + CSTP compatibility
		if strings.TrimSpace(u.Carrier.Type) == "" || strings.TrimSpace(u.Carrier.Type) == "quic" {
			u.Carrier.Type = "trusttunnel"
		}
		u.Behaviors.CSTP.Enabled = true
		u.Behaviors.TLSFrag.Enabled = true
		if u.Behaviors.TLSFrag.Strategy == "" {
			u.Behaviors.TLSFrag.Strategy = "random"
		}
	}
}

func (c *Config) GetVariant() int {
	if explicit, ok := parseVariantValue(c.selectedVariantRaw()); ok {
		return explicit
	}

	behaviors := c.Transport.UQSP.Behaviors

	if behaviors.ECH.Enabled || behaviors.DomainFront.Enabled {
		return 0
	}

	if behaviors.Reality.Enabled || behaviors.ShadowTLS.Enabled || behaviors.TLSMirror.Enabled || behaviors.AnyTLS.Enabled {
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
	case "rawtcp", "faketcp", "icmptun":
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
	if !c.UQSPEnabled() {
		return nil
	}

	if strings.TrimSpace(c.Variant) != "" && strings.TrimSpace(c.Transport.UQSP.VariantProfile) != "" {
		v1, ok1 := parseVariantValue(c.Variant)
		v2, ok2 := parseVariantValue(c.Transport.UQSP.VariantProfile)
		if ok1 && ok2 && v1 != v2 {
			return fmt.Errorf("variant and transport.uqsp.variant_profile conflict: %q vs %q", c.Variant, c.Transport.UQSP.VariantProfile)
		}
	}

	raw := c.selectedVariantRaw()
	variant, ok := parseVariantValue(raw)
	if raw != "" && !ok {
		return fmt.Errorf("variant must be one of: 4a, 4b, 4c, 4d, 4e")
	}
	if !ok {
		variant = c.GetVariant()
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
		seedProvided := strings.TrimSpace(behaviors.Obfs4.Seed) != ""
		if !seedProvided && strings.TrimSpace(behaviors.Obfs4.NodeID) == "" {
			return fmt.Errorf("obfs4.node_id is required when obfs4 is enabled (or set obfs4.seed)")
		}
		if !seedProvided && strings.TrimSpace(behaviors.Obfs4.PublicKey) == "" {
			return fmt.Errorf("obfs4.public_key is required when obfs4 is enabled (or set obfs4.seed)")
		}
	}

	carrierType := c.Transport.UQSP.Carrier.Type
	if carrierType != "rawtcp" && carrierType != "faketcp" && carrierType != "icmptun" && carrierType != "" {
		return fmt.Errorf("raw-tcp variant requires carrier.type to be rawtcp, faketcp, or icmptun, got: %s", carrierType)
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
	if behaviors.AnyTLS.Enabled {
		tlsModes++
		if strings.TrimSpace(behaviors.AnyTLS.Password) == "" {
			return fmt.Errorf("anytls.password is required when AnyTLS is enabled")
		}
	}

	if tlsModes == 0 {
		return fmt.Errorf("tls-mirror variant requires at least one TLS behavior (reality, shadowtls, tlsmirror, or anytls)")
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
		"RawTCP/FakeTCP + KCP/smux + obfs4 + anti-DPI - Low latency, high throughput",
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
