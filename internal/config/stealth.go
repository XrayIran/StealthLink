package config

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"time"
)

const (
	StealthModeTLS  = "tls"
	StealthModeNone = "none"

	StealthProfilePlainTLS   = "plain-tls"
	StealthProfileHTTPSWSS   = "https-websocket"
	StealthProfileHTTPSH2    = "https-h2"
	StealthProfileHTTPSSplit = "https-splithttp"
	StealthProfileReality    = "reality"
	StealthProfileShadowTLS  = "shadowtls"
	StealthProfileTLSMirror  = "tlsmirror"
)

var removedTransportBlocks = map[string]string{
	"tls":         "transport.stealth.camouflage.tls_shape",
	"wss":         "transport.stealth.camouflage.http_cover",
	"h2":          "transport.stealth.camouflage.http_cover",
	"xhttp":       "transport.stealth.camouflage.http_cover",
	"reality":     "transport.stealth.camouflage.reality",
	"shadowtls":   "transport.stealth.camouflage.shadowtls",
	"tlsmirror":   "transport.stealth.camouflage.tlsmirror",
	"quic":        "transport.stealth.carrier.quic",
	"masque":      "transport.stealth.carrier.masque",
	"dtls":        "transport.stealth.carrier.dtls",
	"kcp":         "transport.stealth.carrier.kcp",
	"rawtcp":      "transport.stealth.carrier.raw.tcp",
	"raw_adapter": "transport.stealth.carrier.raw",
	"auto":        "transport.stealth.selection",
}

type StealthConfig struct {
	Carrier     StealthCarrierConfig     `yaml:"carrier"`
	Camouflage  StealthCamouflageConfig  `yaml:"camouflage"`
	Shaping     StealthShapingConfig     `yaml:"shaping"`
	Selection   StealthSelectionConfig   `yaml:"selection"`
	Performance StealthPerformanceConfig `yaml:"performance"`
	Security    StealthSecurityConfig    `yaml:"security"`
	Session     StealthSessionConfig     `yaml:"session"`
}

type StealthCarrierConfig struct {
	Kind   string           `yaml:"kind"` // tcp, quic, masque, dtls, kcp, awg, raw
	QUIC   QUICConfig       `yaml:"quic"`
	MASQUE MASQUEConfig     `yaml:"masque"`
	DTLS   DTLSConfig       `yaml:"dtls"`
	KCP    KCPConfig        `yaml:"kcp"`
	AWG    AWGObfsConfig    `yaml:"awg"`
	Raw    StealthRawConfig `yaml:"raw"`
}

type StealthRawConfig struct {
	Mode       string                     `yaml:"mode"` // tcp, fake_tcp, icmp, dns, udp_over_tcp
	TCP        RawTCPConfig               `yaml:"tcp"`
	DNS        StealthRawDNSConfig        `yaml:"dns"`
	UDPOverTCP StealthRawUDPOverTCPConfig `yaml:"udp_over_tcp"`
}

type StealthRawDNSConfig struct {
	Domain       string `yaml:"domain"`
	ServerAddr   string `yaml:"server_addr"`
	QueryType    string `yaml:"query_type"`
	MaxUDPPacket int    `yaml:"max_udp_packet"`
	Retries      int    `yaml:"retries"`
	Timeout      string `yaml:"timeout"`
	Encoder      string `yaml:"encoder"`
}

type StealthRawUDPOverTCPConfig struct {
	BufferSize int    `yaml:"buffer_size"`
	Timeout    string `yaml:"timeout"`
}

type StealthCamouflageConfig struct {
	Mode      string                 `yaml:"mode"` // tls, none
	Profile   string                 `yaml:"profile"`
	TLS       TLSConfig              `yaml:"tls"`
	TLSShape  StealthTLSShapeConfig  `yaml:"tls_shape"`
	HTTPCover StealthHTTPCoverConfig `yaml:"http_cover"`
	WSS       WSSConfig              `yaml:"wss"`   // deprecated, blocked at top-level transport.wss
	H2        H2Config               `yaml:"h2"`    // deprecated, blocked at top-level transport.h2
	XHTTP     XHTTPConfig            `yaml:"xhttp"` // deprecated, blocked at top-level transport.xhttp
	ShadowTLS ShadowTLSConfig        `yaml:"shadowtls"`
	Reality   RealityConfig          `yaml:"reality"`
	TLSMirror TLSMirrorConfig        `yaml:"tlsmirror"`
}

type StealthTLSShapeConfig struct {
	Fingerprint string                 `yaml:"fingerprint"`
	Fragment    TLSFragmentConfig      `yaml:"fragment"`
	SNIBlend    SNIBlendConfig         `yaml:"sni_blend"`
	Handshake   HandshakePaddingConfig `yaml:"handshake_pad"`
}

type StealthHTTPCoverConfig struct {
	Path           string            `yaml:"path"`
	Origin         string            `yaml:"origin"`
	Headers        map[string]string `yaml:"headers"`
	PadMin         int               `yaml:"pad_min"`
	PadMax         int               `yaml:"pad_max"`
	XPad           XPaddingConfig    `yaml:"xpad"`
	UserAgent      string            `yaml:"user_agent"`
	UARotation     bool              `yaml:"ua_rotation"`
	UAMode         string            `yaml:"ua_mode"`
	CustomUAList   []string          `yaml:"custom_ua_list"`
	MaxConnections int               `yaml:"max_connections"`
	PacketSize     int               `yaml:"packet_size"`
	KeepAlive      string            `yaml:"keep_alive"`
}

type StealthShapingConfig struct {
	Noize      NoizeConfig            `yaml:"noize"`
	Obfs       ObfsConfig             `yaml:"obfs"`
	QPP        QPPConfig              `yaml:"qpp"`
	HalfDuplex HalfDuplexConfig       `yaml:"halfduplex"`
	Handshake  HandshakePaddingConfig `yaml:"handshake_pad"`
}

type StealthSelectionConfig struct {
	FallbackProfiles []string `yaml:"fallback_profiles"`
	ProbeTimeout     string   `yaml:"probe_timeout"`
}

type StealthPerformanceConfig struct {
	TFO  TFOConfig             `yaml:"tfo"`
	TCP  TCPOptimizationConfig `yaml:"tcp"`
	DSCP DSCPConfig            `yaml:"dscp"`
}

type StealthSecurityConfig struct {
	Guard string `yaml:"guard"`
}

type StealthSessionConfig struct {
	MaxStreamsPerSession  int    `yaml:"max_streams_per_session"`
	MaxStreamsTotal       int    `yaml:"max_streams_total"`
	HeaderTimeout         string `yaml:"header_timeout"`
	SmuxKeepAliveInterval string `yaml:"smux_keepalive_interval"`
	SmuxKeepAliveTimeout  string `yaml:"smux_keepalive_timeout"`
	MaxStreamBuffer       int    `yaml:"max_stream_buffer"`
	MaxReceiveBuffer      int    `yaml:"max_receive_buffer"`
}

func (c *Config) StealthCarrierKind() string {
	kind := strings.ToLower(strings.TrimSpace(c.Transport.Stealth.Carrier.Kind))
	if kind == "" {
		return "tcp"
	}
	return kind
}

func (c *Config) StealthCamouflageProfile() string {
	profile := strings.ToLower(strings.TrimSpace(c.Transport.Stealth.Camouflage.Profile))
	if profile == "" {
		return StealthProfileHTTPSWSS
	}
	return profile
}

func (c *Config) StealthGuard() string {
	guard := strings.TrimSpace(c.Transport.Stealth.Security.Guard)
	if guard != "" {
		return guard
	}
	guard = strings.TrimSpace(c.Transport.Guard)
	if guard != "" {
		return guard
	}
	return "sl1"
}

func (c *Config) applyStealthDefaults() {
	s := &c.Transport.Stealth
	if s.Carrier.Kind == "" {
		s.Carrier.Kind = "tcp"
	}
	if s.Camouflage.Mode == "" {
		s.Camouflage.Mode = StealthModeTLS
	}
	if s.Camouflage.Profile == "" {
		s.Camouflage.Profile = StealthProfileHTTPSWSS
	}

	if isZero(s.Camouflage.TLSShape) {
		s.Camouflage.TLSShape = StealthTLSShapeConfig{}
	}
	if s.Camouflage.TLSShape.Fingerprint == "" {
		s.Camouflage.TLSShape.Fingerprint = "chrome"
	}

	if isZero(s.Camouflage.HTTPCover) {
		s.Camouflage.HTTPCover = StealthHTTPCoverConfig{
			Path: "/_sl",
		}
	}
	if s.Camouflage.HTTPCover.Path == "" {
		s.Camouflage.HTTPCover.Path = "/_sl"
	}
	if s.Camouflage.HTTPCover.MaxConnections <= 0 {
		s.Camouflage.HTTPCover.MaxConnections = 2
	}
	if s.Camouflage.HTTPCover.PacketSize <= 0 {
		s.Camouflage.HTTPCover.PacketSize = 1024
	}
	if s.Camouflage.HTTPCover.KeepAlive == "" {
		s.Camouflage.HTTPCover.KeepAlive = "30s"
	}
	if s.Camouflage.HTTPCover.PadMax > 0 && s.Camouflage.HTTPCover.PadMin > s.Camouflage.HTTPCover.PadMax {
		s.Camouflage.HTTPCover.PadMin = s.Camouflage.HTTPCover.PadMax
	}
	if s.Camouflage.ShadowTLS.Version == 0 {
		s.Camouflage.ShadowTLS.Version = 3
	}
	if s.Camouflage.ShadowTLS.WildcardSNIMode == "" {
		s.Camouflage.ShadowTLS.WildcardSNIMode = "off"
	}
	if s.Camouflage.TLSMirror.Enabled {
		if s.Camouflage.TLSMirror.ControlChannel == "" {
			s.Camouflage.TLSMirror.ControlChannel = "/_tlsmirror"
		}
		if !s.Camouflage.TLSMirror.AntiLoopback {
			s.Camouflage.TLSMirror.AntiLoopback = true
		}
	}

	// Keep compatibility for in-repo consumers that still read legacy nested camouflage blocks.
	s.Camouflage.TLS.Fingerprint = s.Camouflage.TLSShape.Fingerprint
	s.Camouflage.TLS.Fragment = s.Camouflage.TLSShape.Fragment
	s.Camouflage.TLS.SNIBlend = s.Camouflage.TLSShape.SNIBlend
	s.Camouflage.TLS.HandshakePad = s.Camouflage.TLSShape.Handshake
	s.Camouflage.WSS.Path = s.Camouflage.HTTPCover.Path
	s.Camouflage.WSS.Origin = s.Camouflage.HTTPCover.Origin
	s.Camouflage.WSS.Headers = cloneStringMap(s.Camouflage.HTTPCover.Headers)
	s.Camouflage.WSS.PadMin = s.Camouflage.HTTPCover.PadMin
	s.Camouflage.WSS.PadMax = s.Camouflage.HTTPCover.PadMax
	s.Camouflage.WSS.XPad = s.Camouflage.HTTPCover.XPad
	s.Camouflage.WSS.UserAgent = s.Camouflage.HTTPCover.UserAgent
	s.Camouflage.WSS.UARotation = s.Camouflage.HTTPCover.UARotation
	s.Camouflage.WSS.UAMode = s.Camouflage.HTTPCover.UAMode
	s.Camouflage.WSS.CustomUAList = append([]string(nil), s.Camouflage.HTTPCover.CustomUAList...)
	s.Camouflage.H2.Path = s.Camouflage.HTTPCover.Path
	s.Camouflage.H2.Headers = cloneStringMap(s.Camouflage.HTTPCover.Headers)
	s.Camouflage.H2.PadMin = s.Camouflage.HTTPCover.PadMin
	s.Camouflage.H2.PadMax = s.Camouflage.HTTPCover.PadMax
	s.Camouflage.H2.XPad = s.Camouflage.HTTPCover.XPad
	s.Camouflage.XHTTP.Path = s.Camouflage.HTTPCover.Path
	s.Camouflage.XHTTP.Headers = cloneStringMap(s.Camouflage.HTTPCover.Headers)
	s.Camouflage.XHTTP.XPad = s.Camouflage.HTTPCover.XPad
	s.Camouflage.XHTTP.MaxConnections = s.Camouflage.HTTPCover.MaxConnections
	s.Camouflage.XHTTP.PacketSize = s.Camouflage.HTTPCover.PacketSize
	s.Camouflage.XHTTP.KeepAlive = s.Camouflage.HTTPCover.KeepAlive

	if s.Carrier.DTLS.HandshakeTimeout == "" {
		s.Carrier.DTLS.HandshakeTimeout = "10s"
	}
	if s.Carrier.QUIC.HandshakeTimeout == "" {
		s.Carrier.QUIC.HandshakeTimeout = "8s"
	}
	if s.Carrier.QUIC.MaxIdleTimeout == "" {
		s.Carrier.QUIC.MaxIdleTimeout = "45s"
	}
	if s.Carrier.QUIC.KeepAlivePeriod == "" {
		s.Carrier.QUIC.KeepAlivePeriod = "15s"
	}
	if s.Carrier.MASQUE.TunnelType == "" {
		s.Carrier.MASQUE.TunnelType = "udp"
	}
	if s.Carrier.KCP.Block == "" {
		s.Carrier.KCP.Block = "aes"
	}
	if s.Carrier.KCP.PacketGuardMagic == "" {
		s.Carrier.KCP.PacketGuardMagic = "PQT1"
	}
	if s.Carrier.KCP.PacketGuardWindow == 0 {
		s.Carrier.KCP.PacketGuardWindow = 30
	}
	if s.Carrier.KCP.PacketGuardSkew == 0 {
		s.Carrier.KCP.PacketGuardSkew = 1
	}
	if s.Carrier.KCP.MTU == 0 {
		s.Carrier.KCP.MTU = 1350
	}
	if s.Carrier.KCP.SndWnd == 0 {
		s.Carrier.KCP.SndWnd = 1024
	}
	if s.Carrier.KCP.RcvWnd == 0 {
		s.Carrier.KCP.RcvWnd = 1024
	}

	if strings.TrimSpace(s.Carrier.Raw.Mode) == "" {
		s.Carrier.Raw.Mode = "tcp"
	}
	if s.Carrier.AWG.ProtocolVer == 0 {
		s.Carrier.AWG.ProtocolVer = 2
	}
	if strings.TrimSpace(s.Carrier.AWG.JunkInterval) == "" {
		s.Carrier.AWG.JunkInterval = "5s"
	}
	s.Carrier.Raw.TCP.applyDefaults(c.Role)
	if s.Carrier.Raw.DNS.MaxUDPPacket <= 0 {
		s.Carrier.Raw.DNS.MaxUDPPacket = 512
	}
	if s.Carrier.Raw.DNS.Retries <= 0 {
		s.Carrier.Raw.DNS.Retries = 3
	}
	if s.Carrier.Raw.DNS.QueryType == "" {
		s.Carrier.Raw.DNS.QueryType = "TXT"
	}
	if s.Carrier.Raw.DNS.Encoder == "" {
		s.Carrier.Raw.DNS.Encoder = "base32"
	}
	if s.Carrier.Raw.DNS.Timeout == "" {
		s.Carrier.Raw.DNS.Timeout = "5s"
	}
	if s.Carrier.Raw.UDPOverTCP.BufferSize <= 0 {
		s.Carrier.Raw.UDPOverTCP.BufferSize = 65535
	}
	if s.Carrier.Raw.UDPOverTCP.Timeout == "" {
		s.Carrier.Raw.UDPOverTCP.Timeout = "30s"
	}

	if s.Selection.ProbeTimeout == "" {
		s.Selection.ProbeTimeout = "4s"
	}

	if s.Security.Guard == "" {
		s.Security.Guard = "sl1"
	}
	c.Transport.Guard = s.Security.Guard

	if s.Shaping.Noize.Enabled {
		if s.Shaping.Noize.BurstPackets <= 0 {
			s.Shaping.Noize.BurstPackets = 1
		}
		if s.Shaping.Noize.BurstInterval <= 0 {
			s.Shaping.Noize.BurstInterval = s.Shaping.Noize.JunkInterval
		}
		if s.Shaping.Noize.MaxJunkPercent <= 0 {
			s.Shaping.Noize.MaxJunkPercent = 30
		}
		if s.Shaping.Noize.MaxJunkPercent > 95 {
			s.Shaping.Noize.MaxJunkPercent = 95
		}
	}

	if s.Session.MaxStreamsPerSession <= 0 {
		s.Session.MaxStreamsPerSession = c.Mux.MaxStreamsPerSession
	}
	if s.Session.MaxStreamsTotal <= 0 {
		s.Session.MaxStreamsTotal = c.Mux.MaxStreamsTotal
	}
	if s.Session.HeaderTimeout == "" {
		s.Session.HeaderTimeout = c.Mux.HeaderTimeout
	}
	if s.Session.SmuxKeepAliveInterval == "" {
		s.Session.SmuxKeepAliveInterval = c.Mux.SmuxKeepAliveInterval
	}
	if s.Session.SmuxKeepAliveTimeout == "" {
		s.Session.SmuxKeepAliveTimeout = c.Mux.SmuxKeepAliveTimeout
	}
	if s.Session.MaxStreamBuffer == 0 {
		s.Session.MaxStreamBuffer = c.Mux.MaxStreamBuffer
	}
	if s.Session.MaxReceiveBuffer == 0 {
		s.Session.MaxReceiveBuffer = c.Mux.MaxReceiveBuffer
	}

	c.Mux.MaxStreamsPerSession = s.Session.MaxStreamsPerSession
	c.Mux.MaxStreamsTotal = s.Session.MaxStreamsTotal
	c.Mux.HeaderTimeout = s.Session.HeaderTimeout
	c.Mux.SmuxKeepAliveInterval = s.Session.SmuxKeepAliveInterval
	c.Mux.SmuxKeepAliveTimeout = s.Session.SmuxKeepAliveTimeout
	c.Mux.MaxStreamBuffer = s.Session.MaxStreamBuffer
	c.Mux.MaxReceiveBuffer = s.Session.MaxReceiveBuffer
}

// validateStealthLegacy provides helpful error messages for legacy stealth configs.
// This is called to detect and reject old transport.stealth configurations.
func (c *Config) validateStealthLegacy() error {
	// Check if any legacy stealth carrier configuration is present
	s := &c.Transport.Stealth

	// If carrier kind is set to anything other than empty/default, reject it
	kind := strings.ToLower(strings.TrimSpace(s.Carrier.Kind))
	if kind != "" && kind != "tcp" {
		return fmt.Errorf("transport.stealth.carrier.kind=%s is no longer supported. Use transport.type=uqsp instead. See docs/UQSP_MIGRATION.md for details", kind)
	}

	// Check for legacy camouflage profiles that are now handled by UQSP
	profile := strings.ToLower(strings.TrimSpace(s.Camouflage.Profile))
	if profile != "" && profile != StealthProfileHTTPSWSS {
		// If they have a non-default profile, they were using stealth features
		// Only warn if they have other stealth settings configured
		if s.Camouflage.Mode != "" || s.Carrier.Kind != "" {
			return fmt.Errorf("transport.stealth.camouflage.profile=%s is no longer supported. Use transport.type=uqsp instead. See docs/UQSP_MIGRATION.md for details", profile)
		}
	}

	return nil
}

// validateStealth is kept for backwards compatibility but now returns errors
// directing users to migrate to UQSP.
// Deprecated: Use ValidateUQSP instead.
func (c *Config) validateStealth() error {
	mode := strings.ToLower(strings.TrimSpace(c.Transport.Stealth.Camouflage.Mode))
	switch mode {
	case StealthModeTLS, StealthModeNone:
	default:
		return fmt.Errorf("transport.stealth.camouflage.mode must be one of: tls, none")
	}

	profile := c.StealthCamouflageProfile()
	switch profile {
	case StealthProfilePlainTLS, StealthProfileHTTPSWSS, StealthProfileHTTPSH2, StealthProfileHTTPSSplit, StealthProfileReality, StealthProfileShadowTLS, StealthProfileTLSMirror:
	default:
		return fmt.Errorf("transport.stealth.camouflage.profile must be one of: plain-tls, https-websocket, https-h2, https-splithttp, reality, shadowtls, tlsmirror")
	}

	kind := c.StealthCarrierKind()
	switch kind {
	case "tcp", "quic", "masque", "dtls", "kcp", "awg", "raw":
	default:
		return fmt.Errorf("transport.stealth.carrier.kind must be one of: tcp, quic, masque, dtls, kcp, awg, raw")
	}

	if kind != "tcp" && mode == StealthModeTLS {
		return fmt.Errorf("transport.stealth.camouflage.mode=tls requires transport.stealth.carrier.kind=tcp")
	}

	if kind == "tcp" && mode == StealthModeTLS {
		if profile == StealthProfileHTTPSWSS && !strings.HasPrefix(c.Transport.Stealth.Camouflage.HTTPCover.Path, "/") {
			return fmt.Errorf("transport.stealth.camouflage.http_cover.path must start with '/'")
		}
		if profile == StealthProfileHTTPSH2 && !strings.HasPrefix(c.Transport.Stealth.Camouflage.HTTPCover.Path, "/") {
			return fmt.Errorf("transport.stealth.camouflage.http_cover.path must start with '/'")
		}
		if profile == StealthProfileHTTPSSplit {
			if !strings.HasPrefix(c.Transport.Stealth.Camouflage.HTTPCover.Path, "/") {
				return fmt.Errorf("transport.stealth.camouflage.http_cover.path must start with '/'")
			}
			if c.Transport.Stealth.Camouflage.HTTPCover.KeepAlive != "" {
				if _, err := time.ParseDuration(c.Transport.Stealth.Camouflage.HTTPCover.KeepAlive); err != nil {
					return fmt.Errorf("transport.stealth.camouflage.http_cover.keep_alive invalid: %w", err)
				}
			}
		}
		if profile == StealthProfileShadowTLS {
			st := c.Transport.Stealth.Camouflage.ShadowTLS
			if strings.TrimSpace(st.Password) == "" {
				return fmt.Errorf("transport.stealth.camouflage.shadowtls.password is required")
			}
			dest := strings.TrimSpace(st.HandshakeDest)
			if dest == "" {
				dest = strings.TrimSpace(c.Transport.Stealth.Camouflage.TLS.ServerName)
			}
			if dest == "" {
				return fmt.Errorf("transport.stealth.camouflage.shadowtls.handshake_dest (or transport.stealth.camouflage.tls.server_name) is required")
			}
			switch st.WildcardSNIMode {
			case "off", "authed", "all":
			default:
				return fmt.Errorf("transport.stealth.camouflage.shadowtls.wildcard_sni_mode must be one of: off, authed, all")
			}
		}
		if profile == StealthProfileReality {
			rl := c.Transport.Stealth.Camouflage.Reality
			if strings.TrimSpace(rl.PrivateKey) == "" {
				return fmt.Errorf("transport.stealth.camouflage.reality.private_key is required")
			}
			if strings.TrimSpace(rl.Dest) == "" && strings.TrimSpace(c.Transport.Stealth.Camouflage.TLS.ServerName) == "" {
				return fmt.Errorf("transport.stealth.camouflage.reality.dest (or transport.stealth.camouflage.tls.server_name) is required")
			}
		}
	}

	switch kind {
	case "dtls":
		if strings.TrimSpace(c.Transport.Stealth.Carrier.DTLS.PSK) == "" {
			return fmt.Errorf("transport.stealth.carrier.dtls.psk is required")
		}
	case "kcp":
		if !isValidKCPBlock(c.Transport.Stealth.Carrier.KCP.Block) {
			return fmt.Errorf("transport.stealth.carrier.kcp.block unsupported: %s", c.Transport.Stealth.Carrier.KCP.Block)
		}
		if kcpKeyRequired(c.Transport.Stealth.Carrier.KCP.Block) && c.Transport.Stealth.Carrier.KCP.Key == "" {
			return fmt.Errorf("transport.stealth.carrier.kcp.key is required")
		}
	case "masque":
		switch strings.ToLower(strings.TrimSpace(c.Transport.Stealth.Carrier.MASQUE.TunnelType)) {
		case "", "udp", "tcp", "ip":
		default:
			return fmt.Errorf("transport.stealth.carrier.masque.tunnel_type must be one of: udp, tcp, ip")
		}
	case "awg":
		awg := c.Transport.Stealth.Carrier.AWG
		if strings.TrimSpace(awg.PrivateKey) == "" {
			return fmt.Errorf("transport.stealth.carrier.awg.private_key is required")
		}
		if !isValidBase64Key32(awg.PrivateKey) {
			return fmt.Errorf("transport.stealth.carrier.awg.private_key must be base64-encoded 32 bytes")
		}
		if strings.TrimSpace(awg.PublicKey) == "" {
			return fmt.Errorf("transport.stealth.carrier.awg.public_key is required")
		}
		if !isValidBase64Key32(awg.PublicKey) {
			return fmt.Errorf("transport.stealth.carrier.awg.public_key must be base64-encoded 32 bytes")
		}
		if v := strings.TrimSpace(awg.PeerPublicKey); v != "" && !isValidBase64Key32(v) {
			return fmt.Errorf("transport.stealth.carrier.awg.peer_public_key must be base64-encoded 32 bytes")
		}
		if awg.ProtocolVer < 1 || awg.ProtocolVer > 3 {
			return fmt.Errorf("transport.stealth.carrier.awg.protocol_ver must be one of: 1, 2, 3")
		}
		if v := strings.TrimSpace(awg.JunkInterval); v != "" {
			if _, err := time.ParseDuration(v); err != nil {
				return fmt.Errorf("transport.stealth.carrier.awg.junk_interval invalid: %w", err)
			}
		}
	case "raw":
		rawMode := strings.ToLower(strings.TrimSpace(c.Transport.Stealth.Carrier.Raw.Mode))
		switch rawMode {
		case "tcp", "fake_tcp", "icmp", "dns", "udp_over_tcp":
		default:
			return fmt.Errorf("transport.stealth.carrier.raw.mode must be one of: tcp, fake_tcp, icmp, dns, udp_over_tcp")
		}
		if rawMode == "tcp" {
			if !isValidKCPBlock(c.Transport.Stealth.Carrier.KCP.Block) {
				return fmt.Errorf("transport.stealth.carrier.kcp.block unsupported: %s", c.Transport.Stealth.Carrier.KCP.Block)
			}
			if kcpKeyRequired(c.Transport.Stealth.Carrier.KCP.Block) && c.Transport.Stealth.Carrier.KCP.Key == "" {
				return fmt.Errorf("transport.stealth.carrier.kcp.key is required")
			}
			if err := c.Transport.Stealth.Carrier.Raw.TCP.validate(c.Role, c.Gateway.Listen); err != nil {
				return err
			}
		}
		if rawMode == "dns" {
			if _, err := time.ParseDuration(c.Transport.Stealth.Carrier.Raw.DNS.Timeout); err != nil {
				return fmt.Errorf("transport.stealth.carrier.raw.dns.timeout invalid: %w", err)
			}
		}
		if rawMode == "udp_over_tcp" {
			if _, err := time.ParseDuration(c.Transport.Stealth.Carrier.Raw.UDPOverTCP.Timeout); err != nil {
				return fmt.Errorf("transport.stealth.carrier.raw.udp_over_tcp.timeout invalid: %w", err)
			}
		}
	}

	for _, p := range c.Transport.Stealth.Selection.FallbackProfiles {
		p = strings.ToLower(strings.TrimSpace(p))
		switch p {
		case StealthProfilePlainTLS, StealthProfileHTTPSWSS, StealthProfileHTTPSH2, StealthProfileHTTPSSplit, StealthProfileReality, StealthProfileShadowTLS, StealthProfileTLSMirror:
		default:
			return fmt.Errorf("transport.stealth.selection.fallback_profiles contains unsupported profile: %s", p)
		}
	}
	if c.Transport.Stealth.Selection.ProbeTimeout != "" {
		if _, err := time.ParseDuration(c.Transport.Stealth.Selection.ProbeTimeout); err != nil {
			return fmt.Errorf("transport.stealth.selection.probe_timeout invalid: %w", err)
		}
	}

	return nil
}

func legacyTransportTypeError(oldType string) error {
	oldType = strings.TrimSpace(oldType)
	switch oldType {
	case "tls", "wss", "h2", "xhttp", "shadowtls", "reality", "tlsmirror", "quic", "masque", "dtls", "kcp", "rawtcp", "raw_adapter", "faketcp", "icmptun", "dnstun", "udptcp", "auto", "awg_obfs":
		return fmt.Errorf("transport.type=%s has been removed; use transport.type=uqsp. See docs/UQSP_MIGRATION.md for details", oldType)
	case "stealth":
		return fmt.Errorf("transport.type=stealth with carrier.kind is no longer supported. Use transport.type=uqsp instead. See docs/UQSP_MIGRATION.md for details")
	case "":
		return fmt.Errorf("transport.type is required and must be 'uqsp'")
	default:
		return fmt.Errorf("transport.type=%s is unsupported; use transport.type=uqsp", oldType)
	}
}

func legacyTransportBlockError(oldKey string) error {
	newPath, ok := removedTransportBlocks[strings.ToLower(strings.TrimSpace(oldKey))]
	if !ok {
		return fmt.Errorf("transport.%s has been removed; use transport.stealth.*", oldKey)
	}
	return fmt.Errorf("transport.%s has been removed; use %s", oldKey, newPath)
}

func isLegacyTransportBlock(key string) bool {
	_, ok := removedTransportBlocks[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

func isZero[T any](v T) bool {
	var zero T
	return reflect.DeepEqual(v, zero)
}

func isValidBase64Key32(s string) bool {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	return err == nil && len(b) == 32
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
