package config

import (
	"fmt"
	"strings"
	"time"
)

// UQSPConfig configures the Unified QUIC Superset Protocol transport.
type UQSPConfig struct {
	Handshake   UQSPHandshakeConfig   `yaml:"handshake"`
	Streams     UQSPStreamsConfig     `yaml:"streams"`
	Datagrams   UQSPDatagramsConfig   `yaml:"datagrams"`
	Capsules    UQSPCapsulesConfig    `yaml:"capsules"`
	Congestion  UQSPCongestionConfig  `yaml:"congestion"`
	Obfuscation UQSPObfuscationConfig `yaml:"obfuscation"`
	AWGProfile  UQSPAWGProfileConfig  `yaml:"awg_profile"`
	Security    UQSPSecurityConfig    `yaml:"security"`
	Carrier     UQSPCarrierConfig     `yaml:"carrier"`
	Behaviors   UQSPBehaviorConfig    `yaml:"behaviors"`
	Reverse     UQSPReverseConfig     `yaml:"reverse"`
}

// UQSPHandshakeConfig configures the UQSP handshake behavior.
type UQSPHandshakeConfig struct {
	AuthMode         string `yaml:"auth_mode"` // token, cert, psk
	Enable0RTT       bool   `yaml:"enable_0rtt"`
	AntiReplayWindow int    `yaml:"anti_replay_window"` // Window size for replay protection
}

// UQSPStreamsConfig configures UQSP stream behavior.
type UQSPStreamsConfig struct {
	MaxConcurrent         int   `yaml:"max_concurrent"`
	FlowControlWindow     int   `yaml:"flow_control_window"` // bytes
	MaxIncomingStreams    int64 `yaml:"max_incoming_streams"`
	MaxIncomingUniStreams int64 `yaml:"max_incoming_uni_streams"`
}

// UQSPDatagramsConfig configures UQSP datagram (UDP) behavior.
type UQSPDatagramsConfig struct {
	MaxSize              int    `yaml:"max_size"`
	EnableFragmentation  bool   `yaml:"enable_fragmentation"`
	RelayMode            string `yaml:"relay_mode"` // native, capsule
	MaxIncomingDatagrams int    `yaml:"max_incoming_datagrams"`
}

// UQSPCapsulesConfig configures CONNECT-UDP/IP capsule behavior.
type UQSPCapsulesConfig struct {
	ConnectUDP    bool   `yaml:"connect_udp"`
	ConnectIP     bool   `yaml:"connect_ip"`
	ContextPolicy string `yaml:"context_policy"` // required, optional, disabled
	MaxContextID  uint64 `yaml:"max_context_id"`
}

// UQSPCongestionConfig configures congestion control.
type UQSPCongestionConfig struct {
	Algorithm     string `yaml:"algorithm"` // bbr, brutal, cubic
	Pacing        string `yaml:"pacing"`    // adaptive, aggressive, conservative
	AdaptiveMode  bool   `yaml:"adaptive_mode"`
	BandwidthMbps int    `yaml:"bandwidth_mbps"` // for brutal CC
}

// UQSPObfuscationConfig configures obfuscation and stealth.
type UQSPObfuscationConfig struct {
	Profile         string                   `yaml:"profile"` // adaptive, salamander, none
	SalamanderKey   string                   `yaml:"salamander_key"`
	PaddingMin      int                      `yaml:"padding_min"`
	PaddingMax      int                      `yaml:"padding_max"`
	TimingJitterMs  int                      `yaml:"timing_jitter_ms"`
	MorphingEnabled bool                     `yaml:"morphing_enabled"`
	Chain           []ObfuscationChainConfig `yaml:"chain"` // Obfuscation chain
}

// ObfuscationChainConfig configures a single obfuscator in the chain
type ObfuscationChainConfig struct {
	Type   string            `yaml:"type"`   // salamander, xor, noize, padding, awg
	Key    string            `yaml:"key"`    // Encryption key
	Params map[string]string `yaml:"params"` // Type-specific parameters
}

// UQSPAWGProfileConfig configures AWG-style junk/padding behavior.
// Complex parameters (Jc, Jmin, Jmax, S1-S4, H1-H4, I1-I15) are auto-generated
// per-session based on handshake entropy to minimize fingerprinting.
type UQSPAWGProfileConfig struct {
	Enabled      bool          `yaml:"enabled"`
	JunkInterval time.Duration `yaml:"junk_interval"`
}

// UQSPSecurityConfig configures UQSP security settings.
type UQSPSecurityConfig struct {
	TLSMinVersion string        `yaml:"tls_min_version"`
	PQKEM         bool          `yaml:"pq_kem"` // post-quantum key exchange
	KeyRotation   time.Duration `yaml:"key_rotation"`
}

// ApplyUQSPDefaults applies default values to UQSP configuration.
func (c *Config) ApplyUQSPDefaults() {
	u := &c.Transport.UQSP

	// Handshake defaults
	if u.Handshake.AuthMode == "" {
		u.Handshake.AuthMode = "token"
	}
	if u.Handshake.AntiReplayWindow == 0 {
		u.Handshake.AntiReplayWindow = 64
	}

	// Streams defaults
	if u.Streams.MaxConcurrent == 0 {
		u.Streams.MaxConcurrent = 100
	}
	if u.Streams.FlowControlWindow == 0 {
		u.Streams.FlowControlWindow = 1048576 // 1MB
	}
	if u.Streams.MaxIncomingStreams == 0 {
		u.Streams.MaxIncomingStreams = 1024
	}
	if u.Streams.MaxIncomingUniStreams == 0 {
		u.Streams.MaxIncomingUniStreams = 128
	}

	// Datagrams defaults
	if u.Datagrams.MaxSize == 0 {
		u.Datagrams.MaxSize = 1350
	}
	if u.Datagrams.RelayMode == "" {
		u.Datagrams.RelayMode = "native"
	}
	if u.Datagrams.MaxIncomingDatagrams == 0 {
		u.Datagrams.MaxIncomingDatagrams = 1024
	}

	// Capsules defaults
	if u.Capsules.ContextPolicy == "" {
		u.Capsules.ContextPolicy = "optional"
	}
	if u.Capsules.MaxContextID == 0 {
		u.Capsules.MaxContextID = 16777215 // 2^24 - 1
	}

	// Congestion defaults
	if u.Congestion.Algorithm == "" {
		u.Congestion.Algorithm = "bbr"
	}
	if u.Congestion.Pacing == "" {
		u.Congestion.Pacing = "adaptive"
	}
	if u.Congestion.BandwidthMbps == 0 {
		u.Congestion.BandwidthMbps = 100
	}

	// Obfuscation defaults
	if u.Obfuscation.Profile == "" {
		u.Obfuscation.Profile = "adaptive"
	}
	if u.Obfuscation.PaddingMin == 0 {
		u.Obfuscation.PaddingMin = 16
	}
	if u.Obfuscation.PaddingMax == 0 {
		u.Obfuscation.PaddingMax = 128
	}

	// AWG profile defaults
	if u.AWGProfile.JunkInterval == 0 {
		u.AWGProfile.JunkInterval = 5 * time.Second
	}

	// Security defaults
	if u.Security.TLSMinVersion == "" {
		u.Security.TLSMinVersion = "1.3"
	}
	if u.Security.KeyRotation == 0 {
		u.Security.KeyRotation = 24 * time.Hour
	}

	// Carrier defaults
	if u.Carrier.Type == "" {
		u.Carrier.Type = "quic"
	}
	if u.Carrier.WebTunnel.TLSFingerprint == "" {
		u.Carrier.WebTunnel.TLSFingerprint = "chrome_auto"
	}
	if u.Carrier.Chisel.TLSFingerprint == "" {
		u.Carrier.Chisel.TLSFingerprint = "chrome_auto"
	}
	if u.Carrier.XHTTP.TLSFingerprint == "" {
		u.Carrier.XHTTP.TLSFingerprint = "chrome_auto"
	}

	// Reverse defaults
	if u.Reverse.HeartbeatInterval == 0 {
		u.Reverse.HeartbeatInterval = 15 * time.Second
	}
	if u.Reverse.ReconnectDelay == 0 {
		u.Reverse.ReconnectDelay = 5 * time.Second
	}
	if u.Reverse.MaxRetries == 0 {
		u.Reverse.MaxRetries = 10
	}
}

// ValidateUQSP validates UQSP configuration.
func (c *Config) ValidateUQSP() error {
	u := &c.Transport.UQSP

	// Validate handshake
	switch strings.ToLower(u.Handshake.AuthMode) {
	case "token", "cert", "psk":
	default:
		return fmt.Errorf("transport.uqsp.handshake.auth_mode must be one of: token, cert, psk")
	}

	if u.Handshake.AntiReplayWindow < 0 {
		return fmt.Errorf("transport.uqsp.handshake.anti_replay_window must be >= 0")
	}

	// Validate streams
	if u.Streams.MaxConcurrent < 1 {
		return fmt.Errorf("transport.uqsp.streams.max_concurrent must be >= 1")
	}
	if u.Streams.FlowControlWindow < 65536 {
		return fmt.Errorf("transport.uqsp.streams.flow_control_window must be >= 65536")
	}

	// Validate datagrams
	if u.Datagrams.MaxSize < 512 || u.Datagrams.MaxSize > 65535 {
		return fmt.Errorf("transport.uqsp.datagrams.max_size must be between 512 and 65535")
	}
	switch strings.ToLower(u.Datagrams.RelayMode) {
	case "native", "capsule":
	default:
		return fmt.Errorf("transport.uqsp.datagrams.relay_mode must be one of: native, capsule")
	}

	// Validate capsules
	switch strings.ToLower(u.Capsules.ContextPolicy) {
	case "required", "optional", "disabled":
	default:
		return fmt.Errorf("transport.uqsp.capsules.context_policy must be one of: required, optional, disabled")
	}

	// Validate congestion
	switch strings.ToLower(u.Congestion.Algorithm) {
	case "bbr", "brutal", "cubic":
	default:
		return fmt.Errorf("transport.uqsp.congestion.algorithm must be one of: bbr, brutal, cubic")
	}
	switch strings.ToLower(u.Congestion.Pacing) {
	case "adaptive", "aggressive", "conservative":
	default:
		return fmt.Errorf("transport.uqsp.congestion.pacing must be one of: adaptive, aggressive, conservative")
	}
	if u.Congestion.Algorithm == "brutal" && u.Congestion.BandwidthMbps < 1 {
		return fmt.Errorf("transport.uqsp.congestion.bandwidth_mbps must be >= 1 when using brutal algorithm")
	}

	// Validate obfuscation
	switch strings.ToLower(u.Obfuscation.Profile) {
	case "adaptive", "salamander", "none":
	default:
		return fmt.Errorf("transport.uqsp.obfuscation.profile must be one of: adaptive, salamander, none")
	}
	if u.Obfuscation.Profile == "salamander" && u.Obfuscation.SalamanderKey == "" {
		return fmt.Errorf("transport.uqsp.obfuscation.salamander_key is required when profile=salamander")
	}
	if u.Obfuscation.PaddingMin < 0 {
		return fmt.Errorf("transport.uqsp.obfuscation.padding_min must be >= 0")
	}
	if u.Obfuscation.PaddingMax < u.Obfuscation.PaddingMin {
		return fmt.Errorf("transport.uqsp.obfuscation.padding_max must be >= padding_min")
	}
	if u.Obfuscation.TimingJitterMs < 0 {
		return fmt.Errorf("transport.uqsp.obfuscation.timing_jitter_ms must be >= 0")
	}

	// Validate security
	switch u.Security.TLSMinVersion {
	case "1.2", "1.3":
	default:
		return fmt.Errorf("transport.uqsp.security.tls_min_version must be one of: 1.2, 1.3")
	}

	// Validate carrier type
	switch strings.ToLower(strings.TrimSpace(u.Carrier.Type)) {
	case "", "quic", "trusttunnel", "rawtcp", "icmptun", "webtunnel", "chisel", "xhttp":
	default:
		return fmt.Errorf("transport.uqsp.carrier.type has unsupported value %q", u.Carrier.Type)
	}

	// Validate carrier fingerprints and key options
	if strings.TrimSpace(u.Carrier.WebTunnel.TLSFingerprint) == "" {
		return fmt.Errorf("transport.uqsp.carrier.webtunnel.tls_fingerprint is required")
	}
	if strings.TrimSpace(u.Carrier.Chisel.TLSFingerprint) == "" {
		return fmt.Errorf("transport.uqsp.carrier.chisel.tls_fingerprint is required")
	}
	if strings.TrimSpace(u.Carrier.XHTTP.TLSFingerprint) == "" {
		return fmt.Errorf("transport.uqsp.carrier.xhttp.tls_fingerprint is required")
	}
	if u.Carrier.TrustTunnel.PaddingMin < 0 || u.Carrier.TrustTunnel.PaddingMax < u.Carrier.TrustTunnel.PaddingMin {
		return fmt.Errorf("transport.uqsp.carrier.trusttunnel padding range is invalid")
	}
	if u.Carrier.TrustTunnel.DPDInterval < 0 {
		return fmt.Errorf("transport.uqsp.carrier.trusttunnel.dpd_interval must be >= 0")
	}

	// Validate reverse mode fields
	if u.Reverse.Enabled {
		switch strings.ToLower(strings.TrimSpace(u.Reverse.Role)) {
		case "", "dialer", "listener":
		default:
			return fmt.Errorf("transport.uqsp.reverse.role must be one of: dialer, listener")
		}
		if strings.TrimSpace(u.Reverse.AuthToken) == "" {
			return fmt.Errorf("transport.uqsp.reverse.auth_token is required when reverse mode is enabled")
		}
		if u.Reverse.HeartbeatInterval <= 0 {
			return fmt.Errorf("transport.uqsp.reverse.heartbeat_interval must be > 0")
		}
		if u.Reverse.ReconnectDelay <= 0 {
			return fmt.Errorf("transport.uqsp.reverse.reconnect_delay must be > 0")
		}
		if u.Reverse.MaxRetries < 1 {
			return fmt.Errorf("transport.uqsp.reverse.max_retries must be >= 1")
		}
	}

	return nil
}

// UQSPEnabled returns true if UQSP transport is configured.
func (c *Config) UQSPEnabled() bool {
	return strings.ToLower(strings.TrimSpace(c.Transport.Type)) == "uqsp"
}

// UQSPCarrierConfig selects and configures the underlying transport carrier.
type UQSPCarrierConfig struct {
	// Type selects the carrier: "quic", "trusttunnel", "rawtcp", "icmptun", "webtunnel", "chisel"
	// Default is "quic" (native QUIC transport)
	Type string `yaml:"type"`

	// Fallback enables fallback to other carriers if the primary fails
	Fallback bool `yaml:"fallback"`

	// Type-specific configurations
	TrustTunnel TrustTunnelCarrierConfig `yaml:"trusttunnel"`
	RawTCP      RawTCPCarrierConfig      `yaml:"rawtcp"`
	ICMPTun     ICMPTunCarrierConfig     `yaml:"icmptun"`
	WebTunnel   WebTunnelCarrierConfig   `yaml:"webtunnel"`
	Chisel      ChiselCarrierConfig      `yaml:"chisel"`
	XHTTP       XHTTPCarrierConfig       `yaml:"xhttp"`
}

// TrustTunnelCarrierConfig configures TrustTunnel as a carrier.
type TrustTunnelCarrierConfig struct {
	Server         string        `yaml:"server"`
	Version        string        `yaml:"version"` // h1, h2, h3, mux
	Token          string        `yaml:"token"`
	MaxConcurrent  int           `yaml:"max_concurrent"`
	StreamTimeout  time.Duration `yaml:"stream_timeout"`
	PaddingMin     int           `yaml:"padding_min"`
	PaddingMax     int           `yaml:"padding_max"`
	DomainFronting string        `yaml:"domain_fronting"`
	DTLSFallback   bool          `yaml:"dtls_fallback"`
	DPDInterval    time.Duration `yaml:"dpd_interval"`
	MTUDiscovery   bool          `yaml:"mtu_discovery"`
	SplitInclude   []string      `yaml:"split_include"`
	SplitExclude   []string      `yaml:"split_exclude"`
}

// RawTCPCarrierConfig configures RawTCP as a carrier.
type RawTCPCarrierConfig struct {
	Raw RawTCPConfig `yaml:"raw"`
	KCP KCPConfig    `yaml:"kcp"`
}

// ICMPTunCarrierConfig configures ICMPTun as a carrier.
type ICMPTunCarrierConfig struct {
	MTU          int           `yaml:"mtu"`
	EchoInterval time.Duration `yaml:"echo_interval"`
	Timeout      time.Duration `yaml:"timeout"`
	WindowSize   int           `yaml:"window_size"`
	Obfuscate    bool          `yaml:"obfuscate"`
	ReadBuffer   int           `yaml:"read_buffer"`
	WriteBuffer  int           `yaml:"write_buffer"`
}

// WebTunnelCarrierConfig configures WebTunnel as a carrier.
type WebTunnelCarrierConfig struct {
	Server                string            `yaml:"server"`
	Path                  string            `yaml:"path"`
	Version               string            `yaml:"version"` // h1, h2
	Headers               map[string]string `yaml:"headers"`
	UserAgent             string            `yaml:"user_agent"`
	TLSInsecureSkipVerify bool              `yaml:"tls_insecure_skip_verify"`
	TLSServerName         string            `yaml:"tls_server_name"`
	TLSFingerprint        string            `yaml:"tls_fingerprint"`
}

// ChiselCarrierConfig configures Chisel as a carrier.
type ChiselCarrierConfig struct {
	Server                string            `yaml:"server"`
	Path                  string            `yaml:"path"`
	Auth                  string            `yaml:"auth"`
	Fingerprint           string            `yaml:"fingerprint"`
	Headers               map[string]string `yaml:"headers"`
	UserAgent             string            `yaml:"user_agent"`
	TLSInsecureSkipVerify bool              `yaml:"tls_insecure_skip_verify"`
	TLSServerName         string            `yaml:"tls_server_name"`
	TLSFingerprint        string            `yaml:"tls_fingerprint"`
}

// XHTTPCarrierConfig configures XHTTP (SplitHTTP) as a carrier.
type XHTTPCarrierConfig struct {
	Server                string            `yaml:"server"`
	Path                  string            `yaml:"path"`
	Mode                  string            `yaml:"mode"` // stream-one, stream-up, stream-down, packet-up
	Headers               map[string]string `yaml:"headers"`
	MaxConns              int               `yaml:"max_connections"`
	TLSInsecureSkipVerify bool              `yaml:"tls_insecure_skip_verify"`
	TLSServerName         string            `yaml:"tls_server_name"`
	TLSFingerprint        string            `yaml:"tls_fingerprint"`
}

// UQSPBehaviorConfig configures protocol behavior overlays.
type UQSPBehaviorConfig struct {
	ShadowTLS   ShadowTLSBehaviorConfig   `yaml:"shadowtls"`
	TLSMirror   TLSMirrorBehaviorConfig   `yaml:"tlsmirror"`
	AWG         AWGBehaviorConfig         `yaml:"awg"`
	Reality     RealityBehaviorConfig     `yaml:"reality"`
	ECH         ECHBehaviorConfig         `yaml:"ech"`
	Obfs4       Obfs4BehaviorConfig       `yaml:"obfs4"`
	Vision      VisionBehaviorConfig      `yaml:"vision"`
	DomainFront DomainFrontBehaviorConfig `yaml:"domainfront"`
	TLSFrag     TLSFragBehaviorConfig     `yaml:"tlsfrag"`
	CSTP        CSTPBehaviorConfig        `yaml:"cstp"`
}

// ShadowTLSBehaviorConfig ports ShadowTLS v3 behaviors as an overlay.
type ShadowTLSBehaviorConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Version       int      `yaml:"version"`
	Password      string   `yaml:"password"`
	HandshakeDest string   `yaml:"handshake_dest"`
	ServerNames   []string `yaml:"server_names"`
}

// TLSMirrorBehaviorConfig ports TLSMirror behaviors as an overlay.
type TLSMirrorBehaviorConfig struct {
	Enabled            bool   `yaml:"enabled"`
	ControlChannel     string `yaml:"control_channel"`
	EnrollmentRequired bool   `yaml:"enrollment_required"`
}

// AWGBehaviorConfig ports AmneziaWG 2.0 behaviors as an overlay.
type AWGBehaviorConfig struct {
	Enabled      bool          `yaml:"enabled"`
	JunkInterval time.Duration `yaml:"junk_interval"`
	JunkMinSize  int           `yaml:"junk_min_size"`
	JunkMaxSize  int           `yaml:"junk_max_size"`
}

// RealityBehaviorConfig ports XTLS REALITY behaviors as an overlay.
type RealityBehaviorConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Dest            string   `yaml:"dest"`
	ServerNames     []string `yaml:"server_names"`
	PrivateKey      string   `yaml:"private_key"`
	ServerPublicKey string   `yaml:"server_public_key"`
	ShortIDs        []string `yaml:"short_ids"`
	SpiderX         string   `yaml:"spider_x"`
	Show            bool     `yaml:"show"`
}

// ECHBehaviorConfig ports Encrypted Client Hello behaviors as an overlay.
type ECHBehaviorConfig struct {
	Enabled    bool     `yaml:"enabled"`
	PublicName string   `yaml:"public_name"`
	InnerSNI   string   `yaml:"inner_sni"`
	Configs    []string `yaml:"configs"` // Base64-encoded ECH configs
	RequireECH bool     `yaml:"require_ech"`
}

// Obfs4BehaviorConfig configures obfs4 obfuscation as an overlay.
type Obfs4BehaviorConfig struct {
	Enabled    bool   `yaml:"enabled"`
	NodeID     string `yaml:"node_id"`     // Base64-encoded node ID (32 bytes)
	PublicKey  string `yaml:"public_key"`  // Base64-encoded public key (32 bytes)
	PrivateKey string `yaml:"private_key"` // Base64-encoded private key (32 bytes, server only)
	Seed       string `yaml:"seed"`        // Base64-encoded DRBG seed
	IATMode    int    `yaml:"iat_mode"`    // 0=off, 1=on, 2=paranoid
}

// VisionBehaviorConfig configures XTLS Vision as an overlay.
type VisionBehaviorConfig struct {
	Enabled          bool          `yaml:"enabled"`
	FlowAutoDetect   bool          `yaml:"flow_auto_detect"`
	AllowInsecure    bool          `yaml:"allow_insecure"`
	BufferSize       int           `yaml:"buffer_size"`
	DetectionTimeout time.Duration `yaml:"detection_timeout"`
}

// DomainFrontBehaviorConfig configures Domain Fronting as an overlay.
type DomainFrontBehaviorConfig struct {
	Enabled            bool     `yaml:"enabled"`
	FrontDomain        string   `yaml:"front_domain"`
	RealHost           string   `yaml:"real_host"`
	RotateIPs          bool     `yaml:"rotate_ips"`
	CustomIPs          []string `yaml:"custom_ips"`
	PreserveHostHeader bool     `yaml:"preserve_host_header"`
}

// TLSFragBehaviorConfig configures TLS Fragmentation as an overlay.
type TLSFragBehaviorConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Strategy  string `yaml:"strategy"` // sni_split, random, fixed
	ChunkSize int    `yaml:"chunk_size"`
	MinDelay  int    `yaml:"min_delay"`
	MaxDelay  int    `yaml:"max_delay"`
	Randomize bool   `yaml:"randomize"`
}

// CSTPBehaviorConfig configures OpenConnect CSTP-style framing and keepalive.
type CSTPBehaviorConfig struct {
	Enabled         bool          `yaml:"enabled"`
	DPDInterval     time.Duration `yaml:"dpd_interval"`
	MTU             int           `yaml:"mtu"`
	EnableSplitTunn bool          `yaml:"enable_split_tunnel"`
	SplitInclude    []string      `yaml:"split_include"`
	SplitExclude    []string      `yaml:"split_exclude"`
}

type UQSPReverseConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Role              string        `yaml:"role"` // dialer, listener
	ClientAddress     string        `yaml:"client_address"`
	ServerAddress     string        `yaml:"server_address"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	ReconnectDelay    time.Duration `yaml:"reconnect_delay"`
	MaxRetries        int           `yaml:"max_retries"`
	AuthToken         string        `yaml:"auth_token"`
}

func (c *UQSPConfig) GetReverse() UQSPReverseConfig {
	return c.Reverse
}
