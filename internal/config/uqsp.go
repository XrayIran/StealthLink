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
	Runtime     UQSPRuntimeConfig     `yaml:"runtime"`
	// VariantProfile is an optional in-transport preset selector.
	// Top-level "variant" remains the primary selector.
	VariantProfile string `yaml:"variant_profile"`

	// VariantPolicy allows per-mode overrides for WARP and reverse.
	// Keys are variant names: "4a", "4b", "4c", "4d", "4e".
	// A nil or missing entry means "use global config".
	VariantPolicy map[string]UQSPVariantPolicy `yaml:"variant_policy"`
}

// UQSPVariantPolicy holds per-variant overrides for WARP and reverse mode.
// Pointer fields are nil = "inherit global", non-nil = "use this value".
type UQSPVariantPolicy struct {
	WARPEnabled    *bool `yaml:"warp_enabled"`
	ReverseEnabled *bool `yaml:"reverse_enabled"`
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
	MaxSize              int           `yaml:"max_size"`
	EnableFragmentation  bool          `yaml:"enable_fragmentation"`
	RelayMode            string        `yaml:"relay_mode"` // native, capsule
	MaxIncomingDatagrams int           `yaml:"max_incoming_datagrams"`
	ReassemblyTimeout    time.Duration `yaml:"reassembly_timeout"`
	MaxReassemblyBytes   int           `yaml:"max_reassembly_bytes"`
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
	PQKEM         bool          `yaml:"pq_kem"`     // post-quantum key exchange
	PQEnforce     bool          `yaml:"pq_enforce"` // enforce PQ signature verification (fail if peer doesn't support)
	KeyRotation   time.Duration `yaml:"key_rotation"`
}

// UQSPRuntimeConfig configures runtime path behavior.
type UQSPRuntimeConfig struct {
	// Mode can be:
	// - "unified" (default): BuildVariantForRole -> UnifiedProtocol runtime
	// - "legacy": historical NewDialer/NewListener path
	Mode string `yaml:"mode"`
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
	if u.Datagrams.ReassemblyTimeout == 0 {
		u.Datagrams.ReassemblyTimeout = 30 * time.Second
	}
	if u.Datagrams.MaxReassemblyBytes == 0 {
		u.Datagrams.MaxReassemblyBytes = 4 << 20
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
	u.Carrier.RawTCP.Raw.applyDefaults(c.Role)
	if u.Carrier.RawTCP.KCP.Block == "" {
		u.Carrier.RawTCP.KCP.Block = "aes"
	}
	if u.Carrier.RawTCP.KCP.PacketGuardMagic == "" {
		u.Carrier.RawTCP.KCP.PacketGuardMagic = "PQT1"
	}
	if u.Carrier.RawTCP.KCP.PacketGuardWindow == 0 {
		u.Carrier.RawTCP.KCP.PacketGuardWindow = 30
	}
	if u.Carrier.RawTCP.KCP.PacketGuardSkew == 0 {
		u.Carrier.RawTCP.KCP.PacketGuardSkew = 1
	}
	if u.Carrier.FakeTCP.MTU == 0 {
		u.Carrier.FakeTCP.MTU = 1400
	}
	if u.Carrier.FakeTCP.WindowSize == 0 {
		u.Carrier.FakeTCP.WindowSize = 65535
	}
	if u.Carrier.FakeTCP.RTO == 0 {
		u.Carrier.FakeTCP.RTO = 200 * time.Millisecond
	}
	if u.Carrier.FakeTCP.Keepalive == 0 {
		u.Carrier.FakeTCP.Keepalive = 30 * time.Second
	}
	if u.Carrier.FakeTCP.KeepaliveIdle == 0 {
		u.Carrier.FakeTCP.KeepaliveIdle = 60 * time.Second
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
	if u.Reverse.ReconnectBackoff == 0 {
		u.Reverse.ReconnectBackoff = 1 * time.Second
	}
	if u.Reverse.MaxReconnectDelay == 0 {
		u.Reverse.MaxReconnectDelay = 60 * time.Second
	}
	if u.Reverse.MaxRetries == 0 {
		u.Reverse.MaxRetries = 10
	}
	if u.Reverse.KeepaliveInterval == 0 {
		u.Reverse.KeepaliveInterval = 30 * time.Second
	}

	// Behavior defaults
	// AWG's special-junk packets are optional by default for compatibility
	// with peers that only advertise magic headers + core junk controls.
	if u.Behaviors.AWG.SpecialJunkOptional == nil {
		v := true
		u.Behaviors.AWG.SpecialJunkOptional = &v
	}
	// FakeTCP fake-HTTP preface is enabled by default for 4b stealth posture,
	// while retaining an explicit opt-out via fake_http.enabled: false.
	if u.Carrier.FakeTCP.FakeHTTP.Enabled == nil {
		v := true
		u.Carrier.FakeTCP.FakeHTTP.Enabled = &v
	}
	if u.Carrier.FakeTCP.FakeHTTP.IsEnabled() {
		if strings.TrimSpace(u.Carrier.FakeTCP.FakeHTTP.Host) == "" {
			u.Carrier.FakeTCP.FakeHTTP.Host = "cdn.cloudflare.com"
		}
		if strings.TrimSpace(u.Carrier.FakeTCP.FakeHTTP.UserAgent) == "" {
			u.Carrier.FakeTCP.FakeHTTP.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		}
		if strings.TrimSpace(u.Carrier.FakeTCP.FakeHTTP.Path) == "" {
			u.Carrier.FakeTCP.FakeHTTP.Path = "/"
		}
	}
	if u.Behaviors.ViolatedTCP.FakeHTTPEnabled {
		if strings.TrimSpace(u.Behaviors.ViolatedTCP.FakeHTTPHost) == "" {
			u.Behaviors.ViolatedTCP.FakeHTTPHost = "cdn.cloudflare.com"
		}
		if strings.TrimSpace(u.Behaviors.ViolatedTCP.FakeHTTPUserAgent) == "" {
			u.Behaviors.ViolatedTCP.FakeHTTPUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		}
	}

	// AnyTLS defaults
	if u.Carrier.AnyTLS.PaddingScheme == "" {
		u.Carrier.AnyTLS.PaddingScheme = "random"
	}
	if u.Carrier.AnyTLS.PaddingMin == 0 {
		u.Carrier.AnyTLS.PaddingMin = 100
	}
	if u.Carrier.AnyTLS.PaddingMax == 0 {
		u.Carrier.AnyTLS.PaddingMax = 900
	}
	if u.Carrier.AnyTLS.IdleSessionTimeout == 0 {
		u.Carrier.AnyTLS.IdleSessionTimeout = 300
	}

	// MASQUE defaults
	if strings.TrimSpace(u.Carrier.MASQUE.TunnelType) == "" {
		u.Carrier.MASQUE.TunnelType = "udp"
	}

	// KCP defaults (standalone carrier)
	if strings.TrimSpace(u.Carrier.KCP.Mode) == "" {
		u.Carrier.KCP.Mode = "standard"
	}
	if strings.TrimSpace(u.Carrier.KCP.Block) == "" {
		u.Carrier.KCP.Block = "none"
	}
	if u.Carrier.KCP.DataShards == 0 {
		u.Carrier.KCP.DataShards = 10
	}
	if u.Carrier.KCP.ParityShards == 0 {
		u.Carrier.KCP.ParityShards = 3
	}
	if u.Carrier.KCP.AutoTuneFEC == nil {
		v := true
		u.Carrier.KCP.AutoTuneFEC = &v
	}
	if u.Carrier.KCP.BatchEnabled == nil {
		v := true
		u.Carrier.KCP.BatchEnabled = &v
	}
	if u.Carrier.KCP.BatchSize == 0 {
		u.Carrier.KCP.BatchSize = 32
	}

	// Reality defaults
	if u.Behaviors.Reality.SpiderConcurrency == 0 {
		u.Behaviors.Reality.SpiderConcurrency = 4
	}
	if u.Behaviors.Reality.SpiderTimeout == 0 {
		u.Behaviors.Reality.SpiderTimeout = 10
	}
	if u.Behaviors.Reality.MaxDepth == 0 {
		u.Behaviors.Reality.MaxDepth = 3
	}
	if u.Behaviors.Reality.MaxTotalFetches == 0 {
		u.Behaviors.Reality.MaxTotalFetches = 20
	}
	if u.Behaviors.Reality.PerHostCap == 0 {
		u.Behaviors.Reality.PerHostCap = 5
	}
	if len(u.Behaviors.Reality.SpiderY) == 0 {
		u.Behaviors.Reality.SpiderY = []int{50, 100, 200, 300, 500, 800, 1000, 1500, 2000, 3000}
	}

	// Runtime defaults
	if strings.TrimSpace(u.Runtime.Mode) == "" {
		u.Runtime.Mode = "unified"
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
	if u.Datagrams.ReassemblyTimeout <= 0 {
		return fmt.Errorf("transport.uqsp.datagrams.reassembly_timeout must be > 0")
	}
	if u.Datagrams.MaxReassemblyBytes < 64*1024 {
		return fmt.Errorf("transport.uqsp.datagrams.max_reassembly_bytes must be >= 65536")
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

	// Validate runtime mode
	switch strings.ToLower(strings.TrimSpace(u.Runtime.Mode)) {
	case "", "unified", "legacy":
	default:
		return fmt.Errorf("transport.uqsp.runtime.mode must be one of: unified, legacy")
	}

	// Validate optional in-transport variant profile selector.
	if strings.TrimSpace(u.VariantProfile) != "" {
		if _, ok := parseVariantValue(u.VariantProfile); !ok {
			return fmt.Errorf("transport.uqsp.variant_profile must be one of: 4a, 4b, 4c, 4d, 4e")
		}
	}

	// Validate carrier type
	carrierType := strings.ToLower(strings.TrimSpace(u.Carrier.Type))
	switch carrierType {
	case "", "quic", "trusttunnel", "rawtcp", "faketcp", "kcp", "icmptun", "webtunnel", "chisel", "xhttp", "anytls", "masque":
	default:
		return fmt.Errorf("transport.uqsp.carrier.type has unsupported value %q", u.Carrier.Type)
	}
	if carrierType == "rawtcp" {
		u.Carrier.RawTCP.Raw.applyDefaults(c.Role)
		if err := u.Carrier.RawTCP.Raw.validate(c.Role, c.Gateway.Listen); err != nil {
			return fmt.Errorf("transport.uqsp.carrier.rawtcp.raw: %w", err)
		}
		if strings.TrimSpace(u.Carrier.RawTCP.KCP.Block) == "" {
			return fmt.Errorf("transport.uqsp.carrier.rawtcp.kcp.block is required")
		}
	}
	if carrierType == "faketcp" {
		if u.Carrier.FakeTCP.MTU < 576 || u.Carrier.FakeTCP.MTU > 65535 {
			return fmt.Errorf("transport.uqsp.carrier.faketcp.mtu must be between 576 and 65535")
		}
		if u.Carrier.FakeTCP.WindowSize < 1024 {
			return fmt.Errorf("transport.uqsp.carrier.faketcp.window_size must be >= 1024")
		}
		if u.Carrier.FakeTCP.RTO <= 0 {
			return fmt.Errorf("transport.uqsp.carrier.faketcp.rto must be > 0")
		}
		if u.Carrier.FakeTCP.Keepalive <= 0 {
			return fmt.Errorf("transport.uqsp.carrier.faketcp.keepalive must be > 0")
		}
		if u.Carrier.FakeTCP.KeepaliveIdle <= 0 {
			return fmt.Errorf("transport.uqsp.carrier.faketcp.keepalive_idle must be > 0")
		}
		switch strings.ToLower(strings.TrimSpace(u.Carrier.FakeTCP.AEADMode)) {
		case "", "off", "chacha20poly1305", "aesgcm":
		default:
			return fmt.Errorf("transport.uqsp.carrier.faketcp.aead_mode must be one of: off, chacha20poly1305, aesgcm")
		}
		if strings.ToLower(strings.TrimSpace(u.Carrier.FakeTCP.AEADMode)) != "off" &&
			strings.TrimSpace(u.Carrier.FakeTCP.AEADMode) != "" &&
			strings.TrimSpace(u.Carrier.FakeTCP.CryptoKey) == "" {
			return fmt.Errorf("transport.uqsp.carrier.faketcp.crypto_key is required when aead_mode is enabled")
		}
	}
	if carrierType == "masque" {
		switch strings.ToLower(strings.TrimSpace(u.Carrier.MASQUE.TunnelType)) {
		case "", "udp", "tcp", "ip":
		default:
			return fmt.Errorf("transport.uqsp.carrier.masque.tunnel_type must be one of: udp, tcp, ip")
		}
	}
	if carrierType == "kcp" {
		switch strings.ToLower(strings.TrimSpace(u.Carrier.KCP.Mode)) {
		case "", "standard", "brutal", "awg", "dtls":
		default:
			return fmt.Errorf("transport.uqsp.carrier.kcp.mode must be one of: standard, brutal, awg, dtls")
		}
		if u.Carrier.KCP.DataShards < 1 || u.Carrier.KCP.DataShards > 255 {
			return fmt.Errorf("transport.uqsp.carrier.kcp.data_shards must be between 1 and 255")
		}
		if u.Carrier.KCP.ParityShards < 0 || u.Carrier.KCP.ParityShards > 255 {
			return fmt.Errorf("transport.uqsp.carrier.kcp.parity_shards must be between 0 and 255")
		}
		if u.Carrier.KCP.BatchSize < 1 || u.Carrier.KCP.BatchSize > 64 {
			return fmt.Errorf("transport.uqsp.carrier.kcp.batch_size must be between 1 and 64")
		}
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
	for _, metaField := range []struct {
		name      string
		placement string
	}{
		{name: "session", placement: u.Carrier.XHTTP.Metadata.Session.Placement},
		{name: "seq", placement: u.Carrier.XHTTP.Metadata.Seq.Placement},
		{name: "mode", placement: u.Carrier.XHTTP.Metadata.Mode.Placement},
	} {
		p := strings.ToLower(strings.TrimSpace(metaField.placement))
		switch p {
		case "", "header", "path", "query", "cookie":
		default:
			return fmt.Errorf("transport.uqsp.carrier.xhttp.metadata.%s.placement must be one of: header, path, query, cookie", metaField.name)
		}
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
		// "dialer"/"listener" are legacy-but-supported roles used by older configs
		// and by internal defaults (see Config.GetReverseRole and uqsp.ReverseDialer).
		case "", "client", "server", "rendezvous", "dialer", "listener":
		default:
			return fmt.Errorf("transport.uqsp.reverse.role must be one of: client, server, rendezvous (or legacy: dialer, listener)")
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
		if u.Reverse.ReconnectBackoff <= 0 {
			return fmt.Errorf("transport.uqsp.reverse.reconnect_backoff must be > 0")
		}
		if u.Reverse.MaxReconnectDelay <= 0 {
			return fmt.Errorf("transport.uqsp.reverse.max_reconnect_delay must be > 0")
		}
		if u.Reverse.MaxReconnectDelay < u.Reverse.ReconnectBackoff {
			return fmt.Errorf("transport.uqsp.reverse.max_reconnect_delay must be >= reconnect_backoff")
		}
		if u.Reverse.MaxRetries < 1 {
			return fmt.Errorf("transport.uqsp.reverse.max_retries must be >= 1")
		}
		if u.Reverse.KeepaliveInterval <= 0 {
			return fmt.Errorf("transport.uqsp.reverse.keepalive_interval must be > 0")
		}
	}

	if u.Behaviors.ViolatedTCP.FakeHTTPEnabled {
		if strings.TrimSpace(u.Behaviors.ViolatedTCP.FakeHTTPHost) == "" {
			return fmt.Errorf("transport.uqsp.behaviors.violated_tcp.fake_http_host is required when fake_http_enabled=true")
		}
		if strings.TrimSpace(u.Behaviors.ViolatedTCP.FakeHTTPUserAgent) == "" {
			return fmt.Errorf("transport.uqsp.behaviors.violated_tcp.fake_http_user_agent is required when fake_http_enabled=true")
		}
	}
	if carrierType == "anytls" {
		pw := strings.TrimSpace(u.Carrier.AnyTLS.Password)
		if pw == "" {
			// Backward compat: allow placing password under behaviors.anytls.password.
			pw = strings.TrimSpace(u.Behaviors.AnyTLS.Password)
		}
		if pw == "" {
			return fmt.Errorf("transport.uqsp.carrier.anytls.password is required when carrier type is anytls (or set transport.uqsp.behaviors.anytls.password)")
		}
		if u.Carrier.AnyTLS.PaddingMin < 0 {
			return fmt.Errorf("transport.uqsp.carrier.anytls.padding_min must be >= 0")
		}
		if u.Carrier.AnyTLS.PaddingMax < u.Carrier.AnyTLS.PaddingMin {
			return fmt.Errorf("transport.uqsp.carrier.anytls.padding_max must be >= padding_min")
		}
		if u.Carrier.AnyTLS.IdleSessionTimeout < 0 {
			return fmt.Errorf("transport.uqsp.carrier.anytls.idle_session_timeout must be >= 0")
		}
	}

	if u.Behaviors.AnyTLS.Enabled {
		if strings.TrimSpace(u.Behaviors.AnyTLS.Password) == "" {
			return fmt.Errorf("transport.uqsp.behaviors.anytls.password is required when anytls behavior is enabled")
		}
	}

	return nil
}

// UQSPEnabled returns true if UQSP transport is configured.
func (c *Config) UQSPEnabled() bool {
	return strings.ToLower(strings.TrimSpace(c.Transport.Type)) == "uqsp"
}

// UQSPRuntimeMode returns the runtime mode for UQSP transport.
func (c *Config) UQSPRuntimeMode() string {
	mode := strings.ToLower(strings.TrimSpace(c.Transport.UQSP.Runtime.Mode))
	if mode == "" {
		return "unified"
	}
	return mode
}

// UQSPCarrierConfig selects and configures the underlying transport carrier.
type UQSPCarrierConfig struct {
	// Type selects the carrier: "quic", "trusttunnel", "rawtcp", "faketcp", "icmptun", "webtunnel", "chisel"
	// Default is "quic" (native QUIC transport)
	Type string `yaml:"type"`

	// Fallback enables fallback to other carriers if the primary fails
	Fallback bool `yaml:"fallback"`

	// Type-specific configurations
	TrustTunnel TrustTunnelCarrierConfig `yaml:"trusttunnel"`
	RawTCP      RawTCPCarrierConfig      `yaml:"rawtcp"`
	FakeTCP     FakeTCPCarrierConfig     `yaml:"faketcp"`
	KCP         KCPBaseCarrierConfig     `yaml:"kcp"`
	ICMPTun     ICMPTunCarrierConfig     `yaml:"icmptun"`
	WebTunnel   WebTunnelCarrierConfig   `yaml:"webtunnel"`
	Chisel      ChiselCarrierConfig      `yaml:"chisel"`
	XHTTP       XHTTPCarrierConfig       `yaml:"xhttp"`
	AnyTLS      AnyTLSCarrierConfig      `yaml:"anytls"`
	MASQUE      MASQUECarrierConfig      `yaml:"masque"`
}

// KCPBaseCarrierConfig configures the standalone KCP carrier for mode 4d.
// It maps onto internal/transport/kcpbase.Config.
type KCPBaseCarrierConfig struct {
	Mode         string `yaml:"mode"`  // standard, brutal, awg, dtls
	Block        string `yaml:"block"` // none, aes, aes-128, salsa20, ...
	Key          string `yaml:"key"`
	DataShards   int    `yaml:"data_shards"`
	ParityShards int    `yaml:"parity_shards"`
	AutoTuneFEC  *bool  `yaml:"auto_tune_fec"`
	DSCP         int    `yaml:"dscp"`
	BatchEnabled *bool  `yaml:"batch_enabled"`
	BatchSize    int    `yaml:"batch_size"`
	Brutal       struct {
		BandwidthMbps int    `yaml:"bandwidth_mbps"`
		PacingMode    string `yaml:"pacing_mode"`
	} `yaml:"brutal"`
	AWG struct {
		JunkEnabled     *bool         `yaml:"junk_enabled"`
		JunkInterval    time.Duration `yaml:"junk_interval"`
		JunkMinSize     int           `yaml:"junk_min_size"`
		JunkMaxSize     int           `yaml:"junk_max_size"`
		PacketObfuscate *bool         `yaml:"packet_obfuscate"`
	} `yaml:"awg"`
	DTLS struct {
		MTU              int           `yaml:"mtu"`
		HandshakeTimeout time.Duration `yaml:"handshake_timeout"`
		FlightInterval   time.Duration `yaml:"flight_interval"`
	} `yaml:"dtls"`
}

// MASQUECarrierConfig configures MASQUE-over-QUIC as a carrier.
// It reuses the transport/masque QUIC profile and guard tagging to blend with
// HTTP/3 CONNECT-{UDP,IP}-like flows.
type MASQUECarrierConfig struct {
	ServerAddr string            `yaml:"server_addr"`
	Target     string            `yaml:"target"`
	TunnelType string            `yaml:"tunnel_type"` // udp, tcp, ip
	AuthToken  string            `yaml:"auth_token"`
	Headers    map[string]string `yaml:"headers"`
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

// FakeTCPCarrierConfig configures FakeTCP as a carrier (tcpraw/udp2raw-style).
type FakeTCPCarrierConfig struct {
	MTU                int                   `yaml:"mtu"`
	WindowSize         int                   `yaml:"window_size"`
	RTO                time.Duration         `yaml:"rto"`
	Keepalive          time.Duration         `yaml:"keepalive"`
	KeepaliveIdle      time.Duration         `yaml:"keepalive_idle"`
	FingerprintProfile string                `yaml:"fingerprint_profile"` // chrome_win10, safari_macos, linux_default, android, random
	CryptoKey          string                `yaml:"crypto_key"`
	AEADMode           string                `yaml:"aead_mode"` // off, chacha20poly1305, aesgcm
	FakeHTTP           FakeTCPFakeHTTPConfig `yaml:"fake_http"`
}

// FakeTCPFakeHTTPConfig configures fake HTTP preface for DPI evasion.
type FakeTCPFakeHTTPConfig struct {
	Enabled   *bool  `yaml:"enabled"`
	Host      string `yaml:"host"`
	UserAgent string `yaml:"user_agent"`
	Path      string `yaml:"path"`
}

// IsEnabled returns whether fake-HTTP preface should be applied.
// Nil means enabled by default.
func (c FakeTCPFakeHTTPConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
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
	Server                string              `yaml:"server"`
	Path                  string              `yaml:"path"`
	Mode                  string              `yaml:"mode"` // stream-one, stream-up, stream-down, packet-up
	Headers               map[string]string   `yaml:"headers"`
	MaxConns              int                 `yaml:"max_connections"`
	TLSInsecureSkipVerify bool                `yaml:"tls_insecure_skip_verify"`
	TLSServerName         string              `yaml:"tls_server_name"`
	TLSFingerprint        string              `yaml:"tls_fingerprint"`
	Metadata              XHTTPMetadataConfig `yaml:"metadata"`
	XMux                  XHTTPXMuxConfig     `yaml:"xmux"`
}

// AnyTLSCarrierConfig configures AnyTLS as a carrier.
type AnyTLSCarrierConfig struct {
	Server             string   `yaml:"server"`
	Password           string   `yaml:"password"`
	PaddingScheme      string   `yaml:"padding_scheme"` // random | fixed | burst | adaptive or custom lines
	PaddingMin         int      `yaml:"padding_min"`
	PaddingMax         int      `yaml:"padding_max"`
	PaddingLines       []string `yaml:"padding_lines"`
	IdleSessionTimeout int      `yaml:"idle_session_timeout"` // seconds
	TLSInsecureSkipVerify bool   `yaml:"tls_insecure_skip_verify"`
	TLSServerName         string `yaml:"tls_server_name"`
}

// XHTTPMetadataConfig controls where session/sequence/mode metadata is encoded.
type XHTTPMetadataConfig struct {
	Session XHTTPMetadataFieldConfig `yaml:"session"`
	Seq     XHTTPMetadataFieldConfig `yaml:"seq"`
	Mode    XHTTPMetadataFieldConfig `yaml:"mode"`
}

// XHTTPMetadataFieldConfig describes placement+key for one metadata field.
type XHTTPMetadataFieldConfig struct {
	Placement string `yaml:"placement"` // header, path, query, cookie
	Key       string `yaml:"key"`
}

// XHTTPXMuxConfig configures XMUX connection pooling for XHTTP.
type XHTTPXMuxConfig struct {
	Enabled          bool   `yaml:"enabled"`
	MaxConnections   int    `yaml:"max_connections"`
	MaxConcurrency   int    `yaml:"max_concurrency"`
	MaxConnectionAge int64  `yaml:"max_connection_age"`
	CMaxReuseTimes   int    `yaml:"c_max_reuse_times"`
	HMaxRequestTimes int    `yaml:"h_max_request_times"`
	HMaxReusableSecs int    `yaml:"h_max_reusable_secs"`
	DrainTimeout     string `yaml:"drain_timeout"` // duration string
}

// UQSPBehaviorConfig configures protocol behavior overlays.
type UQSPBehaviorConfig struct {
	ShadowTLS   ShadowTLSBehaviorConfig   `yaml:"shadowtls"`
	TLSMirror   TLSMirrorBehaviorConfig   `yaml:"tlsmirror"`
	AnyTLS      AnyTLSBehaviorConfig      `yaml:"anytls"`
	AWG         AWGBehaviorConfig         `yaml:"awg"`
	Reality     RealityBehaviorConfig     `yaml:"reality"`
	ECH         ECHBehaviorConfig         `yaml:"ech"`
	Obfs4       Obfs4BehaviorConfig       `yaml:"obfs4"`
	Vision      VisionBehaviorConfig      `yaml:"vision"`
	DomainFront DomainFrontBehaviorConfig `yaml:"domainfront"`
	TLSFrag     TLSFragBehaviorConfig     `yaml:"tlsfrag"`
	CSTP        CSTPBehaviorConfig        `yaml:"cstp"`
	ViolatedTCP ViolatedTCPBehaviorConfig `yaml:"violated_tcp"`
	QPP         QPPBehaviorConfig         `yaml:"qpp"`
}

// AnyTLSBehaviorConfig configures AnyTLS-style authenticated padded framing.
type AnyTLSBehaviorConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Password   string `yaml:"password"`
	PaddingMin int    `yaml:"padding_min"`
	PaddingMax int    `yaml:"padding_max"`
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

	JunkPacketCount           int             `yaml:"junk_packet_count"`
	InitPacketJunkSize        int             `yaml:"init_packet_junk_size"`
	ResponsePacketJunkSize    int             `yaml:"response_packet_junk_size"`
	CookieReplyPacketJunkSize int             `yaml:"cookie_reply_packet_junk_size"`
	TransportPacketJunkSize   int             `yaml:"transport_packet_junk_size"`
	MagicHeaders              *AWGMagicConfig `yaml:"magic_headers"`
	TimingObfuscation         bool            `yaml:"timing_obfuscation"`
	JitterMin                 time.Duration   `yaml:"jitter_min"`
	JitterMax                 time.Duration   `yaml:"jitter_max"`
	SpecialJunkOptional       *bool           `yaml:"special_junk_optional"`
}

type AWGMagicConfig struct {
	Init      string `yaml:"init"`
	Response  string `yaml:"response"`
	Underload string `yaml:"underload"`
	Transport string `yaml:"transport"`
}

// RealityBehaviorConfig ports XTLS REALITY behaviors as an overlay.
type RealityBehaviorConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Dest            string   `yaml:"dest"`
	ServerNames     []string `yaml:"server_names"`
	PrivateKey        string   `yaml:"private_key"`
	ServerPublicKey string   `yaml:"server_public_key"`
	ShortIDs          []string `yaml:"short_ids"`
	SpiderX           string   `yaml:"spider_x"`
	SpiderY           []int    `yaml:"spider_y"`
	SpiderConcurrency int      `yaml:"spider_concurrency"`
	SpiderTimeout     int      `yaml:"spider_timeout"`
	MaxDepth          int      `yaml:"max_depth"`
	MaxTotalFetches   int      `yaml:"max_total_fetches"`
	PerHostCap        int      `yaml:"per_host_cap"`
	Show              bool     `yaml:"show"`
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
	Role              string        `yaml:"role"` // "client" | "server" | "rendezvous"
	ClientAddress     string        `yaml:"client_address"`
	ServerAddress     string        `yaml:"server_address"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	ReconnectDelay    time.Duration `yaml:"reconnect_delay"`
	ReconnectBackoff  time.Duration `yaml:"reconnect_backoff"`   // Initial backoff delay (exponential)
	MaxReconnectDelay time.Duration `yaml:"max_reconnect_delay"` // Maximum backoff delay (default: 60s)
	MaxRetries        int           `yaml:"max_retries"`
	AuthToken         string        `yaml:"auth_token"`
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"` // Keepalive interval for persistent connections
}

type ViolatedTCPBehaviorConfig struct {
	Enabled           bool   `yaml:"enabled"`
	Mode              string `yaml:"mode"` // malformed, no_handshake, random_flags, broken_seq
	SeqRandomness     int    `yaml:"seq_randomness"`
	FlagCycling       bool   `yaml:"flag_cycling"`
	WindowJitter      int    `yaml:"window_jitter"`
	OptionRandom      bool   `yaml:"option_random"`
	FakeHTTPEnabled   bool   `yaml:"fake_http_enabled"`
	FakeHTTPHost      string `yaml:"fake_http_host"`
	FakeHTTPUserAgent string `yaml:"fake_http_user_agent"`
}

type QPPBehaviorConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Key      string `yaml:"key"`
	NumSBox  int    `yaml:"num_sbox"`
	AutoSync bool   `yaml:"auto_sync"`
}

func (c *UQSPConfig) GetReverse() UQSPReverseConfig {
	return c.Reverse
}

// variantPolicyFor returns the per-variant policy for the given variant name,
// or a zero-value policy if none is configured.
func (c *UQSPConfig) variantPolicyFor(variant string) UQSPVariantPolicy {
	if c.VariantPolicy == nil {
		return UQSPVariantPolicy{}
	}
	return c.VariantPolicy[strings.ToLower(strings.TrimSpace(variant))]
}

// WARPEnabledForVariant returns whether WARP should be enabled for the given
// variant.  The per-variant policy overrides the global config if set.
func (c *UQSPConfig) WARPEnabledForVariant(variant string, globalWARP bool) bool {
	p := c.variantPolicyFor(variant)
	if p.WARPEnabled != nil {
		return *p.WARPEnabled
	}
	return globalWARP
}

// ReverseEnabledForVariant returns whether reverse mode should be enabled for
// the given variant.  The per-variant policy overrides the global config if set.
func (c *UQSPConfig) ReverseEnabledForVariant(variant string) bool {
	p := c.variantPolicyFor(variant)
	if p.ReverseEnabled != nil {
		return *p.ReverseEnabled
	}
	return c.Reverse.Enabled
}
