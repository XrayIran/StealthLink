package config

import "time"

// ModeProfile defines the canonical configuration for a StealthLink mode
type ModeProfile struct {
	Mode         string
	Name         string
	Description  string
	Carrier      CarrierProfile
	Capabilities ModeCapabilities
	Defaults     ModeDefaults
}

// CarrierProfile defines carrier-specific configuration
type CarrierProfile struct {
	Type              string
	Protocol          string
	Handshake         string
	Obfuscation       []string
	CongestionControl string
	Reliability       string
	Mux               string
}

// ModeCapabilities defines what a mode supports
type ModeCapabilities struct {
	StreamOriented   bool
	ZeroRTT          bool
	ReplayProtection bool
	PathMigration    bool
	Multipath        bool
	ServerInitiated  bool
	Fronting         bool
	CoverTraffic     bool
}

// ModeDefaults defines default configuration values for a mode
type ModeDefaults struct {
	MTU               int
	CongestionControl string
	Reliability       string
	MuxEnabled        bool
	RotationEnabled   bool
	PaddingEnabled    bool
}

// Mode4aProfile defines the XHTTP + Domain Fronting profile
var Mode4aProfile = ModeProfile{
	Mode:        "4a",
	Name:        "XHTTP + Domain Fronting",
	Description: "HTTP/2 over TLS with flexible metadata placement and connection rotation",
	Carrier: CarrierProfile{
		Type:              "xhttp",
		Protocol:          "HTTP/2",
		Handshake:         "TLS 1.3",
		Obfuscation:       []string{"domain-fronting", "metadata-placement", "xmux-rotation"},
		CongestionControl: "cubic",
		Reliability:       "tcp",
		Mux:               "smux",
	},
	Capabilities: ModeCapabilities{
		StreamOriented:   true,
		ZeroRTT:          true, // via TLS 1.3
		ReplayProtection: false,
		PathMigration:    false,
		Multipath:        false,
		ServerInitiated:  true,
		Fronting:         true,
		CoverTraffic:     false,
	},
	Defaults: ModeDefaults{
		MTU:               1400, // 1500 - 100 (HTTP/2 + TLS overhead)
		CongestionControl: "cubic",
		Reliability:       "tcp",
		MuxEnabled:        true,
		RotationEnabled:   true,
		PaddingEnabled:    false,
	},
}

// Mode4aConfig defines XHTTP-specific configuration
type Mode4aConfig struct {
	// Metadata Placement
	SessionPlacement  string `yaml:"session_placement"`  // path | query | header | cookie
	SessionKey        string `yaml:"session_key"`        // custom key name
	SequencePlacement string `yaml:"sequence_placement"` // path | query | header | cookie
	SequenceKey       string `yaml:"sequence_key"`       // custom key name

	// Xmux Connection Lifecycle
	XmuxEnabled      bool          `yaml:"xmux_enabled"`
	CMaxReuseTimes   int           `yaml:"c_max_reuse_times"`   // default: 32
	HMaxRequestTimes int           `yaml:"h_max_request_times"` // default: 100
	HMaxReusableSecs int           `yaml:"h_max_reusable_secs"` // default: 3600
	DrainTimeout     time.Duration `yaml:"drain_timeout"`       // default: 30s

	// Domain Fronting
	FrontingEnabled bool   `yaml:"fronting_enabled"`
	FrontingDomain  string `yaml:"fronting_domain"` // CDN domain for fronting
	TargetDomain    string `yaml:"target_domain"`   // actual target domain
}

// DefaultMode4aConfig returns default configuration for Mode 4a
func DefaultMode4aConfig() Mode4aConfig {
	return Mode4aConfig{
		SessionPlacement:  "header",
		SessionKey:        "X-Session-ID",
		SequencePlacement: "header",
		SequenceKey:       "X-Seq",
		XmuxEnabled:       true,
		CMaxReuseTimes:    32,
		HMaxRequestTimes:  100,
		HMaxReusableSecs:  3600,
		DrainTimeout:      30 * time.Second,
		FrontingEnabled:   false,
		FrontingDomain:    "",
		TargetDomain:      "",
	}
}

// Mode4bProfile defines the FakeTCP + Anti-DPI profile
var Mode4bProfile = ModeProfile{
	Mode:        "4b",
	Name:        "FakeTCP + Anti-DPI",
	Description: "UDP with TCP mimicry, directional encryption, and batch I/O",
	Carrier: CarrierProfile{
		Type:              "faketcp",
		Protocol:          "UDP",
		Handshake:         "Fake TCP 3-way",
		Obfuscation:       []string{"tcp-fingerprint", "fake-http-preface", "directional-hkdf", "aead"},
		CongestionControl: "none",
		Reliability:       "faketcp",
		Mux:               "smux",
	},
	Capabilities: ModeCapabilities{
		StreamOriented:   false,
		ZeroRTT:          false,
		ReplayProtection: true, // via AEAD
		PathMigration:    false,
		Multipath:        false,
		ServerInitiated:  true,
		Fronting:         false,
		CoverTraffic:     false,
	},
	Defaults: ModeDefaults{
		MTU:               1460, // 1500 - 24 (FakeTCP header) - 16 (AEAD tag)
		CongestionControl: "none",
		Reliability:       "faketcp",
		MuxEnabled:        true,
		RotationEnabled:   false,
		PaddingEnabled:    false,
	},
}

// Mode4bConfig defines FakeTCP-specific configuration
type Mode4bConfig struct {
	// Crypto Configuration
	SharedSecret string `yaml:"shared_secret"` // shared secret for key derivation
	AEADMode     string `yaml:"aead_mode"`     // off | chacha20poly1305 | aesgcm

	// Batch I/O
	BatchIOEnabled bool `yaml:"batch_io_enabled"`
	BatchSize      int  `yaml:"batch_size"` // 1-64, default: 32

	// TCP Mimicry
	FakeHTTPPreface bool   `yaml:"fake_http_preface"` // send fake HTTP request
	TCPFingerprint  string `yaml:"tcp_fingerprint"`   // linux | windows | macos

	// Anti-DPI
	FragmentEnabled bool `yaml:"fragment_enabled"` // fragment initial packets
	FragmentSize    int  `yaml:"fragment_size"`    // bytes per fragment
}

// DefaultMode4bConfig returns default configuration for Mode 4b
func DefaultMode4bConfig() Mode4bConfig {
	return Mode4bConfig{
		SharedSecret:    "",
		AEADMode:        "chacha20poly1305",
		BatchIOEnabled:  true,
		BatchSize:       32,
		FakeHTTPPreface: true,
		TCPFingerprint:  "linux",
		FragmentEnabled: false,
		FragmentSize:    0,
	}
}

// Mode4cProfile defines the TLS-Like + REALITY/AnyTLS profile
var Mode4cProfile = ModeProfile{
	Mode:        "4c",
	Name:        "TLS-Like + REALITY/AnyTLS",
	Description: "TLS 1.3 with REALITY spider or AnyTLS padding for fingerprint resistance",
	Carrier: CarrierProfile{
		Type:              "tls-like",
		Protocol:          "TLS 1.3",
		Handshake:         "REALITY/AnyTLS",
		Obfuscation:       []string{"reality-spider", "anytls-padding", "tls-fingerprint-variation"},
		CongestionControl: "cubic",
		Reliability:       "tcp",
		Mux:               "smux",
	},
	Capabilities: ModeCapabilities{
		StreamOriented:   true,
		ZeroRTT:          true, // via TLS 1.3
		ReplayProtection: false,
		PathMigration:    false,
		Multipath:        false,
		ServerInitiated:  true,
		Fronting:         false,
		CoverTraffic:     true, // via padding
	},
	Defaults: ModeDefaults{
		MTU:               1400, // 1500 - 100 (TLS + REALITY overhead)
		CongestionControl: "cubic",
		Reliability:       "tcp",
		MuxEnabled:        true,
		RotationEnabled:   true,
		PaddingEnabled:    true,
	},
}

// Mode4cConfig defines TLS-Like-specific configuration
type Mode4cConfig struct {
	// Mode Selection
	TLSMode string `yaml:"tls_mode"` // reality | anytls

	// REALITY Configuration
	REALITYEnabled    bool    `yaml:"reality_enabled"`
	SpiderX           string  `yaml:"spider_x"`           // initial URL seed
	SpiderY           [10]int `yaml:"spider_y"`           // timing array in milliseconds
	SpiderConcurrency int     `yaml:"spider_concurrency"` // default: 4
	SpiderTimeout     int     `yaml:"spider_timeout"`     // seconds, default: 10
	MaxDepth          int     `yaml:"max_depth"`          // default: 3
	MaxTotalFetches   int     `yaml:"max_total_fetches"`  // default: 20
	PerHostCap        int     `yaml:"per_host_cap"`       // default: 5

	// AnyTLS Configuration
	AnyTLSEnabled      bool   `yaml:"anytls_enabled"`
	PaddingScheme      string `yaml:"padding_scheme"`       // random | fixed | burst | adaptive
	PaddingMin         int    `yaml:"padding_min"`          // default: 100
	PaddingMax         int    `yaml:"padding_max"`          // default: 900
	IdleSessionTimeout int    `yaml:"idle_session_timeout"` // seconds, default: 300

	// Connection Rotation
	RotationEnabled  bool `yaml:"rotation_enabled"`
	RotationInterval int  `yaml:"rotation_interval"` // seconds
}

// DefaultMode4cConfig returns default configuration for Mode 4c
func DefaultMode4cConfig() Mode4cConfig {
	return Mode4cConfig{
		TLSMode:            "reality",
		REALITYEnabled:     true,
		SpiderX:            "https://www.example.com",
		SpiderY:            [10]int{50, 100, 200, 300, 500, 800, 1000, 1500, 2000, 3000},
		SpiderConcurrency:  4,
		SpiderTimeout:      10,
		MaxDepth:           3,
		MaxTotalFetches:    20,
		PerHostCap:         5,
		AnyTLSEnabled:      false,
		PaddingScheme:      "random",
		PaddingMin:         100,
		PaddingMax:         900,
		IdleSessionTimeout: 300,
		RotationEnabled:    true,
		RotationInterval:   3600,
	}
}

// Mode4dProfile defines the QUIC + Brutal CC profile
var Mode4dProfile = ModeProfile{
	Mode:        "4d",
	Name:        "QUIC + Brutal CC",
	Description: "QUIC with Brutal congestion control, FEC, hardware entropy, and batch I/O",
	Carrier: CarrierProfile{
		Type:              "quic",
		Protocol:          "QUIC",
		Handshake:         "QUIC 0-RTT",
		Obfuscation:       []string{"awg-junk-packets", "brutal-cc"},
		CongestionControl: "brutal",
		Reliability:       "quic",
		Mux:               "quic-streams",
	},
	Capabilities: ModeCapabilities{
		StreamOriented:   true,
		ZeroRTT:          true, // via QUIC 0-RTT
		ReplayProtection: true, // built into QUIC
		PathMigration:    true,
		Multipath:        true,
		ServerInitiated:  true,
		Fronting:         false,
		CoverTraffic:     true, // via junk packets
	},
	Defaults: ModeDefaults{
		MTU:               1450, // 1500 - 50 (QUIC header + encryption)
		CongestionControl: "brutal",
		Reliability:       "quic",
		MuxEnabled:        false, // QUIC has native streams
		RotationEnabled:   false, // uses connection migration instead
		PaddingEnabled:    false,
	},
}

// Mode4dConfig defines QUIC-specific configuration
type Mode4dConfig struct {
	// Brutal Congestion Control
	BrutalEnabled   bool `yaml:"brutal_enabled"`
	BrutalBandwidth int  `yaml:"brutal_bandwidth"` // Mbps, fixed bandwidth

	// FEC Configuration
	FECEnabled   bool `yaml:"fec_enabled"`
	DataShards   int  `yaml:"data_shards"`   // default: 10
	ParityShards int  `yaml:"parity_shards"` // default: 3
	AutoTune     bool `yaml:"auto_tune"`
	ParitySkip   bool `yaml:"parity_skip"`

	// Hardware Entropy
	EntropyAccelerated bool `yaml:"entropy_accelerated"` // use AES-NI/ChaCha8

	// Batch I/O
	BatchIOEnabled bool `yaml:"batch_io_enabled"`
	BatchSize      int  `yaml:"batch_size"` // 1-64, default: 32

	// Connection Migration
	MigrationEnabled bool `yaml:"migration_enabled"`
	MultipathEnabled bool `yaml:"multipath_enabled"`

	// AWG Junk Packets
	JunkPacketsEnabled bool `yaml:"junk_packets_enabled"`
	JunkPacketRate     int  `yaml:"junk_packet_rate"` // packets per second
}

// DefaultMode4dConfig returns default configuration for Mode 4d
func DefaultMode4dConfig() Mode4dConfig {
	return Mode4dConfig{
		BrutalEnabled:      true,
		BrutalBandwidth:    100, // 100 Mbps
		FECEnabled:         true,
		DataShards:         10,
		ParityShards:       3,
		AutoTune:           true,
		ParitySkip:         true,
		EntropyAccelerated: true,
		BatchIOEnabled:     true,
		BatchSize:          32,
		MigrationEnabled:   true,
		MultipathEnabled:   false,
		JunkPacketsEnabled: false,
		JunkPacketRate:     0,
	}
}

// Mode4eProfile defines the TrustTunnel + CSTP profile
var Mode4eProfile = ModeProfile{
	Mode:        "4e",
	Name:        "TrustTunnel + CSTP",
	Description: "HTTP/2 or HTTP/3 CONNECT with ICMP multiplexing and session recovery",
	Carrier: CarrierProfile{
		Type:              "trusttunnel",
		Protocol:          "HTTP/2 or HTTP/3",
		Handshake:         "HTTP CONNECT + CSTP",
		Obfuscation:       []string{"icmp-mux", "http-connect"},
		CongestionControl: "cubic", // or QUIC if HTTP/3
		Reliability:       "tcp",   // or QUIC if HTTP/3
		Mux:               "trusttunnel-icmp",
	},
	Capabilities: ModeCapabilities{
		StreamOriented:   true,
		ZeroRTT:          true, // via HTTP/3
		ReplayProtection: false,
		PathMigration:    false,
		Multipath:        false,
		ServerInitiated:  true,
		Fronting:         false,
		CoverTraffic:     false,
	},
	Defaults: ModeDefaults{
		MTU:               1380, // 1500 - 120 (HTTP/2 + ICMP mux overhead)
		CongestionControl: "cubic",
		Reliability:       "tcp",
		MuxEnabled:        false, // uses ICMP mux instead
		RotationEnabled:   false,
		PaddingEnabled:    false,
	},
}

// Mode4eConfig defines TrustTunnel-specific configuration
type Mode4eConfig struct {
	// Protocol Selection
	HTTPVersion string `yaml:"http_version"` // http2 | http3

	// CSTP Configuration
	CSTPEnabled bool   `yaml:"cstp_enabled"`
	CSTPPath    string `yaml:"cstp_path"` // CONNECT path

	// ICMP Multiplexing
	ICMPMuxEnabled bool   `yaml:"icmp_mux_enabled"`
	ICMPMuxMode    string `yaml:"icmp_mux_mode"` // echo | timestamp

	// Session Recovery
	SessionRecoveryEnabled bool `yaml:"session_recovery_enabled"`
	RecoveryTimeout        int  `yaml:"recovery_timeout"`      // seconds, default: 60
	MaxRecoveryAttempts    int  `yaml:"max_recovery_attempts"` // default: 3

	// Reconnection
	ReconnectEnabled bool `yaml:"reconnect_enabled"`
	ReconnectBackoff int  `yaml:"reconnect_backoff"` // seconds, exponential backoff base
}

// DefaultMode4eConfig returns default configuration for Mode 4e
func DefaultMode4eConfig() Mode4eConfig {
	return Mode4eConfig{
		HTTPVersion:            "http2",
		CSTPEnabled:            true,
		CSTPPath:               "/tunnel",
		ICMPMuxEnabled:         true,
		ICMPMuxMode:            "echo",
		SessionRecoveryEnabled: true,
		RecoveryTimeout:        60,
		MaxRecoveryAttempts:    3,
		ReconnectEnabled:       true,
		ReconnectBackoff:       1,
	}
}

// AllModeProfiles returns all 5 mode profiles
func AllModeProfiles() []ModeProfile {
	return []ModeProfile{
		Mode4aProfile,
		Mode4bProfile,
		Mode4cProfile,
		Mode4dProfile,
		Mode4eProfile,
	}
}

// GetModeProfile returns the profile for a given mode
func GetModeProfile(mode string) (ModeProfile, bool) {
	profiles := map[string]ModeProfile{
		"4a": Mode4aProfile,
		"4b": Mode4bProfile,
		"4c": Mode4cProfile,
		"4d": Mode4dProfile,
		"4e": Mode4eProfile,
	}
	profile, ok := profiles[mode]
	return profile, ok
}

// CapabilityMatrix represents the capability comparison across all modes
type CapabilityMatrix struct {
	Capabilities []CapabilityRow
}

// CapabilityRow represents a single capability across all modes
type CapabilityRow struct {
	Capability string
	Mode4a     bool
	Mode4b     bool
	Mode4c     bool
	Mode4d     bool
	Mode4e     bool
}

// GetCapabilityMatrix returns the capability matrix for all 5 modes
func GetCapabilityMatrix() CapabilityMatrix {
	return CapabilityMatrix{
		Capabilities: []CapabilityRow{
			{
				Capability: "StreamOriented",
				Mode4a:     Mode4aProfile.Capabilities.StreamOriented,
				Mode4b:     Mode4bProfile.Capabilities.StreamOriented,
				Mode4c:     Mode4cProfile.Capabilities.StreamOriented,
				Mode4d:     Mode4dProfile.Capabilities.StreamOriented,
				Mode4e:     Mode4eProfile.Capabilities.StreamOriented,
			},
			{
				Capability: "ZeroRTT",
				Mode4a:     Mode4aProfile.Capabilities.ZeroRTT,
				Mode4b:     Mode4bProfile.Capabilities.ZeroRTT,
				Mode4c:     Mode4cProfile.Capabilities.ZeroRTT,
				Mode4d:     Mode4dProfile.Capabilities.ZeroRTT,
				Mode4e:     Mode4eProfile.Capabilities.ZeroRTT,
			},
			{
				Capability: "ReplayProtection",
				Mode4a:     Mode4aProfile.Capabilities.ReplayProtection,
				Mode4b:     Mode4bProfile.Capabilities.ReplayProtection,
				Mode4c:     Mode4cProfile.Capabilities.ReplayProtection,
				Mode4d:     Mode4dProfile.Capabilities.ReplayProtection,
				Mode4e:     Mode4eProfile.Capabilities.ReplayProtection,
			},
			{
				Capability: "PathMigration",
				Mode4a:     Mode4aProfile.Capabilities.PathMigration,
				Mode4b:     Mode4bProfile.Capabilities.PathMigration,
				Mode4c:     Mode4cProfile.Capabilities.PathMigration,
				Mode4d:     Mode4dProfile.Capabilities.PathMigration,
				Mode4e:     Mode4eProfile.Capabilities.PathMigration,
			},
			{
				Capability: "Multipath",
				Mode4a:     Mode4aProfile.Capabilities.Multipath,
				Mode4b:     Mode4bProfile.Capabilities.Multipath,
				Mode4c:     Mode4cProfile.Capabilities.Multipath,
				Mode4d:     Mode4dProfile.Capabilities.Multipath,
				Mode4e:     Mode4eProfile.Capabilities.Multipath,
			},
			{
				Capability: "ServerInitiated",
				Mode4a:     Mode4aProfile.Capabilities.ServerInitiated,
				Mode4b:     Mode4bProfile.Capabilities.ServerInitiated,
				Mode4c:     Mode4cProfile.Capabilities.ServerInitiated,
				Mode4d:     Mode4dProfile.Capabilities.ServerInitiated,
				Mode4e:     Mode4eProfile.Capabilities.ServerInitiated,
			},
			{
				Capability: "Fronting",
				Mode4a:     Mode4aProfile.Capabilities.Fronting,
				Mode4b:     Mode4bProfile.Capabilities.Fronting,
				Mode4c:     Mode4cProfile.Capabilities.Fronting,
				Mode4d:     Mode4dProfile.Capabilities.Fronting,
				Mode4e:     Mode4eProfile.Capabilities.Fronting,
			},
			{
				Capability: "CoverTraffic",
				Mode4a:     Mode4aProfile.Capabilities.CoverTraffic,
				Mode4b:     Mode4bProfile.Capabilities.CoverTraffic,
				Mode4c:     Mode4cProfile.Capabilities.CoverTraffic,
				Mode4d:     Mode4dProfile.Capabilities.CoverTraffic,
				Mode4e:     Mode4eProfile.Capabilities.CoverTraffic,
			},
		},
	}
}
