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
	Streams        bool // supports multiplexed streams
	Datagrams      bool // supports native datagrams (unreliable)
	Capsules       bool // supports CONNECT-UDP / CONNECT-IP style capsules
	ReverseConnect bool // supports reverse-connect topology
	WARPUnderlay   bool // supports WARP underlay dialer (policy-controlled)
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

// Mode4aProfile defines the HTTP-family profile (stream-first).
var Mode4aProfile = ModeProfile{
	Mode:        VariantHTTPPlus,
	Name:        "HTTP-Family (XHTTP)",
	Description: "Stream-first profile using XHTTP-style carrier defaults",
	Carrier: CarrierProfile{
		Type:              "xhttp",
		Protocol:          "HTTP/2",
		Handshake:         "TLS 1.3",
		Obfuscation:       []string{"rotation", "pooling"},
		CongestionControl: "tcp",
		Reliability:       "tcp",
		Mux:               "smux (in-core)",
	},
	Capabilities: ModeCapabilities{
		Streams:        true,
		Datagrams:      false,
		Capsules:       false,
		ReverseConnect: true,
		WARPUnderlay:   true,
	},
	Defaults: ModeDefaults{
		MTU:               1400, // 1500 - 100 (HTTP/2 + TLS overhead)
		CongestionControl: "tcp",
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

// Mode4bProfile defines the raw TCP-family profile (stream-first).
var Mode4bProfile = ModeProfile{
	Mode:        VariantTCPPlus,
	Name:        "Raw TCP-Family",
	Description: "Stream-first profile using rawtcp / faketcp / icmptun carriers",
	Carrier: CarrierProfile{
		Type:              "rawtcp",
		Protocol:          "TCP",
		Handshake:         "TCP",
		Obfuscation:       []string{"tuning"},
		CongestionControl: "tcp",
		Reliability:       "tcp",
		Mux:               "smux (in-core)",
	},
	Capabilities: ModeCapabilities{
		Streams:        true,
		Datagrams:      false,
		Capsules:       false,
		ReverseConnect: true,
		WARPUnderlay:   true,
	},
	Defaults: ModeDefaults{
		MTU:               1400,
		CongestionControl: "tcp",
		Reliability:       "tcp",
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

// Mode4cProfile defines the TLS look-alike profile (stream-first).
var Mode4cProfile = ModeProfile{
	Mode:        VariantTLSPlus,
	Name:        "TLS Look-Alike Family",
	Description: "Stream-first profile using TLS look-alike overlays (Reality / ShadowTLS / AnyTLS)",
	Carrier: CarrierProfile{
		Type:              "xhttp",
		Protocol:          "TLS",
		Handshake:         "TLS 1.3",
		Obfuscation:       []string{"tuning"},
		CongestionControl: "tcp",
		Reliability:       "tcp",
		Mux:               "smux (in-core)",
	},
	Capabilities: ModeCapabilities{
		Streams:        true,
		Datagrams:      false,
		Capsules:       false,
		ReverseConnect: true,
		WARPUnderlay:   true,
	},
	Defaults: ModeDefaults{
		MTU:               1400, // 1500 - 100 (TLS + REALITY overhead)
		CongestionControl: "tcp",
		Reliability:       "tcp",
		MuxEnabled:        true,
		RotationEnabled:   true,
		PaddingEnabled:    false,
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

// Mode4dProfile defines the UDP/QUIC-family profile (datagram-first).
var Mode4dProfile = ModeProfile{
	Mode:        VariantUDPPlus,
	Name:        "UDP/QUIC Family",
	Description: "Datagram-capable profile (QUIC DATAGRAM) with CONNECT-UDP/IP capsules enabled by default",
	Carrier: CarrierProfile{
		Type:              "quic",
		Protocol:          "QUIC",
		Handshake:         "QUIC",
		Obfuscation:       []string{"tuning"},
		CongestionControl: "quic",
		Reliability:       "quic",
		Mux:               "quic streams",
	},
	Capabilities: ModeCapabilities{
		Streams:        true,
		Datagrams:      true,
		Capsules:       true,
		ReverseConnect: true,
		WARPUnderlay:   true,
	},
	Defaults: ModeDefaults{
		MTU:               1450, // 1500 - 50 (QUIC header + encryption)
		CongestionControl: "quic",
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

// Mode4eProfile defines the TLS-tunnel family profile (stream-first).
var Mode4eProfile = ModeProfile{
	Mode:        VariantTLS,
	Name:        "TLS-Tunnel Family (TrustTunnel)",
	Description: "Stream-first profile using trusttunnel-style carrier defaults",
	Carrier: CarrierProfile{
		Type:              "trusttunnel",
		Protocol:          "TLS tunnel",
		Handshake:         "TLS",
		Obfuscation:       []string{"tuning"},
		CongestionControl: "tcp",
		Reliability:       "tcp",
		Mux:               "smux (in-core)",
	},
	Capabilities: ModeCapabilities{
		Streams:        true,
		Datagrams:      false,
		Capsules:       false,
		ReverseConnect: true,
		WARPUnderlay:   true,
	},
	Defaults: ModeDefaults{
		MTU:               1380, // 1500 - 120 (HTTP/2 + ICMP mux overhead)
		CongestionControl: "tcp",
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
		VariantHTTPPlus: Mode4aProfile,
		VariantTCPPlus:  Mode4bProfile,
		VariantTLSPlus:  Mode4cProfile,
		VariantUDPPlus:  Mode4dProfile,
		VariantTLS:      Mode4eProfile,
	}
	canonical, ok := canonicalVariantName(mode)
	if !ok {
		return ModeProfile{}, false
	}
	profile, ok := profiles[canonical]
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
				Capability: "Streams",
				Mode4a:     Mode4aProfile.Capabilities.Streams,
				Mode4b:     Mode4bProfile.Capabilities.Streams,
				Mode4c:     Mode4cProfile.Capabilities.Streams,
				Mode4d:     Mode4dProfile.Capabilities.Streams,
				Mode4e:     Mode4eProfile.Capabilities.Streams,
			},
			{
				Capability: "Datagrams",
				Mode4a:     Mode4aProfile.Capabilities.Datagrams,
				Mode4b:     Mode4bProfile.Capabilities.Datagrams,
				Mode4c:     Mode4cProfile.Capabilities.Datagrams,
				Mode4d:     Mode4dProfile.Capabilities.Datagrams,
				Mode4e:     Mode4eProfile.Capabilities.Datagrams,
			},
			{
				Capability: "Capsules",
				Mode4a:     Mode4aProfile.Capabilities.Capsules,
				Mode4b:     Mode4bProfile.Capabilities.Capsules,
				Mode4c:     Mode4cProfile.Capabilities.Capsules,
				Mode4d:     Mode4dProfile.Capabilities.Capsules,
				Mode4e:     Mode4eProfile.Capabilities.Capsules,
			},
			{
				Capability: "ReverseConnect",
				Mode4a:     Mode4aProfile.Capabilities.ReverseConnect,
				Mode4b:     Mode4bProfile.Capabilities.ReverseConnect,
				Mode4c:     Mode4cProfile.Capabilities.ReverseConnect,
				Mode4d:     Mode4dProfile.Capabilities.ReverseConnect,
				Mode4e:     Mode4eProfile.Capabilities.ReverseConnect,
			},
			{
				Capability: "WARPUnderlay",
				Mode4a:     Mode4aProfile.Capabilities.WARPUnderlay,
				Mode4b:     Mode4bProfile.Capabilities.WARPUnderlay,
				Mode4c:     Mode4cProfile.Capabilities.WARPUnderlay,
				Mode4d:     Mode4dProfile.Capabilities.WARPUnderlay,
				Mode4e:     Mode4eProfile.Capabilities.WARPUnderlay,
			},
		},
	}
}
