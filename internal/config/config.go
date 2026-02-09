package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"stealthlink/internal/vpn"
	"stealthlink/internal/warp"
)

type Config struct {
	Role             string                 `yaml:"role"`
	Gateway          Gateway                `yaml:"gateway"`
	Agent            Agent                  `yaml:"agent"`
	Transport        Transport              `yaml:"transport"`
	Mux              Mux                    `yaml:"mux"`
	Services         []Service              `yaml:"services"`
	Logging          Logging                `yaml:"logging"`
	Security         Security               `yaml:"security"`
	Auth             AuthConfig             `yaml:"auth"`
	TransparentProxy TransparentProxyConfig `yaml:"transparent_proxy"`
	Obfuscation      ObfuscationConfig      `yaml:"obfuscation"`
	HostOpt          HostOptConfig          `yaml:"host_opt"`
	Metrics          Metrics                `yaml:"metrics"`
	VPN              vpn.Config             `yaml:"vpn"`
	WARP             warp.Config            `yaml:"warp"`
}

type Gateway struct {
	Listen     string           `yaml:"listen"`
	Masquerade MasqueradeConfig `yaml:"masquerade"`
}

// MasqueradeConfig configures backend masquerade behavior.
type MasqueradeConfig struct {
	Enabled         bool              `yaml:"enabled"`
	BackendURL      string            `yaml:"backend_url"`      // URL to proxy to when auth fails
	HealthEndpoint  string            `yaml:"health_endpoint"`  // Health check endpoint
	VersionEndpoint string            `yaml:"version_endpoint"` // Version endpoint
	StaticFiles     map[string]string `yaml:"static_files"`     // Static file mappings
	IndexFile       string            `yaml:"index_file"`       // Index file for root path
	StatusCode      int               `yaml:"status_code"`      // Status code for fallback
	ResponseBody    string            `yaml:"response_body"`    // Response body for fallback
	Headers         map[string]string `yaml:"headers"`          // Headers to add to responses
}

type Agent struct {
	ID               string `yaml:"id"`
	GatewayAddr      string `yaml:"gateway_addr"`
	ReconnectBackoff string `yaml:"reconnect_backoff"`
}

type Transport struct {
	Type         string                `yaml:"type"`
	Stealth      StealthConfig         `yaml:"stealth"`
	UQSP         UQSPConfig            `yaml:"uqsp"`
	Experimental bool                  `yaml:"experimental"`
	Guard        string                `yaml:"guard"`
	Proxy        Proxy                 `yaml:"proxy"`
	TFO          TFOConfig             `yaml:"tfo"`
	TCP          TCPOptimizationConfig `yaml:"tcp"`
	DSCP         DSCPConfig            `yaml:"dscp"`
	TLS          TLSConfig             `yaml:"tls"`
	ShadowTLS    ShadowTLSConfig       `yaml:"shadowtls"`
	Reality      RealityConfig         `yaml:"reality"`
	DTLS         DTLSConfig            `yaml:"dtls"`
	QUIC         QUICConfig            `yaml:"quic"`
	MASQUE       MASQUEConfig          `yaml:"masque"`
	Auto         AutoTransportConfig   `yaml:"auto"`
	WSS          WSSConfig             `yaml:"wss"`
	H2           H2Config              `yaml:"h2"`
	XHTTP        XHTTPConfig           `yaml:"xhttp"`
	TLSMirror    TLSMirrorConfig       `yaml:"tlsmirror"`
	AWGObfs      AWGObfsConfig         `yaml:"awg_obfs"`
	RawAdapter   RawAdapterConfig      `yaml:"raw_adapter"`
	Pipeline     PipelineConfig        `yaml:"pipeline"`
	KCP          KCPConfig             `yaml:"kcp"`
	RawTCP       RawTCPConfig          `yaml:"rawtcp"`
	FakeDNS      FakeDNSConfig         `yaml:"fakedns"`
	Obfs         ObfsConfig            `yaml:"obfs"`
	Noize        NoizeConfig           `yaml:"noize"`
	QPP          QPPConfig             `yaml:"qpp"`
	HalfDuplex   HalfDuplexConfig      `yaml:"halfduplex"`
}

// TFOConfig configures TCP Fast Open.
type TFOConfig struct {
	Enabled   bool `yaml:"enabled"`
	QueueSize int  `yaml:"queue_size"` // TFO queue size (default: 1024)
}

// TCPOptimizationConfig configures TCP performance optimizations.
type TCPOptimizationConfig struct {
	Enabled             bool   `yaml:"enabled"`              // Enable TCP optimizations
	CongestionAlgorithm string `yaml:"congestion_algorithm"` // bbr, bbrv3, cubic, hybla, reno
	ReadBufferSize      int    `yaml:"read_buffer_size"`     // TCP read buffer (0 = system default)
	WriteBufferSize     int    `yaml:"write_buffer_size"`    // TCP write buffer (0 = system default)
	NoDelay             bool   `yaml:"no_delay"`             // Disable Nagle's algorithm
	QuickAck            bool   `yaml:"quick_ack"`            // Enable quick ACK
	KeepAlive           bool   `yaml:"keep_alive"`           // Enable TCP keepalive
	KeepAliveIdle       int    `yaml:"keep_alive_idle"`      // Keepalive idle time in seconds
	KeepAliveInterval   int    `yaml:"keep_alive_interval"`  // Keepalive interval in seconds
	KeepAliveCount      int    `yaml:"keep_alive_count"`     // Keepalive probe count
	MaxSegmentSize      int    `yaml:"max_segment_size"`     // TCP MSS (0 = system default)
	WindowScaling       bool   `yaml:"window_scaling"`       // Enable window scaling
	Timestamp           bool   `yaml:"timestamp"`            // Enable TCP timestamps
	SACK                bool   `yaml:"sack"`                 // Enable SACK
	FastOpen            bool   `yaml:"fast_open"`            // Enable TCP Fast Open on socket
	FastOpenConnect     bool   `yaml:"fast_open_connect"`    // Use TFO for outgoing connections
}

// DSCPConfig configures DSCP/TOS traffic marking.
type DSCPConfig struct {
	Enabled     bool   `yaml:"enabled"`      // Enable DSCP marking
	Value       int    `yaml:"value"`        // DSCP value (0-63)
	Class       string `yaml:"class"`        // Traffic class: default, low, bulk, best-effort, critical, realtime, network-control, expedited
	MarkControl bool   `yaml:"mark_control"` // Mark control traffic separately
	MarkData    bool   `yaml:"mark_data"`    // Mark data traffic
	ControlDSCP int    `yaml:"control_dscp"` // DSCP for control traffic (default: 48/CS6)
	DataDSCP    int    `yaml:"data_dscp"`    // DSCP for data traffic (default: 46/EF)
}

type Proxy struct {
	// URL supports schemes: http, https, socks5, socks5h. Empty disables proxy.
	URL string `yaml:"url"`
}

type TLSConfig struct {
	CertFile           string                 `yaml:"cert_file"`
	KeyFile            string                 `yaml:"key_file"`
	CAFile             string                 `yaml:"ca_file"`
	ServerName         string                 `yaml:"server_name"`
	InsecureSkipVerify bool                   `yaml:"insecure_skip_verify"`
	Fingerprint        string                 `yaml:"fingerprint"`
	Fragment           TLSFragmentConfig      `yaml:"fragment"`
	SNIBlend           SNIBlendConfig         `yaml:"sni_blend"`
	HandshakePad       HandshakePaddingConfig `yaml:"handshake_pad"`
}

type TLSFragmentConfig struct {
	Enabled   bool `yaml:"enabled"`
	Size      int  `yaml:"size"`      // Bytes per fragment (default: 32)
	DelayMs   int  `yaml:"delay_ms"`  // Delay between fragments in milliseconds
	Randomize bool `yaml:"randomize"` // Randomize fragment sizes
}

// HandshakePaddingConfig configures random padding for handshakes.
// Based on Hysteria's padding technique.
type HandshakePaddingConfig struct {
	Enabled bool `yaml:"enabled"`  // Enable handshake padding
	AuthMin int  `yaml:"auth_min"` // Min padding for auth handshake (default: 256)
	AuthMax int  `yaml:"auth_max"` // Max padding for auth handshake (default: 2048)
	DataMin int  `yaml:"data_min"` // Min padding for data frames (default: 64)
	DataMax int  `yaml:"data_max"` // Max padding for data frames (default: 1024)
}

type SNIBlendConfig struct {
	Enabled   bool `yaml:"enabled"`
	Fragments int  `yaml:"fragments"` // Number of fragments (default: 8)
	Shuffle   bool `yaml:"shuffle"`   // Shuffle fragment order
}

type WSSConfig struct {
	Path         string                 `yaml:"path"`
	Origin       string                 `yaml:"origin"`
	Headers      map[string]string      `yaml:"headers"`
	PadMin       int                    `yaml:"pad_min"`
	PadMax       int                    `yaml:"pad_max"`
	XPad         XPaddingConfig         `yaml:"xpad"`
	UserAgent    string                 `yaml:"user_agent"`     // Static User-Agent (if rotation disabled)
	UARotation   bool                   `yaml:"ua_rotation"`    // Enable User-Agent rotation
	UAMode       string                 `yaml:"ua_mode"`        // Rotation mode: random, rotate
	CustomUAList []string               `yaml:"custom_ua_list"` // Custom UA list for rotation
	HandshakePad HandshakePaddingConfig `yaml:"handshake_pad"`  // Handshake padding config
}

type H2Config struct {
	Path         string                 `yaml:"path"`
	Headers      map[string]string      `yaml:"headers"`
	PadMin       int                    `yaml:"pad_min"`
	PadMax       int                    `yaml:"pad_max"`
	XPad         XPaddingConfig         `yaml:"xpad"`
	HandshakePad HandshakePaddingConfig `yaml:"handshake_pad"` // Handshake padding config
}

// XHTTPConfig configures SplitHTTP/XHTTP transport.
type XHTTPConfig struct {
	Mode           string            `yaml:"mode"` // stream-one, stream-up, stream-down, packet-up
	Path           string            `yaml:"path"`
	Headers        map[string]string `yaml:"headers"`
	XPad           XPaddingConfig    `yaml:"xpad"`
	MaxConnections int               `yaml:"max_connections"`
	PacketSize     int               `yaml:"packet_size"`
	KeepAlive      string            `yaml:"keep_alive"` // duration, e.g. 30s
}

// ShadowTLSConfig configures ShadowTLS transport.
type ShadowTLSConfig struct {
	Version         int      `yaml:"version"`           // ShadowTLS version (default: 3)
	Password        string   `yaml:"password"`          // Shared secret
	HandshakeDest   string   `yaml:"handshake_dest"`    // Decoy destination host[:port]
	HandshakeSNI    string   `yaml:"handshake_sni"`     // Optional SNI override
	ServerNames     []string `yaml:"server_names"`      // Allowed server names on gateway
	StrictMode      bool     `yaml:"strict_mode"`       // Enforce stricter TLS behavior
	WildcardSNIMode string   `yaml:"wildcard_sni_mode"` // off, authed, all
}

// RealityConfig configures REALITY transport.
type RealityConfig struct {
	Dest        string   `yaml:"dest"`
	ServerNames []string `yaml:"server_names"`
	PrivateKey  string   `yaml:"private_key"`
	ShortIDs    []string `yaml:"short_ids"`
	SpiderX     string   `yaml:"spider_x"`
	Show        bool     `yaml:"show"`
}

// DTLSConfig configures DTLS transport.
type DTLSConfig struct {
	Version          uint16 `yaml:"version"`
	PSK              string `yaml:"psk"`
	PSKIdentity      string `yaml:"psk_identity"`
	MTU              int    `yaml:"mtu"`
	HandshakeTimeout string `yaml:"handshake_timeout"`
	Retransmit       bool   `yaml:"retransmit"`
	ReplayWindow     int    `yaml:"replay_window"`
}

// QUICConfig configures QUIC transport.
type QUICConfig struct {
	Enable0RTT            bool           `yaml:"enable_0rtt"`
	HandshakeTimeout      string         `yaml:"handshake_timeout"`
	MaxIdleTimeout        string         `yaml:"max_idle_timeout"`
	KeepAlivePeriod       string         `yaml:"keep_alive_period"`
	MaxIncomingStreams    int64          `yaml:"max_incoming_streams"`
	MaxIncomingUniStreams int64          `yaml:"max_incoming_uni_streams"`
	Obfs                  QUICObfsConfig `yaml:"obfs"`
	Masquerade            QUICMasqConfig `yaml:"masquerade"`
	Padding               QUICPadConfig  `yaml:"padding"`
}

type QUICObfsConfig struct {
	Type     string `yaml:"type"`
	Password string `yaml:"password"`
}

type QUICMasqConfig struct {
	Type   string `yaml:"type"`
	Listen string `yaml:"listen"`
}

type QUICPadConfig struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

// MASQUEConfig configures MASQUE-over-QUIC transport.
type MASQUEConfig struct {
	ServerAddr string            `yaml:"server_addr"`
	Target     string            `yaml:"target"`
	TunnelType string            `yaml:"tunnel_type"` // udp, tcp, ip
	AuthToken  string            `yaml:"auth_token"`
	Headers    map[string]string `yaml:"headers"`
}

// AutoTransportConfig configures adaptive transport dialing.
type AutoTransportConfig struct {
	Candidates   []string `yaml:"candidates"`    // ordered list
	ProbeTimeout string   `yaml:"probe_timeout"` // per-attempt timeout
}

// XPaddingConfig configures XPadding behavior for HTTP/2 and WebSocket.
type XPaddingConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Min       int    `yaml:"min"`       // Minimum padding bytes
	Max       int    `yaml:"max"`       // Maximum padding bytes
	Method    string `yaml:"method"`    // Padding method: random, repeat-x, tokenish, spaces
	Placement string `yaml:"placement"` // Placement: header, cookie, referer, query
}

type KCPConfig struct {
	Block                string         `yaml:"block"`
	Key                  string         `yaml:"key"`
	Guard                string         `yaml:"guard"`
	PacketGuard          bool           `yaml:"packet_guard"`
	PacketGuardMagic     string         `yaml:"packet_guard_magic"`
	PacketGuardWindow    int            `yaml:"packet_guard_window"`
	PacketGuardSkew      int            `yaml:"packet_guard_skew"`
	MTU                  int            `yaml:"mtu"`
	SndWnd               int            `yaml:"sndwnd"`
	RcvWnd               int            `yaml:"rcvwnd"`
	NoDelay              int            `yaml:"nodelay"`
	Interval             int            `yaml:"interval"`
	Resend               int            `yaml:"resend"`
	NoCongestion         int            `yaml:"nocongestion"`
	WDelay               bool           `yaml:"wdelay"`
	AckNoDelay           bool           `yaml:"acknodelay"`
	DShard               int            `yaml:"dshard"`
	PShard               int            `yaml:"pshard"`
	Mode                 string         `yaml:"mode"`                    // normal, fast, fast2, fast3
	AutoTune             bool           `yaml:"autotune"`                // Enable FEC auto-tuning
	DSCP                 int            `yaml:"dscp"`                    // DSCP/TOS value
	MaxSessions          int            `yaml:"max_sessions"`            // Max concurrent sessions (0 = unlimited)
	MaxStreamsTotal      int            `yaml:"max_streams_total"`       // Max total streams across all sessions
	MaxStreamsPerSession int            `yaml:"max_streams_per_session"` // Max streams per session
	SmuxBuf              int            `yaml:"smuxbuf"`                 // SMux buffer size
	StreamBuf            int            `yaml:"streambuf"`               // Per-stream buffer size
	PortHop              PortHopConfig  `yaml:"port_hop"`                // Port hopping configuration
	BrutalCC             BrutalCCConfig `yaml:"brutal_cc"`               // Brutal congestion control
	FEC                  FECConfig      `yaml:"fec"`                     // Forward Error Correction
}

// FECConfig configures Reed-Solomon Forward Error Correction.
type FECConfig struct {
	Enabled        bool    `yaml:"enabled"`          // Enable FEC
	DataShards     int     `yaml:"data_shards"`      // Number of data shards (default: 10)
	ParityShards   int     `yaml:"parity_shards"`    // Number of parity shards (default: 3)
	MaxDelay       int     `yaml:"max_delay"`        // Maximum delay for FEC decoding in ms
	AutoTune       bool    `yaml:"autotune"`         // Auto-tune based on packet loss
	MinDataShards  int     `yaml:"min_data_shards"`  // Minimum data shards for auto-tune
	MaxDataShards  int     `yaml:"max_data_shards"`  // Maximum data shards for auto-tune
	TargetLossRate float64 `yaml:"target_loss_rate"` // Target packet loss rate for auto-tune
}

// PortHopConfig configures UDP port hopping.
type PortHopConfig struct {
	Enabled   bool          `yaml:"enabled"`    // Enable port hopping
	PortRange string        `yaml:"port_range"` // Port range (e.g., "3000-4000")
	Interval  time.Duration `yaml:"interval"`   // Hop interval
	Overlap   time.Duration `yaml:"overlap"`    // Connection overlap during hop
	Randomize bool          `yaml:"randomize"`  // Randomize port selection
}

// BrutalCCConfig configures Brutal congestion control.
type BrutalCCConfig struct {
	Enabled       bool `yaml:"enabled"`        // Enable brutal CC
	BandwidthMbps int  `yaml:"bandwidth_mbps"` // Target bandwidth in Mbps
}

type RawTCPConfig struct {
	Interface string     `yaml:"interface"`
	GUID      string     `yaml:"guid"`
	IPv4      RawTCPAddr `yaml:"ipv4"`
	IPv6      RawTCPAddr `yaml:"ipv6"`
	PCAP      RawTCPPCAP `yaml:"pcap"`
	TCP       RawTCPTCP  `yaml:"tcp"`

	iface *net.Interface `yaml:"-"`
	port  int            `yaml:"-"`
}

type RawTCPAddr struct {
	Addr      string `yaml:"addr"`
	RouterMAC string `yaml:"router_mac"`

	addr   *net.UDPAddr     `yaml:"-"`
	router net.HardwareAddr `yaml:"-"`
}

type RawTCPPCAP struct {
	Sockbuf   int  `yaml:"sockbuf"`    // PCAP buffer size
	Snaplen   int  `yaml:"snaplen"`    // Snapshot length (max bytes per packet)
	Promisc   bool `yaml:"promisc"`    // Enable promiscuous mode
	Immediate bool `yaml:"immediate"`  // Enable immediate mode
	TimeoutMs int  `yaml:"timeout_ms"` // Read timeout in milliseconds (0 = block forever)
}

type RawTCPTCP struct {
	LocalFlags  []string   `yaml:"local_flag"`
	RemoteFlags []string   `yaml:"remote_flag"`
	Randomize   bool       `yaml:"randomize"`  // Enable flag sequence randomization
	CycleMode   string     `yaml:"cycle_mode"` // Cycle mode: sequential, random, weighted
	local       []TCPFlags `yaml:"-"`
	remote      []TCPFlags `yaml:"-"`
}

type TCPFlags struct {
	FIN bool
	SYN bool
	RST bool
	PSH bool
	ACK bool
	URG bool
	ECE bool
	CWR bool
	NS  bool
}

type Mux struct {
	MaxStreamsPerSession  int    `yaml:"max_streams_per_session"`
	MaxStreamsTotal       int    `yaml:"max_streams_total"`
	HeaderTimeout         string `yaml:"header_timeout"`
	SmuxKeepAliveInterval string `yaml:"smux_keepalive_interval"`
	SmuxKeepAliveTimeout  string `yaml:"smux_keepalive_timeout"`
	MaxStreamBuffer       int    `yaml:"max_stream_buffer"`
	MaxReceiveBuffer      int    `yaml:"max_receive_buffer"`
}

type Service struct {
	Name       string       `yaml:"name"`
	Protocol   string       `yaml:"protocol"` // tcp, udp, tun, socks5
	Listen     string       `yaml:"listen"`   // gateway-only
	Target     string       `yaml:"target"`   // agent-only
	MaxStreams int          `yaml:"max_streams"`
	AllowCIDRs []string     `yaml:"allow_cidrs"`
	Tun        TunConfig    `yaml:"tun"`
	UDP        UDPConfig    `yaml:"udp"`
	Host       HostConfig   `yaml:"host"`
	SOCKS5     SOCKS5Config `yaml:"socks5"`
}

// SOCKS5Config configures a built-in SOCKS5 proxy service.
type SOCKS5Config struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Logging struct {
	Level string `yaml:"level"`
}

type Security struct {
	SharedKey      string              `yaml:"shared_key"`
	SharedKeys     []string            `yaml:"shared_keys"`
	AgentTokens    map[string]string   `yaml:"agent_tokens"`    // agent_id -> token
	AgentServices  map[string][]string `yaml:"agent_services"`  // agent_id -> allowed service names
	ReplayProtect  bool                `yaml:"replay_protect"`  // enable control-plane replay filter
	ReplayCapacity int                 `yaml:"replay_capacity"` // bloom capacity
}

type Metrics struct {
	Listen    string `yaml:"listen"`
	AuthToken string `yaml:"auth_token"`
	Pprof     bool   `yaml:"pprof"` // expose /debug/pprof/* endpoints on metrics listener
}

type TunConfig struct {
	Name string `yaml:"name"`
	MTU  int    `yaml:"mtu"`
	Mode string `yaml:"mode"` // "tun" or "tap"
}

type UDPConfig struct {
	ReadBuffer  int    `yaml:"read_buffer"`
	WriteBuffer int    `yaml:"write_buffer"`
	MaxPPS      int    `yaml:"max_pps"`
	MaxBPS      int    `yaml:"max_bps"`
	Burst       int    `yaml:"burst"`
	Mode        string `yaml:"mode"` // drop or pace
}

type HostConfig struct {
	SNI         string            `yaml:"sni"`
	Host        string            `yaml:"host"`
	Origin      string            `yaml:"origin"`
	Path        string            `yaml:"path"`
	Fingerprint string            `yaml:"fingerprint"`
	ConnectIP   string            `yaml:"connect_ip"`
	MaxConns    int               `yaml:"max_conns"`
	Headers     map[string]string `yaml:"headers"`
}

// FakeDNSConfig configures FakeDNS.
type FakeDNSConfig struct {
	Enabled bool          `yaml:"enabled"`
	IPRange string        `yaml:"ip_range"` // CIDR range for fake IPs (default: 198.18.0.0/15)
	TTL     time.Duration `yaml:"ttl"`      // TTL for DNS responses (default: 5m)
}

// ObfsConfig configures obfuscation.
type ObfsConfig struct {
	Type   string            `yaml:"type"` // obfs type: salamander, xor
	Key    string            `yaml:"key"`  // obfs key
	Params map[string]string `yaml:"params"`
}

// NoizeConfig configures Noize protocol mimicry.
type NoizeConfig struct {
	Enabled          bool          `yaml:"enabled"`
	Preset           string        `yaml:"preset"`            // minimal, light, medium, heavy, stealth, gfw, firewall
	JunkInterval     time.Duration `yaml:"junk_interval"`     // Interval between junk packets
	JunkMinSize      int           `yaml:"junk_min_size"`     // Minimum junk packet size
	JunkMaxSize      int           `yaml:"junk_max_size"`     // Maximum junk packet size
	SignaturePackets []string      `yaml:"signature_packets"` // Packet types to mimic: http, https, dns, stun
	FragmentPackets  bool          `yaml:"fragment_packets"`  // Fragment initial packets
	BurstPackets     int           `yaml:"burst_packets"`     // Junk packets per burst interval
	BurstInterval    time.Duration `yaml:"burst_interval"`    // Interval between bursts
	MaxJunkPercent   int           `yaml:"max_junk_percent"`  // Soft budget of junk traffic (1-95)
	Adaptive         bool          `yaml:"adaptive"`          // Adapt junk behavior to observed conditions
}

// QPPConfig configures Quantum Permutation Pad encryption.
type QPPConfig struct {
	Enabled    bool   `yaml:"enabled"`
	NumPads    int    `yaml:"num_pads"`   // Number of permutation pads (default: 251)
	Key        string `yaml:"key"`        // Encryption key
	Asymmetric bool   `yaml:"asymmetric"` // Use different cipher/key per direction
}

// HalfDuplexConfig configures half-duplex mode.
type HalfDuplexConfig struct {
	Enabled    bool          `yaml:"enabled"`
	UpConn     string        `yaml:"up_conn"`     // Address for upload connection
	DownConn   string        `yaml:"down_conn"`   // Address for download connection
	MuxTimeout time.Duration `yaml:"mux_timeout"` // Timeout for mux operations
	BufferSize int           `yaml:"buffer_size"` // Buffer size for relay
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := validateRemovedTransportBlocks(data); err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Transport.Type == "" {
		c.Transport.Type = "uqsp"
	}

	// Apply UQSP defaults if using UQSP transport
	if c.UQSPEnabled() {
		c.ApplyUQSPDefaults()
	}
	if c.Security.ReplayCapacity == 0 {
		c.Security.ReplayCapacity = 1000000
	}
	if c.Agent.ReconnectBackoff == "" {
		c.Agent.ReconnectBackoff = "3s"
	}
	if c.Mux.HeaderTimeout == "" {
		c.Mux.HeaderTimeout = "10s"
	}
	if c.Mux.SmuxKeepAliveInterval == "" {
		c.Mux.SmuxKeepAliveInterval = "2s"
	}
	if c.Mux.SmuxKeepAliveTimeout == "" {
		c.Mux.SmuxKeepAliveTimeout = "8s"
	}
	if c.Mux.MaxStreamBuffer == 0 {
		c.Mux.MaxStreamBuffer = 1024 * 1024
	}
	if c.Mux.MaxReceiveBuffer == 0 {
		c.Mux.MaxReceiveBuffer = 4 * 1024 * 1024
	}
	c.applyExtensionDefaults()
	c.applyStealthDefaults()
}

func (c *Config) validate() error {
	if c.Role != "gateway" && c.Role != "agent" {
		return fmt.Errorf("role must be 'gateway' or 'agent'")
	}

	// Validate transport type - only 'uqsp' is supported now
	switch strings.ToLower(strings.TrimSpace(c.Transport.Type)) {
	case "uqsp":
		// UQSP is the new unified transport
	case "stealth":
		// Stealth with carrier.kind is no longer supported
		return fmt.Errorf("transport.type=stealth with carrier.kind is no longer supported. Use transport.type=uqsp instead. See docs/UQSP_MIGRATION.md for details")
	default:
		return legacyTransportTypeError(c.Transport.Type)
	}

	// Validate UQSP configuration
	if err := c.ValidateUQSP(); err != nil {
		return err
	}

	// Legacy stealth validation - only for backwards compatibility checks
	// This will fail with helpful error if old stealth config is detected
	if err := c.validateStealthLegacy(); err != nil {
		return err
	}
	if c.Role == "gateway" {
		if c.Gateway.Listen == "" {
			return fmt.Errorf("gateway.listen is required")
		}
	}
	if c.Role == "agent" {
		if c.Agent.GatewayAddr == "" {
			return fmt.Errorf("agent.gateway_addr is required")
		}
	}
	if err := c.validateExtensions(); err != nil {
		return err
	}
	if c.Transport.Stealth.Shaping.Noize.Enabled {
		if c.Transport.Stealth.Shaping.Noize.JunkMinSize < 0 {
			return fmt.Errorf("transport.stealth.shaping.noize.junk_min_size must be >= 0")
		}
		if c.Transport.Stealth.Shaping.Noize.JunkMaxSize < c.Transport.Stealth.Shaping.Noize.JunkMinSize {
			return fmt.Errorf("transport.stealth.shaping.noize.junk_max_size must be >= junk_min_size")
		}
		if c.Transport.Stealth.Shaping.Noize.BurstPackets < 1 {
			return fmt.Errorf("transport.stealth.shaping.noize.burst_packets must be >= 1 when enabled")
		}
		if c.Transport.Stealth.Shaping.Noize.BurstInterval < 0 {
			return fmt.Errorf("transport.stealth.shaping.noize.burst_interval must be >= 0")
		}
		if c.Transport.Stealth.Shaping.Noize.MaxJunkPercent < 1 || c.Transport.Stealth.Shaping.Noize.MaxJunkPercent > 95 {
			return fmt.Errorf("transport.stealth.shaping.noize.max_junk_percent must be between 1 and 95")
		}
		for _, sig := range c.Transport.Stealth.Shaping.Noize.SignaturePackets {
			switch sig {
			case "http", "https", "dns", "stun":
			default:
				return fmt.Errorf("transport.stealth.shaping.noize.signature_packets contains unsupported packet type: %s", sig)
			}
		}
	}
	if c.Transport.Proxy.URL != "" {
		u, err := url.Parse(c.Transport.Proxy.URL)
		if err != nil {
			return fmt.Errorf("transport.proxy.url invalid: %w", err)
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return fmt.Errorf("transport.proxy.url scheme must be http/https/socks5/socks5h")
		}
		if u.Host == "" {
			return fmt.Errorf("transport.proxy.url missing host")
		}
	}
	if len(c.ActiveSharedKey()) == 0 {
		return fmt.Errorf("security.shared_key or security.shared_keys is required")
	}
	if c.Security.ReplayProtect && c.Security.ReplayCapacity < 1024 {
		return fmt.Errorf("security.replay_capacity must be >= 1024 when replay_protect is enabled")
	}
	for i := range c.Services {
		svc := &c.Services[i]
		if svc.Name == "" {
			return fmt.Errorf("service name is required")
		}
		if svc.MaxStreams < 0 {
			return fmt.Errorf("service %s max_streams must be >= 0", svc.Name)
		}
		if svc.Protocol == "tun" && svc.Tun.Name == "" {
			return fmt.Errorf("service %s protocol tun requires tun.name", svc.Name)
		}
		if svc.Protocol == "tun" && svc.Tun.Mode != "" {
			if svc.Tun.Mode != "tun" && svc.Tun.Mode != "tap" {
				return fmt.Errorf("service %s tun.mode must be 'tun' or 'tap'", svc.Name)
			}
		}
		if svc.Protocol == "socks5" {
			if svc.Listen == "" {
				return fmt.Errorf("service %s protocol socks5 requires listen address", svc.Name)
			}
			if svc.SOCKS5.Username != "" && svc.SOCKS5.Password == "" {
				return fmt.Errorf("service %s socks5 username requires password", svc.Name)
			}
			if svc.SOCKS5.Password != "" && svc.SOCKS5.Username == "" {
				return fmt.Errorf("service %s socks5 password requires username", svc.Name)
			}
			// Require auth for non-loopback binds
			host, _, _ := net.SplitHostPort(svc.Listen)
			if host != "" && host != "127.0.0.1" && host != "::1" && host != "localhost" {
				if svc.SOCKS5.Username == "" {
					return fmt.Errorf("service %s socks5 requires authentication when listening on non-loopback address %s", svc.Name, host)
				}
			}
		}
		if svc.Protocol == "udp" {
			if svc.UDP.Mode == "" {
				svc.UDP.Mode = "drop"
			}
			if svc.UDP.Mode != "drop" && svc.UDP.Mode != "pace" {
				return fmt.Errorf("service %s udp.mode must be drop or pace", svc.Name)
			}
		}
		if svc.Host.MaxConns < 0 {
			return fmt.Errorf("service %s host.max_conns must be >= 0", svc.Name)
		}
		if svc.Host.Path == "" {
			svc.Host.Path = c.Transport.Stealth.Camouflage.HTTPCover.Path
		}
	}
	return nil
}

func validateRemovedTransportBlocks(data []byte) error {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}
	transportRaw, ok := raw["transport"]
	if !ok {
		return nil
	}
	transport := coerceStringMap(transportRaw)
	if transport == nil {
		return nil
	}
	for k := range transport {
		if k == "type" || k == "stealth" || k == "uqsp" {
			continue
		}
		if isLegacyTransportBlock(k) {
			return legacyTransportBlockError(k)
		}
		return fmt.Errorf("transport.%s has been removed; use transport.stealth.* or transport.uqsp", k)
	}
	return nil
}

func coerceStringMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			ks, ok := k.(string)
			if !ok {
				continue
			}
			out[ks] = val
		}
		return out
	default:
		return nil
	}
}

// ActiveSharedKey returns the key used for outbound control writes.
func (c *Config) ActiveSharedKey() string {
	if len(c.Security.SharedKeys) > 0 {
		for _, k := range c.Security.SharedKeys {
			k = strings.TrimSpace(k)
			if k != "" {
				return k
			}
		}
	}
	return strings.TrimSpace(c.Security.SharedKey)
}

// AcceptedSharedKeys returns all keys accepted for inbound control reads.
func (c *Config) AcceptedSharedKeys() []string {
	out := make([]string, 0, 1+len(c.Security.SharedKeys))
	seen := map[string]struct{}{}
	if k := strings.TrimSpace(c.Security.SharedKey); k != "" {
		seen[k] = struct{}{}
		out = append(out, k)
	}
	for _, k := range c.Security.SharedKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// AgentToken returns per-agent token if configured, otherwise active shared key.
func (c *Config) AgentToken(agentID string) string {
	if c.Security.AgentTokens != nil {
		if tok, ok := c.Security.AgentTokens[agentID]; ok && strings.TrimSpace(tok) != "" {
			return strings.TrimSpace(tok)
		}
	}
	return c.ActiveSharedKey()
}

func (c *Config) HeaderTimeout() time.Duration {
	return parseDurationOr(c.Mux.HeaderTimeout, 10*time.Second)
}

func (c *Config) SmuxKeepAliveInterval() time.Duration {
	return parseDurationOr(c.Mux.SmuxKeepAliveInterval, 2*time.Second)
}

func (c *Config) SmuxKeepAliveTimeout() time.Duration {
	return parseDurationOr(c.Mux.SmuxKeepAliveTimeout, 8*time.Second)
}

func (c *Config) ReconnectBackoff() time.Duration {
	return parseDurationOr(c.Agent.ReconnectBackoff, 3*time.Second)
}

func parseDurationOr(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return fallback
}

func writeErr(allErrors []error) error {
	if len(allErrors) == 0 {
		return nil
	}
	messages := make([]string, 0, len(allErrors))
	for _, err := range allErrors {
		messages = append(messages, err.Error())
	}
	return fmt.Errorf("validation failed:\n  - %s", strings.Join(messages, "\n  - "))
}

func (r *RawTCPConfig) applyDefaults(role string) {
	r.PCAP.applyDefaults(role)
	r.TCP.applyDefaults()
}

func (p *RawTCPPCAP) applyDefaults(role string) {
	if p.Sockbuf == 0 {
		if role == "gateway" {
			p.Sockbuf = 8 * 1024 * 1024
		} else {
			p.Sockbuf = 4 * 1024 * 1024
		}
	}
	if p.Snaplen == 0 {
		p.Snaplen = 65536 // Default snap length (max packet size)
	}
	// Promisc defaults to true (set in newHandle)
	// Immediate defaults to true (set in newHandle)
	// TimeoutMs defaults to 0 (block forever)
}

func (t *RawTCPTCP) applyDefaults() {
	if len(t.LocalFlags) == 0 {
		t.LocalFlags = []string{"PA"}
	}
	if len(t.RemoteFlags) == 0 {
		t.RemoteFlags = []string{"PA"}
	}
	if t.CycleMode == "" {
		t.CycleMode = "sequential"
	}
}

func (r *RawTCPConfig) validate(role, listen string) error {
	var allErrors []error

	if r.Interface == "" {
		allErrors = append(allErrors, fmt.Errorf("transport.rawtcp.interface is required"))
	}
	if len(r.Interface) > 15 {
		allErrors = append(allErrors, fmt.Errorf("transport.rawtcp.interface name too long (max 15 characters): '%s'", r.Interface))
	}
	if r.Interface != "" {
		iface, err := net.InterfaceByName(r.Interface)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("transport.rawtcp.interface %s not found: %v", r.Interface, err))
		} else {
			r.iface = iface
		}
	}
	if runtime.GOOS == "windows" && r.GUID == "" {
		allErrors = append(allErrors, fmt.Errorf("transport.rawtcp.guid is required on windows"))
	}

	ipv4Set := r.IPv4.Addr != ""
	ipv6Set := r.IPv6.Addr != ""
	if !ipv4Set && !ipv6Set {
		allErrors = append(allErrors, fmt.Errorf("transport.rawtcp requires ipv4 or ipv6 config"))
		return writeErr(allErrors)
	}

	allowZero := role == "agent"
	if ipv4Set {
		allErrors = append(allErrors, r.IPv4.validate(allowZero)...)
	}
	if ipv6Set {
		allErrors = append(allErrors, r.IPv6.validate(allowZero)...)
	}
	if ipv4Set && ipv6Set && r.IPv4.addr != nil && r.IPv6.addr != nil {
		if r.IPv4.addr.Port != r.IPv6.addr.Port {
			allErrors = append(allErrors, fmt.Errorf("transport.rawtcp ipv4 and ipv6 ports must match"))
		}
	}
	if r.IPv4.addr != nil {
		r.port = r.IPv4.addr.Port
	} else if r.IPv6.addr != nil {
		r.port = r.IPv6.addr.Port
	}

	if role == "gateway" && listen != "" {
		if laddr, err := net.ResolveTCPAddr("tcp", listen); err == nil && laddr != nil && laddr.Port > 0 {
			if r.port != 0 && r.port != laddr.Port {
				allErrors = append(allErrors, fmt.Errorf("transport.rawtcp port %d must match gateway.listen port %d", r.port, laddr.Port))
			}
		}
	}

	allErrors = append(allErrors, r.PCAP.validate()...)
	allErrors = append(allErrors, r.TCP.validate()...)

	return writeErr(allErrors)
}

func (a *RawTCPAddr) validate(allowZeroPort bool) []error {
	var errors []error
	if a.Addr == "" {
		errors = append(errors, fmt.Errorf("transport.rawtcp addr is required"))
		return errors
	}
	uaddr, err := net.ResolveUDPAddr("udp", a.Addr)
	if err != nil {
		errors = append(errors, fmt.Errorf("invalid transport.rawtcp addr '%s': %v", a.Addr, err))
		return errors
	}
	if uaddr.Port == 0 && !allowZeroPort {
		errors = append(errors, fmt.Errorf("transport.rawtcp addr port must be between 1-65535"))
	} else if uaddr.Port < 0 || uaddr.Port > 65535 {
		errors = append(errors, fmt.Errorf("transport.rawtcp addr port must be between 0-65535"))
	}
	a.addr = uaddr
	if a.RouterMAC == "" {
		errors = append(errors, fmt.Errorf("transport.rawtcp router_mac is required"))
		return errors
	}
	hw, err := net.ParseMAC(a.RouterMAC)
	if err != nil {
		errors = append(errors, fmt.Errorf("invalid transport.rawtcp router_mac '%s': %v", a.RouterMAC, err))
		return errors
	}
	a.router = hw
	return errors
}

func (p *RawTCPPCAP) validate() []error {
	var errors []error
	if p.Sockbuf < 1024 {
		errors = append(errors, fmt.Errorf("transport.rawtcp.pcap.sockbuf must be >= 1024"))
	}
	if p.Sockbuf > 100*1024*1024 {
		errors = append(errors, fmt.Errorf("transport.rawtcp.pcap.sockbuf too large (max 100MB)"))
	}
	return errors
}

func (t *RawTCPTCP) validate() []error {
	var errors []error
	if len(t.LocalFlags) > 0 {
		t.local = make([]TCPFlags, len(t.LocalFlags))
		for i, f := range t.LocalFlags {
			flags, err := parseTCPFlags(f)
			if err != nil {
				errors = append(errors, err)
			}
			t.local[i] = flags
		}
	}
	if len(t.RemoteFlags) > 0 {
		t.remote = make([]TCPFlags, len(t.RemoteFlags))
		for i, f := range t.RemoteFlags {
			flags, err := parseTCPFlags(f)
			if err != nil {
				errors = append(errors, err)
			}
			t.remote[i] = flags
		}
	}
	if len(t.local) == 0 || len(t.remote) == 0 {
		errors = append(errors, fmt.Errorf("transport.rawtcp.tcp requires at least one tcp flag combination"))
	}
	return errors
}

func parseTCPFlags(flagStr string) (TCPFlags, error) {
	var f TCPFlags
	for _, ch := range flagStr {
		switch ch {
		case 'F':
			f.FIN = true
		case 'S':
			f.SYN = true
		case 'R':
			f.RST = true
		case 'P':
			f.PSH = true
		case 'A':
			f.ACK = true
		case 'U':
			f.URG = true
		case 'E':
			f.ECE = true
		case 'C':
			f.CWR = true
		case 'N':
			f.NS = true
		default:
			return f, fmt.Errorf("invalid TCP flag '%c' in combination", ch)
		}
	}
	return f, nil
}

func (r *RawTCPConfig) InterfaceObj() *net.Interface {
	return r.iface
}

func (r *RawTCPConfig) Port() int {
	return r.port
}

// GetDSCP returns the effective DSCP value based on configuration.
func (d *DSCPConfig) GetDSCP() int {
	if !d.Enabled {
		return 0
	}
	if d.Value > 0 {
		return d.Value
	}
	// Convert class to DSCP value
	switch d.Class {
	case "low":
		return 8 // CS1
	case "bulk":
		return 16 // CS2
	case "critical":
		return 24 // CS3
	case "realtime":
		return 32 // CS4
	case "network-control":
		return 48 // CS6
	case "expedited":
		return 46 // EF
	default:
		return 0 // CS0 (default)
	}
}

// GetControlDSCP returns DSCP for control traffic.
func (d *DSCPConfig) GetControlDSCP() int {
	if !d.Enabled {
		return 0
	}
	if d.MarkControl && d.ControlDSCP > 0 {
		return d.ControlDSCP
	}
	return d.GetDSCP()
}

// GetDataDSCP returns DSCP for data traffic.
func (d *DSCPConfig) GetDataDSCP() int {
	if !d.Enabled {
		return 0
	}
	if d.MarkData && d.DataDSCP > 0 {
		return d.DataDSCP
	}
	return d.GetDSCP()
}

func (a *RawTCPAddr) UDPAddr() *net.UDPAddr {
	return a.addr
}

func (a *RawTCPAddr) Router() net.HardwareAddr {
	return a.router
}

func (t *RawTCPTCP) LocalParsed() []TCPFlags {
	return t.local
}

func (t *RawTCPTCP) RemoteParsed() []TCPFlags {
	return t.remote
}

func isValidKCPBlock(block string) bool {
	switch block {
	case "aes", "aes-128", "aes-128-gcm", "aes-192", "aes-256",
		"salsa20", "blowfish", "twofish", "cast5", "3des", "tea", "xtea",
		"xor", "sm4", "none", "null":
		return true
	default:
		return false
	}
}

func kcpKeyRequired(block string) bool {
	return block != "none" && block != "null"
}
