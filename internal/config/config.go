package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"stealthlink/internal/vpn"
	"stealthlink/internal/warp"
)

type Config struct {
	Variant          string                 `yaml:"variant"` // Optional explicit mode selector: HTTP+ | TCP+ | TLS+ | UDP+ | TLS
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
	AllowLoopback    bool   `yaml:"allow_loopback_gateway_addr"`
	ReconnectBackoff string `yaml:"reconnect_backoff"`
}

type Transport struct {
	Type         string                `yaml:"type"`
	Mode         string                `yaml:"mode"` // "HTTP+" | "TCP+" | "TLS+" | "UDP+" | "TLS" - StealthLink mode profile
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

	// Mode-specific configurations
	Mode4a Mode4aConfig `yaml:"mode_4a"` // XHTTP + Domain Fronting configuration
	Mode4b Mode4bConfig `yaml:"mode_4b"` // FakeTCP + Anti-DPI configuration
	Mode4c Mode4cConfig `yaml:"mode_4c"` // TLS-Like + REALITY/AnyTLS configuration
	Mode4d Mode4dConfig `yaml:"mode_4d"` // QUIC + Brutal CC configuration
	Mode4e Mode4eConfig `yaml:"mode_4e"` // TrustTunnel + CSTP configuration

	// Underlay dialer configuration
	Dialer       string             `yaml:"dialer"`        // "direct" (default) | "warp" | "socks"
	WARPDialer   WARPDialer         `yaml:"warp_dialer"`   // WARP dialer configuration
	SOCKSDialer  SOCKSDialer        `yaml:"socks_dialer"`  // SOCKS dialer configuration
	DialerPolicy DialerPolicyConfig `yaml:"dialer_policy"` // optional per-destination dialer routing

	// Upstream compatibility adapters (OPTIONAL)
	// Use ONLY when interoperability with upstream clients is required
	CompatMode string              `yaml:"compat_mode"` // "none" (default) | "xray" | "singbox"
	Xray       XrayCompatConfig    `yaml:"xray"`        // Xray-core adapter configuration
	Singbox    SingboxCompatConfig `yaml:"singbox"`     // sing-box adapter configuration

	// Adaptive connection pool configuration
	Pool AdaptivePoolConfig `yaml:"pool"`
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

// WARPDialer configures Cloudflare WARP as transport underlay
type WARPDialer struct {
	// Mode is the operator-facing WARP operational model.
	// It is intentionally distinct from internal/warp.Config.Mode (engine selection).
	//
	// Accepted values (by convention): "consumer" | "zero-trust" | "connector".
	// This field does not currently change low-level tunnel engine behavior.
	Mode string `yaml:"mode"`

	// Engine selects which WARP tunnel engine to use:
	// - "builtin" (default): in-process WireGuard implementation
	// - "wgquick": use system wg-quick tooling
	Engine string `yaml:"engine"`

	// Required controls whether selecting dialer=warp should hard-fail startup if
	// WARP cannot be initialized. Default false is safer for dev/test, but operators
	// should set true when WARP is used as an anti-blocking measure (to avoid silent IP leak).
	Required bool `yaml:"required"`

	// FailurePolicy is a human-readable alias for Required:
	// - fail-open   => required=false
	// - fail-closed => required=true
	FailurePolicy string `yaml:"failure_policy"`

	DeviceID string `yaml:"device_id"` // WARP device registration ID

	// Mark is the fwmark value used for policy routing.
	// Sockets created by this dialer will have SO_MARK set to this value,
	// and policy routing rules will route marked packets via WARP.
	// Default: 51888
	Mark int `yaml:"mark"`

	// Table is the routing table number for WARP routes.
	// Default: 51888
	Table int `yaml:"table"`

	// RulePriority is the priority for the ip rule that directs marked packets.
	// Lower values = higher priority. Default: 11000
	RulePriority int `yaml:"rule_priority"`

	// RoutingPolicy determines how traffic is routed through WARP:
	// - "socket_mark" (default): Only sockets with SO_MARK set use WARP routing
	// - "global": All traffic uses WARP (disruptive, changes default route)
	RoutingPolicy string `yaml:"routing_policy"`
}

// SOCKSDialer configures SOCKS5 proxy as transport underlay
type SOCKSDialer struct {
	Address  string `yaml:"address"`  // SOCKS5 proxy address (host:port)
	Username string `yaml:"username"` // Optional SOCKS5 username
	Password string `yaml:"password"` // Optional SOCKS5 password
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

// AdaptivePoolConfig configures the auto-scaling connection pool.
type AdaptivePoolConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Mode         string `yaml:"mode"` // normal, aggressive
	MinSize      int    `yaml:"min_size"`
	MaxSize      int    `yaml:"max_size"`
	CooldownSecs int    `yaml:"cooldown_secs"`
}

// BrutalCCConfig configures Brutal congestion control.
type BrutalCCConfig struct {
	Enabled       bool `yaml:"enabled"`        // Enable brutal CC
	BandwidthMbps int  `yaml:"bandwidth_mbps"` // Target bandwidth in Mbps
}

type RawTCPConfig struct {
	Interface          string     `yaml:"interface"`
	GUID               string     `yaml:"guid"`
	IPv4               RawTCPAddr `yaml:"ipv4"`
	IPv6               RawTCPAddr `yaml:"ipv6"`
	PCAP               RawTCPPCAP `yaml:"pcap"`
	TCP                RawTCPTCP  `yaml:"tcp"`
	FingerprintProfile string     `yaml:"fingerprint_profile"` // TCP option mimicry: chrome_win10, safari_macos, linux_default, android, random
	BPFProfile         string     `yaml:"bpf_profile"`         // BPF filter mode: basic, strict, stealth

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
	MaxStreamsPerSession  int                  `yaml:"max_streams_per_session"`
	MaxStreamsTotal       int                  `yaml:"max_streams_total"`
	HeaderTimeout         string               `yaml:"header_timeout"`
	SmuxKeepAliveInterval string               `yaml:"smux_keepalive_interval"`
	SmuxKeepAliveTimeout  string               `yaml:"smux_keepalive_timeout"`
	MaxStreamBuffer       int                  `yaml:"max_stream_buffer"`
	MaxReceiveBuffer      int                  `yaml:"max_receive_buffer"`
	Shaper                PriorityShaperConfig `yaml:"shaper"`
}

// PriorityShaperConfig configures the smux priority shaper.
type PriorityShaperConfig struct {
	Enabled         bool `yaml:"enabled"`
	MaxControlBurst int  `yaml:"max_control_burst"` // default: 16
	QueueSize       int  `yaml:"queue_size"`        // default: 1024
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
	Name      string `yaml:"name"`
	MTU       int    `yaml:"mtu"`
	Mode      string `yaml:"mode"`      // "tun" (L3-only)
	Transport string `yaml:"transport"` // auto (default), stream, datagram
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
	if c.Transport.Dialer == "" {
		c.Transport.Dialer = "direct"
	}
	if c.Transport.WARPDialer.Mode == "" {
		c.Transport.WARPDialer.Mode = "consumer"
	}
	if c.Transport.WARPDialer.Engine == "" {
		c.Transport.WARPDialer.Engine = "builtin"
	}
	switch strings.ToLower(strings.TrimSpace(c.Transport.WARPDialer.FailurePolicy)) {
	case "":
		if c.Transport.WARPDialer.Required {
			c.Transport.WARPDialer.FailurePolicy = "fail-closed"
		} else {
			c.Transport.WARPDialer.FailurePolicy = "fail-open"
		}
	case "fail-open":
		c.Transport.WARPDialer.Required = false
	case "fail-closed":
		c.Transport.WARPDialer.Required = true
	}
	if c.Transport.WARPDialer.Mark == 0 {
		c.Transport.WARPDialer.Mark = 51888
	}
	if c.Transport.WARPDialer.Table == 0 {
		c.Transport.WARPDialer.Table = 51888
	}
	if c.Transport.WARPDialer.RulePriority == 0 {
		c.Transport.WARPDialer.RulePriority = 11000
	}
	if c.Transport.WARPDialer.RoutingPolicy == "" {
		c.Transport.WARPDialer.RoutingPolicy = "socket_mark"
	}

	// Apply UQSP defaults if using UQSP transport
	if c.UQSPEnabled() {
		c.ApplyUQSPDefaults()
		c.applyVariantPreset()
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
	if c.Mux.Shaper.MaxControlBurst == 0 {
		c.Mux.Shaper.MaxControlBurst = 16
	}
	if c.Mux.Shaper.QueueSize == 0 {
		c.Mux.Shaper.QueueSize = 1024
	}
	c.applyExtensionDefaults()
	c.applyStealthDefaults()
	c.ApplyCompatDefaults()
	c.applyPoolDefaults()
}

func (c *Config) applyPoolDefaults() {
	if c.Transport.Pool.MinSize <= 0 {
		c.Transport.Pool.MinSize = 2
	}
	if c.Transport.Pool.MaxSize <= 0 {
		c.Transport.Pool.MaxSize = 32
	}
	if c.Transport.Pool.CooldownSecs <= 0 {
		c.Transport.Pool.CooldownSecs = 30
	}
	if c.Transport.Pool.Mode == "" {
		c.Transport.Pool.Mode = "normal"
	}
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
	if err := c.ValidateVariant(); err != nil {
		return err
	}

	// Validate mode configuration
	if err := c.ValidateMode(); err != nil {
		return err
	}

	// Validate compatibility mode configuration
	if err := c.ValidateCompatMode(); err != nil {
		return err
	}
	if err := c.validateUnderlayDialer(); err != nil {
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
		if err := validateGatewayAddr(c.Agent.GatewayAddr, c.Agent.AllowLoopback); err != nil {
			return err
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
			if svc.Tun.Mode != "tun" {
				return fmt.Errorf("service %s tun.mode must be 'tun' (tap/L2 not supported)", svc.Name)
			}
		}
		if svc.Protocol == "tun" {
			// Default to L3-only TUN if the service doesn't specify a mode.
			if strings.TrimSpace(svc.Tun.Mode) == "" {
				svc.Tun.Mode = "tun"
			}
			switch strings.ToLower(strings.TrimSpace(svc.Tun.Transport)) {
			case "", "auto":
				// default
			case "stream", "datagram":
			default:
				return fmt.Errorf("service %s tun.transport must be one of: auto, stream, datagram", svc.Name)
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

	// Enforce VPN config validation when enabled (L3-only; rejects tap).
	if err := c.VPN.Validate(); err != nil {
		return fmt.Errorf("vpn: %w", err)
	}
	return nil
}

func validateGatewayAddr(addr string, allowLoopback bool) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return fmt.Errorf("agent.gateway_addr is required")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.Count(addr, ":") > 1 && !strings.HasPrefix(addr, "[") {
			return fmt.Errorf("agent.gateway_addr must be in host:port form; for IPv6 use [ipv6]:port (example: [2001:db8::1]:8443)")
		}
		return fmt.Errorf("agent.gateway_addr invalid (expected host:port): %w", err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("agent.gateway_addr missing host")
	}
	if host == "0.0.0.0" || host == "::" {
		return fmt.Errorf("agent.gateway_addr must not be 0.0.0.0 or :: (not dialable)")
	}
	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("agent.gateway_addr has invalid port: %q", portStr)
	}

	if strings.EqualFold(host, "localhost") && !allowLoopback {
		return fmt.Errorf("agent.gateway_addr=%q is loopback; set agent.allow_loopback_gateway_addr=true for same-host testing", addr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return fmt.Errorf("agent.gateway_addr must not be 0.0.0.0 or :: (not dialable)")
		}
		if ip.IsLoopback() && !allowLoopback {
			return fmt.Errorf("agent.gateway_addr=%q is loopback; set agent.allow_loopback_gateway_addr=true for same-host testing", addr)
		}
	}

	return nil
}

func (c *Config) validateUnderlayDialer() error {
	dialer := strings.ToLower(strings.TrimSpace(c.Transport.Dialer))
	switch dialer {
	case "", "direct":
		return nil
	case "policy":
		if !c.Transport.DialerPolicy.Enabled {
			return fmt.Errorf("transport.dialer=policy requires transport.dialer_policy.enabled=true")
		}
		return c.validateDialerPolicy()
	case "warp":
		engine := strings.ToLower(strings.TrimSpace(c.Transport.WARPDialer.Engine))
		switch engine {
		case "", "builtin", "wgquick":
		default:
			return fmt.Errorf("transport.warp_dialer.engine must be one of: builtin, wgquick")
		}
		policy := strings.ToLower(strings.TrimSpace(c.Transport.WARPDialer.FailurePolicy))
		switch policy {
		case "", "fail-open", "fail-closed":
		default:
			return fmt.Errorf("transport.warp_dialer.failure_policy must be one of: fail-open, fail-closed")
		}
		if policy == "fail-open" && c.Transport.WARPDialer.Required {
			return fmt.Errorf("transport.warp_dialer.failure_policy=fail-open conflicts with required=true")
		}
		if policy == "fail-closed" && !c.Transport.WARPDialer.Required {
			return fmt.Errorf("transport.warp_dialer.failure_policy=fail-closed requires required=true")
		}
		if c.Transport.WARPDialer.Mark < 1 || c.Transport.WARPDialer.Mark > 0xFFFFFFFF {
			return fmt.Errorf("transport.warp_dialer.mark must be between 1 and %d", 0xFFFFFFFF)
		}
		if c.Transport.WARPDialer.Table < 1 || c.Transport.WARPDialer.Table > 0xFFFFFFFF {
			return fmt.Errorf("transport.warp_dialer.table must be between 1 and %d", 0xFFFFFFFF)
		}
		if c.Transport.WARPDialer.RulePriority < 1 || c.Transport.WARPDialer.RulePriority > 32767 {
			return fmt.Errorf("transport.warp_dialer.rule_priority must be between 1 and 32767")
		}
		rp := strings.ToLower(strings.TrimSpace(c.Transport.WARPDialer.RoutingPolicy))
		switch rp {
		case "", "socket_mark", "global":
		default:
			return fmt.Errorf("transport.warp_dialer.routing_policy must be one of: socket_mark, global")
		}
		return nil
	case "socks":
		if strings.TrimSpace(c.Transport.SOCKSDialer.Address) == "" {
			return fmt.Errorf("transport.socks_dialer.address is required when transport.dialer=socks")
		}
		return nil
	default:
		return fmt.Errorf("transport.dialer must be one of: direct, warp, socks, policy")
	}
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
	allowed := map[string]struct{}{
		"type":          {},
		"mode":          {},
		"stealth":       {},
		"uqsp":          {},
		"dialer":        {},
		"warp_dialer":   {},
		"socks_dialer":  {},
		"dialer_policy": {},
		"compat_mode":   {},
		"xray":          {},
		"singbox":       {},
	}
	for k := range transport {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if k == "pipeline" {
			return fmt.Errorf("transport.pipeline has been removed; use transport.stealth.*")
		}
		if _, ok := allowed[k]; ok {
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
	switch strings.ToLower(strings.TrimSpace(r.FingerprintProfile)) {
	case "", "chrome_win10", "safari_macos", "linux_default", "android", "random":
	default:
		allErrors = append(allErrors, fmt.Errorf("transport.rawtcp.fingerprint_profile must be one of: chrome_win10, safari_macos, linux_default, android, random"))
	}
	switch strings.ToLower(strings.TrimSpace(r.BPFProfile)) {
	case "", "basic", "strict", "stealth":
	default:
		allErrors = append(allErrors, fmt.Errorf("transport.rawtcp.bpf_profile must be one of: basic, strict, stealth"))
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

// GetActiveMode returns the active StealthLink mode.
// Priority: transport.mode > variant > default ("HTTP+")
func (c *Config) GetActiveMode() string {
	if c.Transport.Mode != "" {
		return c.Transport.Mode
	}
	if c.Variant != "" {
		return c.Variant
	}
	return VariantHTTPPlus // default mode
}

// GetMode4aConfig returns the Mode 4a configuration with defaults applied.
func (c *Config) GetMode4aConfig() Mode4aConfig {
	cfg := c.Transport.Mode4a
	defaults := DefaultMode4aConfig()

	// Apply defaults for zero values
	if cfg.SessionPlacement == "" {
		cfg.SessionPlacement = defaults.SessionPlacement
	}
	if cfg.SessionKey == "" {
		cfg.SessionKey = defaults.SessionKey
	}
	if cfg.SequencePlacement == "" {
		cfg.SequencePlacement = defaults.SequencePlacement
	}
	if cfg.SequenceKey == "" {
		cfg.SequenceKey = defaults.SequenceKey
	}
	if cfg.CMaxReuseTimes == 0 {
		cfg.CMaxReuseTimes = defaults.CMaxReuseTimes
	}
	if cfg.HMaxRequestTimes == 0 {
		cfg.HMaxRequestTimes = defaults.HMaxRequestTimes
	}
	if cfg.HMaxReusableSecs == 0 {
		cfg.HMaxReusableSecs = defaults.HMaxReusableSecs
	}
	if cfg.DrainTimeout == 0 {
		cfg.DrainTimeout = defaults.DrainTimeout
	}

	return cfg
}

// GetMode4bConfig returns the Mode 4b configuration with defaults applied.
func (c *Config) GetMode4bConfig() Mode4bConfig {
	cfg := c.Transport.Mode4b
	defaults := DefaultMode4bConfig()

	// Apply defaults for zero values
	if cfg.AEADMode == "" {
		cfg.AEADMode = defaults.AEADMode
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = defaults.BatchSize
	}
	if cfg.TCPFingerprint == "" {
		cfg.TCPFingerprint = defaults.TCPFingerprint
	}

	return cfg
}

// GetMode4cConfig returns the Mode 4c configuration with defaults applied.
func (c *Config) GetMode4cConfig() Mode4cConfig {
	cfg := c.Transport.Mode4c
	defaults := DefaultMode4cConfig()

	// Apply defaults for zero values
	if cfg.TLSMode == "" {
		cfg.TLSMode = defaults.TLSMode
	}
	if cfg.SpiderX == "" {
		cfg.SpiderX = defaults.SpiderX
	}
	if cfg.SpiderY == [10]int{} {
		cfg.SpiderY = defaults.SpiderY
	}
	if cfg.SpiderConcurrency == 0 {
		cfg.SpiderConcurrency = defaults.SpiderConcurrency
	}
	if cfg.SpiderTimeout == 0 {
		cfg.SpiderTimeout = defaults.SpiderTimeout
	}
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = defaults.MaxDepth
	}
	if cfg.MaxTotalFetches == 0 {
		cfg.MaxTotalFetches = defaults.MaxTotalFetches
	}
	if cfg.PerHostCap == 0 {
		cfg.PerHostCap = defaults.PerHostCap
	}
	if cfg.PaddingScheme == "" {
		cfg.PaddingScheme = defaults.PaddingScheme
	}
	if cfg.PaddingMin == 0 {
		cfg.PaddingMin = defaults.PaddingMin
	}
	if cfg.PaddingMax == 0 {
		cfg.PaddingMax = defaults.PaddingMax
	}
	if cfg.IdleSessionTimeout == 0 {
		cfg.IdleSessionTimeout = defaults.IdleSessionTimeout
	}
	if cfg.RotationInterval == 0 {
		cfg.RotationInterval = defaults.RotationInterval
	}

	return cfg
}

// GetMode4dConfig returns the Mode 4d configuration with defaults applied.
func (c *Config) GetMode4dConfig() Mode4dConfig {
	cfg := c.Transport.Mode4d
	defaults := DefaultMode4dConfig()

	// Apply defaults for zero values
	if cfg.BrutalBandwidth == 0 {
		cfg.BrutalBandwidth = defaults.BrutalBandwidth
	}
	if cfg.DataShards == 0 {
		cfg.DataShards = defaults.DataShards
	}
	if cfg.ParityShards == 0 {
		cfg.ParityShards = defaults.ParityShards
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = defaults.BatchSize
	}

	return cfg
}

// GetMode4eConfig returns the Mode 4e configuration with defaults applied.
func (c *Config) GetMode4eConfig() Mode4eConfig {
	cfg := c.Transport.Mode4e
	defaults := DefaultMode4eConfig()

	// Apply defaults for zero values
	if cfg.HTTPVersion == "" {
		cfg.HTTPVersion = defaults.HTTPVersion
	}
	if cfg.CSTPPath == "" {
		cfg.CSTPPath = defaults.CSTPPath
	}
	if cfg.ICMPMuxMode == "" {
		cfg.ICMPMuxMode = defaults.ICMPMuxMode
	}
	if cfg.RecoveryTimeout == 0 {
		cfg.RecoveryTimeout = defaults.RecoveryTimeout
	}
	if cfg.MaxRecoveryAttempts == 0 {
		cfg.MaxRecoveryAttempts = defaults.MaxRecoveryAttempts
	}
	if cfg.ReconnectBackoff == 0 {
		cfg.ReconnectBackoff = defaults.ReconnectBackoff
	}

	return cfg
}

// ValidateMode validates the transport.mode configuration and mode-specific settings.
func (c *Config) ValidateMode() error {
	modeRaw := c.GetActiveMode()
	mode, ok := canonicalVariantName(modeRaw)
	if !ok {
		return fmt.Errorf("transport.mode must be one of: %s (got: %s)", allowedVariantNamesText(), modeRaw)
	}

	// Validate mode-specific configuration
	switch mode {
	case VariantHTTPPlus:
		return c.validateMode4a()
	case VariantTCPPlus:
		return c.validateMode4b()
	case VariantTLSPlus:
		return c.validateMode4c()
	case VariantUDPPlus:
		return c.validateMode4d()
	case VariantTLS:
		return c.validateMode4e()
	}

	return nil
}

// validateMode4a validates Mode 4a (XHTTP + Domain Fronting) configuration.
func (c *Config) validateMode4a() error {
	cfg := c.GetMode4aConfig()

	// Validate session placement
	validPlacements := map[string]bool{
		"path":   true,
		"query":  true,
		"header": true,
		"cookie": true,
	}

	if !validPlacements[cfg.SessionPlacement] {
		return fmt.Errorf("transport.mode_4a.session_placement must be one of: path, query, header, cookie (got: %s)", cfg.SessionPlacement)
	}

	if !validPlacements[cfg.SequencePlacement] {
		return fmt.Errorf("transport.mode_4a.sequence_placement must be one of: path, query, header, cookie (got: %s)", cfg.SequencePlacement)
	}

	// Validate key names are not empty
	if cfg.SessionKey == "" {
		return fmt.Errorf("transport.mode_4a.session_key cannot be empty")
	}

	if cfg.SequenceKey == "" {
		return fmt.Errorf("transport.mode_4a.sequence_key cannot be empty")
	}

	// Check for key collision
	if cfg.SessionKey == cfg.SequenceKey && cfg.SessionPlacement == cfg.SequencePlacement {
		return fmt.Errorf("transport.mode_4a: session_key and sequence_key cannot be the same when using the same placement type")
	}

	// Validate Xmux limits
	if cfg.XmuxEnabled {
		if cfg.CMaxReuseTimes < 1 {
			return fmt.Errorf("transport.mode_4a.c_max_reuse_times must be >= 1 (got: %d)", cfg.CMaxReuseTimes)
		}

		if cfg.HMaxRequestTimes < 1 {
			return fmt.Errorf("transport.mode_4a.h_max_request_times must be >= 1 (got: %d)", cfg.HMaxRequestTimes)
		}

		if cfg.HMaxReusableSecs < 1 {
			return fmt.Errorf("transport.mode_4a.h_max_reusable_secs must be >= 1 (got: %d)", cfg.HMaxReusableSecs)
		}

		if cfg.DrainTimeout < 1*time.Second {
			return fmt.Errorf("transport.mode_4a.drain_timeout must be >= 1s (got: %v)", cfg.DrainTimeout)
		}
	}

	// Validate domain fronting configuration
	if cfg.FrontingEnabled {
		if cfg.FrontingDomain == "" {
			return fmt.Errorf("transport.mode_4a.fronting_domain is required when fronting_enabled is true")
		}

		if cfg.TargetDomain == "" {
			return fmt.Errorf("transport.mode_4a.target_domain is required when fronting_enabled is true")
		}
	}

	return nil
}

// validateMode4b validates Mode 4b (FakeTCP + Anti-DPI) configuration.
func (c *Config) validateMode4b() error {
	cfg := c.GetMode4bConfig()

	// Validate AEAD mode
	validAEADModes := map[string]bool{
		"off":              true,
		"chacha20poly1305": true,
		"aesgcm":           true,
	}

	if !validAEADModes[cfg.AEADMode] {
		return fmt.Errorf("transport.mode_4b.aead_mode must be one of: off, chacha20poly1305, aesgcm (got: %s)", cfg.AEADMode)
	}

	// Validate shared secret is provided if AEAD is enabled
	if cfg.AEADMode != "off" && cfg.SharedSecret == "" {
		return fmt.Errorf("transport.mode_4b.shared_secret is required when aead_mode is not 'off'")
	}

	// Validate batch I/O configuration
	if cfg.BatchIOEnabled {
		if cfg.BatchSize < 1 || cfg.BatchSize > 64 {
			return fmt.Errorf("transport.mode_4b.batch_size must be between 1 and 64 (got: %d)", cfg.BatchSize)
		}
	}

	// Validate TCP fingerprint
	validFingerprints := map[string]bool{
		"linux":   true,
		"windows": true,
		"macos":   true,
	}

	if !validFingerprints[cfg.TCPFingerprint] {
		return fmt.Errorf("transport.mode_4b.tcp_fingerprint must be one of: linux, windows, macos (got: %s)", cfg.TCPFingerprint)
	}

	// Validate fragment configuration
	if cfg.FragmentEnabled && cfg.FragmentSize < 1 {
		return fmt.Errorf("transport.mode_4b.fragment_size must be >= 1 when fragment_enabled is true (got: %d)", cfg.FragmentSize)
	}

	return nil
}

// validateMode4c validates Mode 4c (TLS-Like + REALITY/AnyTLS) configuration.
func (c *Config) validateMode4c() error {
	cfg := c.GetMode4cConfig()

	// Validate TLS mode
	validTLSModes := map[string]bool{
		"reality": true,
		"anytls":  true,
	}

	if !validTLSModes[cfg.TLSMode] {
		return fmt.Errorf("transport.mode_4c.tls_mode must be one of: reality, anytls (got: %s)", cfg.TLSMode)
	}

	// Validate REALITY configuration
	if cfg.REALITYEnabled {
		if cfg.SpiderX == "" {
			return fmt.Errorf("transport.mode_4c.spider_x is required when reality_enabled is true")
		}

		if cfg.SpiderConcurrency < 1 || cfg.SpiderConcurrency > 16 {
			return fmt.Errorf("transport.mode_4c.spider_concurrency must be between 1 and 16 (got: %d)", cfg.SpiderConcurrency)
		}

		if cfg.SpiderTimeout < 1 {
			return fmt.Errorf("transport.mode_4c.spider_timeout must be >= 1 (got: %d)", cfg.SpiderTimeout)
		}

		if cfg.MaxDepth < 1 || cfg.MaxDepth > 10 {
			return fmt.Errorf("transport.mode_4c.max_depth must be between 1 and 10 (got: %d)", cfg.MaxDepth)
		}

		if cfg.MaxTotalFetches < 1 {
			return fmt.Errorf("transport.mode_4c.max_total_fetches must be >= 1 (got: %d)", cfg.MaxTotalFetches)
		}

		if cfg.PerHostCap < 1 {
			return fmt.Errorf("transport.mode_4c.per_host_cap must be >= 1 (got: %d)", cfg.PerHostCap)
		}
	}

	// Validate AnyTLS configuration
	if cfg.AnyTLSEnabled {
		validPaddingSchemes := map[string]bool{
			"random":   true,
			"fixed":    true,
			"burst":    true,
			"adaptive": true,
		}

		if !validPaddingSchemes[cfg.PaddingScheme] {
			return fmt.Errorf("transport.mode_4c.padding_scheme must be one of: random, fixed, burst, adaptive (got: %s)", cfg.PaddingScheme)
		}

		if cfg.PaddingMin < 0 {
			return fmt.Errorf("transport.mode_4c.padding_min must be >= 0 (got: %d)", cfg.PaddingMin)
		}

		if cfg.PaddingMax < cfg.PaddingMin {
			return fmt.Errorf("transport.mode_4c.padding_max must be >= padding_min (got: max=%d, min=%d)", cfg.PaddingMax, cfg.PaddingMin)
		}

		if cfg.IdleSessionTimeout < 1 {
			return fmt.Errorf("transport.mode_4c.idle_session_timeout must be >= 1 (got: %d)", cfg.IdleSessionTimeout)
		}
	}

	// Validate that at least one mode is enabled
	if !cfg.REALITYEnabled && !cfg.AnyTLSEnabled {
		return fmt.Errorf("transport.mode_4c: either reality_enabled or anytls_enabled must be true")
	}

	// Validate rotation configuration
	if cfg.RotationEnabled && cfg.RotationInterval < 1 {
		return fmt.Errorf("transport.mode_4c.rotation_interval must be >= 1 when rotation_enabled is true (got: %d)", cfg.RotationInterval)
	}

	return nil
}

// validateMode4d validates Mode 4d (QUIC + Brutal CC) configuration.
func (c *Config) validateMode4d() error {
	cfg := c.GetMode4dConfig()

	// Validate Brutal CC configuration
	if cfg.BrutalEnabled {
		if cfg.BrutalBandwidth < 1 {
			return fmt.Errorf("transport.mode_4d.brutal_bandwidth must be >= 1 Mbps (got: %d)", cfg.BrutalBandwidth)
		}
	}

	// Validate FEC configuration
	if cfg.FECEnabled {
		if cfg.DataShards < 3 || cfg.DataShards > 20 {
			return fmt.Errorf("transport.mode_4d.data_shards must be between 3 and 20 (got: %d)", cfg.DataShards)
		}

		if cfg.ParityShards < 1 || cfg.ParityShards > 10 {
			return fmt.Errorf("transport.mode_4d.parity_shards must be between 1 and 10 (got: %d)", cfg.ParityShards)
		}
	}

	// Validate batch I/O configuration
	if cfg.BatchIOEnabled {
		if cfg.BatchSize < 1 || cfg.BatchSize > 64 {
			return fmt.Errorf("transport.mode_4d.batch_size must be between 1 and 64 (got: %d)", cfg.BatchSize)
		}
	}

	// Validate junk packet configuration
	if cfg.JunkPacketsEnabled && cfg.JunkPacketRate < 1 {
		return fmt.Errorf("transport.mode_4d.junk_packet_rate must be >= 1 when junk_packets_enabled is true (got: %d)", cfg.JunkPacketRate)
	}

	return nil
}

// validateMode4e validates Mode 4e (TrustTunnel + CSTP) configuration.
func (c *Config) validateMode4e() error {
	cfg := c.GetMode4eConfig()

	// Validate HTTP version
	validHTTPVersions := map[string]bool{
		"http2": true,
		"http3": true,
	}

	if !validHTTPVersions[cfg.HTTPVersion] {
		return fmt.Errorf("transport.mode_4e.http_version must be one of: http2, http3 (got: %s)", cfg.HTTPVersion)
	}

	// Validate CSTP configuration
	if cfg.CSTPEnabled && cfg.CSTPPath == "" {
		return fmt.Errorf("transport.mode_4e.cstp_path is required when cstp_enabled is true")
	}

	// Validate ICMP mux configuration
	if cfg.ICMPMuxEnabled {
		validICMPModes := map[string]bool{
			"echo":      true,
			"timestamp": true,
		}

		if !validICMPModes[cfg.ICMPMuxMode] {
			return fmt.Errorf("transport.mode_4e.icmp_mux_mode must be one of: echo, timestamp (got: %s)", cfg.ICMPMuxMode)
		}
	}

	// Validate session recovery configuration
	if cfg.SessionRecoveryEnabled {
		if cfg.RecoveryTimeout < 1 {
			return fmt.Errorf("transport.mode_4e.recovery_timeout must be >= 1 (got: %d)", cfg.RecoveryTimeout)
		}

		if cfg.MaxRecoveryAttempts < 1 {
			return fmt.Errorf("transport.mode_4e.max_recovery_attempts must be >= 1 (got: %d)", cfg.MaxRecoveryAttempts)
		}
	}

	// Validate reconnection configuration
	if cfg.ReconnectEnabled && cfg.ReconnectBackoff < 1 {
		return fmt.Errorf("transport.mode_4e.reconnect_backoff must be >= 1 when reconnect_enabled is true (got: %d)", cfg.ReconnectBackoff)
	}

	return nil
}
