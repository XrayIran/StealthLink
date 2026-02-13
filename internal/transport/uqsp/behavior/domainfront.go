package behavior

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"stealthlink/internal/tlsutil"
)

// DomainFrontOverlay implements domain fronting for CDN-based hiding.
// It modifies the TLS SNI (outer) to a front domain while keeping the
// HTTP Host header pointing to the real destination.
type DomainFrontOverlay struct {
	EnabledField bool   `yaml:"enabled"`
	FrontDomain  string `yaml:"front_domain"` // e.g., "cdn.cloudflare.com"
	RealHost     string `yaml:"real_host"`    // e.g., "real.example.com"
	CFWorker     string `yaml:"cf_worker"`    // Cloudflare Worker route header

	// Cloudflare IP range rotation
	RotateIPs       bool     `yaml:"rotate_ips"`
	CustomIPs       []string `yaml:"custom_ips"`
	FailoverDomains []string `yaml:"failover_domains"`

	// HTTP-specific settings
	PreserveHostHeader bool `yaml:"preserve_host_header"`

	mu         sync.RWMutex
	currentIP  string
	ipIndex    int
	frontIndex int // cycles through FrontDomain + FailoverDomains
	httpClient *http.Client
}

// Name returns the name of this overlay
func (d *DomainFrontOverlay) Name() string {
	return "domainfront"
}

// Enabled returns whether this overlay is enabled (for Overlay interface)
func (d *DomainFrontOverlay) Enabled() bool {
	return d.EnabledField
}

// Validate validates the configuration
func (d *DomainFrontOverlay) Validate() error {
	if !d.EnabledField {
		return nil
	}

	if d.FrontDomain == "" {
		return fmt.Errorf("front_domain is required for domain fronting")
	}

	if d.RealHost == "" {
		return fmt.Errorf("real_host is required for domain fronting")
	}

	return nil
}

// Apply applies the domain fronting overlay to a connection
func (d *DomainFrontOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !d.EnabledField {
		return conn, nil
	}

	// Domain fronting is applied at the TLS level, not the connection level
	// The actual implementation wraps the dialer to modify the SNI
	return &domainFrontConn{
		Conn:        conn,
		overlay:     d,
		frontDomain: d.FrontDomain,
		realHost:    d.RealHost,
	}, nil
}

// PrepareContext wires domain-fronting options into dial path.
// Each call rotates the active front domain so successive dials distribute
// across the primary + failover domains.
func (d *DomainFrontOverlay) PrepareContext(ctx context.Context) (context.Context, error) {
	if !d.EnabledField {
		return ctx, nil
	}
	activeFront := d.SelectFront()
	connectIP := d.SelectIP()

	// Build failover list excluding the active front (it's already primary).
	var failover []string
	if d.FrontDomain != "" && d.FrontDomain != activeFront {
		failover = append(failover, d.FrontDomain)
	}
	for _, h := range d.FailoverDomains {
		if h != activeFront {
			failover = append(failover, h)
		}
	}

	opts := tlsutil.FrontDialOptions{
		Enabled:       true,
		FrontDomain:   activeFront,
		RealHost:      d.RealHost,
		ConnectIP:     connectIP,
		CFWorker:      d.CFWorker,
		FailoverHosts: failover,
	}
	return tlsutil.WithFrontDialOptions(ctx, opts), nil
}

// GetTLSConfig returns a TLS config with the front domain as SNI
func (d *DomainFrontOverlay) GetTLSConfig(originalConfig *tls.Config) *tls.Config {
	if !d.EnabledField || d.FrontDomain == "" {
		return originalConfig
	}

	config := originalConfig.Clone()
	config.ServerName = d.FrontDomain

	return config
}

// GetHTTPHost returns the real host for HTTP Host header
func (d *DomainFrontOverlay) GetHTTPHost() string {
	if !d.EnabledField {
		return ""
	}
	return d.RealHost
}

// SelectFront returns the current front domain and advances the rotation index.
// The rotation pool is [FrontDomain] + FailoverDomains; when the pool is empty
// or exhausted, it wraps around.
func (d *DomainFrontOverlay) SelectFront() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	pool := d.frontPool()
	if len(pool) == 0 {
		return d.FrontDomain
	}
	front := pool[d.frontIndex%len(pool)]
	d.frontIndex = (d.frontIndex + 1) % len(pool)
	return front
}

// frontPool builds the combined front domain list (must hold d.mu).
func (d *DomainFrontOverlay) frontPool() []string {
	pool := make([]string, 0, 1+len(d.FailoverDomains))
	if d.FrontDomain != "" {
		pool = append(pool, d.FrontDomain)
	}
	pool = append(pool, d.FailoverDomains...)
	return pool
}

// SelectIP selects an IP to connect to (for rotation)
func (d *DomainFrontOverlay) SelectIP() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.RotateIPs {
		return ""
	}

	// Rotate through custom IPs first.
	if len(d.CustomIPs) > 0 {
		ip := d.CustomIPs[d.ipIndex]
		d.ipIndex = (d.ipIndex + 1) % len(d.CustomIPs)
		d.currentIP = ip
		return ip
	}

	// Fall back to sampled Cloudflare ranges.
	if ip, ok := randomCloudflareIPv4(); ok {
		d.currentIP = ip
		return ip
	}
	return ""
}

// domainFrontConn wraps a connection for domain fronting
type domainFrontConn struct {
	net.Conn
	overlay     *DomainFrontOverlay
	frontDomain string
	realHost    string
	mu          sync.Mutex
}

// DomainFrontDialer wraps a dialer with domain fronting
type DomainFrontDialer struct {
	Dialer    func(network, addr string) (net.Conn, error)
	Overlay   *DomainFrontOverlay
	TLSConfig *tls.Config
}

// Dial connects with domain fronting
func (d *DomainFrontDialer) Dial(network, addr string) (net.Conn, error) {
	if !d.Overlay.EnabledField {
		return d.Dialer(network, addr)
	}

	// Use front domain for connection if rotating IPs
	connectAddr := addr
	if ip := strings.TrimSpace(d.Overlay.SelectIP()); ip != "" && ip != d.Overlay.FrontDomain {
		// Extract port from original address
		_, port, splitErr := net.SplitHostPort(addr)
		if splitErr == nil {
			if port == "" {
				port = "443"
			}
			connectAddr = net.JoinHostPort(ip, port)
		}
	}

	// Dial the connection
	conn, err := d.Dialer(network, connectAddr)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS using front domain as SNI
	tlsConfig := d.Overlay.GetTLSConfig(d.TLSConfig)
	tlsConn := tls.Client(conn, tlsConfig)

	// Perform handshake
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	return &domainFrontTLSConn{
		Conn:        tlsConn,
		realHost:    d.Overlay.RealHost,
		frontDomain: d.Overlay.FrontDomain,
	}, nil
}

// domainFrontTLSConn wraps a TLS connection with domain fronting
type domainFrontTLSConn struct {
	*tls.Conn
	realHost    string
	frontDomain string
}

// GetFrontDomain returns the front domain used for SNI
func (c *domainFrontTLSConn) GetFrontDomain() string {
	return c.frontDomain
}

// GetRealHost returns the real host for HTTP Host header
func (c *domainFrontTLSConn) GetRealHost() string {
	return c.realHost
}

// DomainFrontHTTPTransport creates an HTTP transport with domain fronting
func DomainFrontHTTPTransport(overlay *DomainFrontOverlay, tlsConfig *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig: overlay.GetTLSConfig(tlsConfig),
		DialTLS: func(network, addr string) (net.Conn, error) {
			dialer := &DomainFrontDialer{
				Dialer:    (&net.Dialer{Timeout: 30 * time.Second}).Dial,
				Overlay:   overlay,
				TLSConfig: tlsConfig,
			}
			return dialer.Dial(network, addr)
		},
	}
}

// DomainFrontConfig configures domain fronting
type DomainFrontConfig struct {
	Enabled            bool     `yaml:"enabled"`
	FrontDomain        string   `yaml:"front_domain"`
	RealHost           string   `yaml:"real_host"`
	RotateIPs          bool     `yaml:"rotate_ips"`
	CustomIPs          []string `yaml:"custom_ips"`
	PreserveHostHeader bool     `yaml:"preserve_host_header"`
}

// ToOverlay converts config to overlay
func (c *DomainFrontConfig) ToOverlay() *DomainFrontOverlay {
	return &DomainFrontOverlay{
		EnabledField:       c.Enabled,
		FrontDomain:        c.FrontDomain,
		RealHost:           c.RealHost,
		RotateIPs:          c.RotateIPs,
		CustomIPs:          c.CustomIPs,
		PreserveHostHeader: c.PreserveHostHeader,
	}
}

// Common front domains for popular CDNs
var CommonFrontDomains = map[string][]string{
	"cloudflare": {
		"cdn.cloudflare.com",
		"www.cloudflare.com",
		"cloudflare.com",
	},
	"fastly": {
		"github.map.fastly.net",
		"staging.map.fastly.net",
	},
	"cloudfront": {
		"cdn.amazon.com",
		"static.amazon.com",
	},
	"google": {
		"www.google.com",
		"ssl.gstatic.com",
	},
}

var cloudflareIPv4CIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

func randomCloudflareIPv4() (string, bool) {
	if len(cloudflareIPv4CIDRs) == 0 {
		return "", false
	}
	idx := randInt(len(cloudflareIPv4CIDRs))
	_, cidr, err := net.ParseCIDR(cloudflareIPv4CIDRs[idx])
	if err != nil {
		return "", false
	}
	ip := cidr.IP.To4()
	if ip == nil {
		return "", false
	}
	mask := cidr.Mask
	netPart := []byte{ip[0] & mask[0], ip[1] & mask[1], ip[2] & mask[2], ip[3] & mask[3]}
	hostBits := 32 - maskSize(mask)
	if hostBits <= 1 {
		return net.IP(netPart).String(), true
	}
	max := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", false
	}
	host := n.Uint64()
	base := uint32(netPart[0])<<24 | uint32(netPart[1])<<16 | uint32(netPart[2])<<8 | uint32(netPart[3])
	out := base | uint32(host)
	res := net.IPv4(byte(out>>24), byte(out>>16), byte(out>>8), byte(out))
	return res.String(), true
}

func maskSize(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

// SelectRandomFrontDomain selects a random front domain from a provider
func SelectRandomFrontDomain(provider string) string {
	domains, ok := CommonFrontDomains[provider]
	if !ok || len(domains) == 0 {
		return ""
	}

	// Random selection
	b := make([]byte, 1)
	rand.Read(b)
	return domains[int(b[0])%len(domains)]
}

// DomainFrontDetector detects domain fronting in incoming connections
type DomainFrontDetector struct {
	mu           sync.RWMutex
	frontDomains map[string]bool
}

// NewDomainFrontDetector creates a new detector
func NewDomainFrontDetector() *DomainFrontDetector {
	return &DomainFrontDetector{
		frontDomains: make(map[string]bool),
	}
}

// AddFrontDomain adds a front domain to detect
func (d *DomainFrontDetector) AddFrontDomain(domain string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.frontDomains[strings.ToLower(domain)] = true
}

// IsFrontDomain checks if a domain is a known front domain
func (d *DomainFrontDetector) IsFrontDomain(domain string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.frontDomains[strings.ToLower(domain)]
}

// Detect detects domain fronting by comparing SNI and Host header
func (d *DomainFrontDetector) Detect(sni, host string) bool {
	// If SNI is a front domain but Host is different, this is domain fronting
	if d.IsFrontDomain(sni) && !d.IsFrontDomain(host) {
		return true
	}
	return false
}

// DomainFrontMetrics tracks domain fronting statistics
type DomainFrontMetrics struct {
	TotalConnections   uint64
	FrontedConnections uint64
	Errors             uint64
	mu                 sync.RWMutex
}

// RecordConnection records a connection
func (m *DomainFrontMetrics) RecordConnection(fronted bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalConnections++
	if fronted {
		m.FrontedConnections++
	}
}

// RecordError records an error
func (m *DomainFrontMetrics) RecordError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Errors++
}

// GetStats returns current statistics
func (m *DomainFrontMetrics) GetStats() (total, fronted, errors uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.TotalConnections, m.FrontedConnections, m.Errors
}
