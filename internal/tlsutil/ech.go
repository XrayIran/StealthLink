// Package tlsutil provides ECH (Encrypted Client Hello) support.
// ECH hides the SNI from network observers by encrypting the Client Hello.
package tlsutil

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/dns/dnsmessage"
)

// ECHConfig configures Encrypted Client Hello.
type ECHConfig struct {
	Enabled      bool   `yaml:"enabled"`
	DoHEndpoint  string `yaml:"doh_endpoint"`  // DNS-over-HTTPS endpoint
	QueryPadding bool   `yaml:"query_padding"` // Pad DNS queries
	PaddingMin   int    `yaml:"padding_min"`   // Min padding bytes
	PaddingMax   int    `yaml:"padding_max"`   // Max padding bytes
	RetryWithout bool   `yaml:"retry_without"` // Retry without ECH on failure
	ConfigID     uint8  `yaml:"config_id"`     // ECH config ID to use
}

// ApplyDefaults sets default values.
func (c *ECHConfig) ApplyDefaults() {
	if c.DoHEndpoint == "" {
		c.DoHEndpoint = "https://cloudflare-dns.com/dns-query"
	}
	if c.PaddingMin <= 0 {
		c.PaddingMin = 100
	}
	if c.PaddingMax <= 0 {
		c.PaddingMax = 300
	}
}

// ECHResolver resolves ECH configs from DNS HTTPS records.
type ECHResolver struct {
	config ECHConfig
	client *http.Client
	cache  map[string]*ECHConfigRecord
	mu     sync.RWMutex
}

// ECHConfigRecord represents a cached ECH config.
type ECHConfigRecord struct {
	Hostname   string
	Config     []byte
	PublicName string
	Expiry     time.Time
}

// NewECHResolver creates a new ECH resolver.
func NewECHResolver(config ECHConfig) *ECHResolver {
	config.ApplyDefaults()
	return &ECHResolver{
		config: config,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache: make(map[string]*ECHConfigRecord),
	}
}

// Resolve fetches ECH config for a hostname.
func (r *ECHResolver) Resolve(ctx context.Context, hostname string) (*ECHConfigRecord, error) {
	if !r.config.Enabled {
		return nil, fmt.Errorf("ECH not enabled")
	}

	// Check cache
	r.mu.RLock()
	if cached, ok := r.cache[hostname]; ok && time.Now().Before(cached.Expiry) {
		r.mu.RUnlock()
		return cached, nil
	}
	r.mu.RUnlock()

	// Query DNS for HTTPS records
	configs, err := r.queryHTTPS(ctx, hostname)
	if err != nil {
		return nil, err
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("no ECH config found for %s", hostname)
	}

	// Cache and return first config
	record := &ECHConfigRecord{
		Hostname: hostname,
		Config:   normalizeECHConfigList(configs[0]),
		Expiry:   time.Now().Add(1 * time.Hour),
	}
	r.mu.Lock()
	r.cache[hostname] = record
	r.mu.Unlock()

	return record, nil
}

// Invalidate removes cached ECH config for a hostname.
func (r *ECHResolver) Invalidate(hostname string) {
	r.mu.Lock()
	delete(r.cache, hostname)
	r.mu.Unlock()
}

// queryHTTPS queries DNS HTTPS records for ECH config.
func (r *ECHResolver) queryHTTPS(ctx context.Context, hostname string) ([][]byte, error) {
	// Build DNS query
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: uint16(1234), // Fixed ID for simplicity
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(hostname + "."),
				Type:  dnsmessage.TypeHTTPS,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	// Add padding if enabled
	if r.config.QueryPadding {
		padding := r.generatePadding()
		msg.Additionals = append(msg.Additionals, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: 4096, // UDP payload size
			},
			Body: &dnsmessage.OPTResource{
				Options: []dnsmessage.Option{
					{
						Code: 12, // Padding option
						Data: []byte(padding),
					},
				},
			},
		})
	}

	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS query: %w", err)
	}

	// Send DoH query
	req, err := http.NewRequestWithContext(ctx, "POST", r.config.DoHEndpoint, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}

	var response dnsmessage.Message
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack DNS response: %w", err)
	}

	// Extract ECH configs from HTTPS records
	var echConfigs [][]byte
	for _, ans := range response.Answers {
		if ans.Header.Type == dnsmessage.TypeHTTPS {
			extracted, err := extractECHConfigsFromHTTPSAnswer(ans.Body)
			if err != nil {
				continue
			}
			echConfigs = append(echConfigs, extracted...)
		}
	}

	return echConfigs, nil
}

func extractECHConfigsFromHTTPSAnswer(body dnsmessage.ResourceBody) ([][]byte, error) {
	switch https := body.(type) {
	case *dnsmessage.HTTPSResource:
		var out [][]byte
		for _, param := range https.Params {
			if param.Key == 5 { // ech
				ech := make([]byte, len(param.Value))
				copy(ech, param.Value)
				out = append(out, ech)
			}
		}
		return out, nil
	case *dnsmessage.UnknownResource:
		return parseECHConfigsFromHTTPSRData(https.Data)
	default:
		return nil, fmt.Errorf("unsupported HTTPS answer body: %T", body)
	}
}

func parseECHConfigsFromHTTPSRData(rdata []byte) ([][]byte, error) {
	// HTTPS RR RDATA format: priority(2) + targetName + SvcParams...
	if len(rdata) < 3 {
		return nil, fmt.Errorf("HTTPS RDATA too short")
	}

	offset := 2 // skip priority
	nameEnd, err := skipDNSName(rdata, offset)
	if err != nil {
		return nil, err
	}
	offset = nameEnd

	var out [][]byte
	for offset+4 <= len(rdata) {
		key := binary.BigEndian.Uint16(rdata[offset : offset+2])
		valueLen := int(binary.BigEndian.Uint16(rdata[offset+2 : offset+4]))
		offset += 4
		if offset+valueLen > len(rdata) {
			return nil, fmt.Errorf("SVCB param length overflow")
		}
		if key == 5 {
			ech := make([]byte, valueLen)
			copy(ech, rdata[offset:offset+valueLen])
			out = append(out, ech)
		}
		offset += valueLen
	}
	return out, nil
}

func skipDNSName(data []byte, offset int) (int, error) {
	seen := 0
	for {
		if offset >= len(data) {
			return 0, fmt.Errorf("invalid DNS name encoding")
		}
		l := data[offset]
		offset++
		switch {
		case l == 0:
			return offset, nil
		case l&0xC0 == 0xC0:
			// Compression pointer (2 bytes including current octet).
			if offset >= len(data) {
				return 0, fmt.Errorf("invalid DNS compression pointer")
			}
			return offset + 1, nil
		default:
			labelLen := int(l)
			if offset+labelLen > len(data) {
				return 0, fmt.Errorf("invalid DNS label length")
			}
			offset += labelLen
		}
		seen++
		if seen > 128 {
			return 0, fmt.Errorf("DNS name too long")
		}
	}
}

func (r *ECHResolver) generatePadding() string {
	// Generate random padding
	length := r.config.PaddingMin
	if r.config.PaddingMax > r.config.PaddingMin {
		delta := r.config.PaddingMax - r.config.PaddingMin
		length += randInt(delta)
	}
	padding := make([]byte, length)
	randRead(padding)
	return string(padding)
}

// ECHDialer wraps a TLS dialer with ECH support.
type ECHDialer struct {
	resolver *ECHResolver
	dialer   *tls.Dialer
}

// NewECHDialer creates a new ECH-enabled dialer.
func NewECHDialer(config ECHConfig) *ECHDialer {
	return &ECHDialer{
		resolver: NewECHResolver(config),
		dialer: &tls.Dialer{
			Config: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		},
	}
}

// Dial connects with ECH.
func (d *ECHDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}
	host = strings.TrimSpace(host)

	// Resolve ECH config
	echRecord, err := d.resolver.Resolve(ctx, host)
	if err != nil {
		if d.resolver.config.RetryWithout {
			// Fall back to regular TLS
			return d.dialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("ECH resolution failed: %w", err)
	}

	// Configure TLS with ECH
	config := d.dialer.Config.Clone()
	config.ServerName = host
	config.EncryptedClientHelloConfigList = normalizeECHConfigList(echRecord.Config)

	echDialer := &tls.Dialer{
		Config: config,
	}
	conn, err := echDialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	if err == nil {
		return conn, nil
	}
	d.resolver.Invalidate(host)
	if !d.resolver.config.RetryWithout {
		return nil, err
	}

	// Retry without ECH if configured.
	return d.dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
}

// ECHConn wraps a connection with ECH metadata.
type ECHConn struct {
	net.Conn
	ECHUsed    bool
	PublicName string
}

// IsECHAvailable checks if ECH is available for a hostname.
func IsECHAvailable(ctx context.Context, hostname string) bool {
	resolver := NewECHResolver(ECHConfig{Enabled: true})
	_, err := resolver.Resolve(ctx, hostname)
	return err == nil
}

// ParseECHConfig parses an ECH config from bytes.
func ParseECHConfig(data []byte) (*ECHConfigRecord, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("ECH config too short")
	}

	// Parse ECHConfig structure
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17
	version := uint16(data[0])<<8 | uint16(data[1])
	_ = version

	length := uint16(data[2])<<8 | uint16(data[3])
	if len(data) < int(length)+4 {
		return nil, fmt.Errorf("ECH config length mismatch")
	}

	return &ECHConfigRecord{
		Config: data,
	}, nil
}

// NormalizeECHConfigList ensures data is in TLS ECHConfigList wire format.
func NormalizeECHConfigList(data []byte) []byte {
	return normalizeECHConfigList(data)
}

func normalizeECHConfigList(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	// Already an ECHConfigList: uint16 list_len || entries
	if len(data) >= 2 {
		listLen := int(binary.BigEndian.Uint16(data[:2]))
		if listLen == len(data)-2 {
			out := make([]byte, len(data))
			copy(out, data)
			return out
		}
	}

	// Wrap single ECHConfig into ECHConfigList.
	entryLen := len(data)
	out := make([]byte, 2+2+entryLen)
	binary.BigEndian.PutUint16(out[0:2], uint16(2+entryLen))
	binary.BigEndian.PutUint16(out[2:4], uint16(entryLen))
	copy(out[4:], data)
	return out
}

type echContextKey struct{}

// ECHDialOptions controls per-dial ECH behavior through context.
type ECHDialOptions struct {
	Enabled    bool
	RequireECH bool
	PublicName string
	InnerSNI   string
	ConfigList []byte
}

// WithECHDialOptions injects ECH dial options into a context.
func WithECHDialOptions(ctx context.Context, opts ECHDialOptions) context.Context {
	return context.WithValue(ctx, echContextKey{}, opts)
}

// ECHDialOptionsFromContext reads ECH dial options from a context.
func ECHDialOptionsFromContext(ctx context.Context) (ECHDialOptions, bool) {
	v := ctx.Value(echContextKey{})
	if v == nil {
		return ECHDialOptions{}, false
	}
	opts, ok := v.(ECHDialOptions)
	return opts, ok
}

type frontContextKey struct{}

// FrontDialOptions controls domain-fronting and CDN dial behavior through context.
type FrontDialOptions struct {
	Enabled       bool
	PoolKey       string
	FrontDomain   string
	RealHost      string
	ConnectIP     string
	// ConnectIPCandidates provides additional connect-address candidates (IPs).
	// When present, the dialer should try candidates in order (or health-sorted)
	// before giving up. ConnectIP remains as the primary/legacy single-candidate field.
	ConnectIPCandidates []string
	CFWorker      string
	FailoverHosts []string
}

// WithFrontDialOptions injects fronting options into a context.
func WithFrontDialOptions(ctx context.Context, opts FrontDialOptions) context.Context {
	return context.WithValue(ctx, frontContextKey{}, opts)
}

// FrontDialOptionsFromContext reads fronting options from context.
func FrontDialOptionsFromContext(ctx context.Context) (FrontDialOptions, bool) {
	v := ctx.Value(frontContextKey{})
	if v == nil {
		return FrontDialOptions{}, false
	}
	opts, ok := v.(FrontDialOptions)
	return opts, ok
}

// EncodeECHExtension encodes an ECH extension for Client Hello.
func EncodeECHExtension(echConfig []byte) []byte {
	// ECH extension type: 0xfe0d (draft-17)
	extType := []byte{0xfe, 0x0d}

	// Extension data: config_id + kem_id + config
	// Simplified encoding
	data := make([]byte, 0, len(echConfig)+4)
	data = append(data, echConfig...)

	// Extension length
	length := make([]byte, 2)
	length[0] = byte(len(data) >> 8)
	length[1] = byte(len(data))

	return append(extType, append(length, data...)...)
}

// GenerateECHKey generates an ECH key pair.
func GenerateECHKey() ([]byte, []byte, error) {
	privateKey := make([]byte, 32)
	if _, err := randRead(privateKey); err != nil {
		return nil, nil, err
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive ECH public key: %w", err)
	}

	return publicKey, privateKey, nil
}

// Helper functions
func randRead(p []byte) (int, error) {
	return rand.Read(p)
}

// ECHStatus represents the status of ECH negotiation.
type ECHStatus int

const (
	ECHStatusNotAttempted ECHStatus = iota
	ECHStatusSuccess
	ECHStatusFailure
	ECHStatusRetryWithout
)

// String returns the status as a string.
func (s ECHStatus) String() string {
	switch s {
	case ECHStatusNotAttempted:
		return "not_attempted"
	case ECHStatusSuccess:
		return "success"
	case ECHStatusFailure:
		return "failure"
	case ECHStatusRetryWithout:
		return "retry_without"
	default:
		return "unknown"
	}
}

// WrapWithECH wraps an existing connection with ECH.
// This is a placeholder for future full ECH implementation.
func WrapWithECH(conn net.Conn, echConfig *ECHConfigRecord) (net.Conn, error) {
	return &ECHConn{
		Conn:       conn,
		ECHUsed:    true,
		PublicName: echConfig.PublicName,
	}, nil
}
