package behavior

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"stealthlink/internal/config"
	"stealthlink/internal/tlsutil"
)

// ECHOverlay ports Encrypted Client Hello behaviors as a UQSP overlay.
// ECH encrypts the SNI in TLS handshakes to prevent traffic analysis.
type ECHOverlay struct {
	EnabledField bool
	PublicName   string   // Outer SNI (e.g., cloudflare-ech.com)
	InnerSNI     string   // Actual destination (encrypted)
	Configs      [][]byte // ECH configs from DNS HTTPS records
	RequireECH   bool
}

// NewECHOverlay creates a new ECH overlay from config
func NewECHOverlay(cfg config.ECHBehaviorConfig) *ECHOverlay {
	// Decode ECH configs if provided as base64 strings
	var configs [][]byte
	for _, cfgStr := range cfg.Configs {
		decoded, err := base64.StdEncoding.DecodeString(cfgStr)
		if err == nil {
			configs = append(configs, decoded)
		}
	}

	return &ECHOverlay{
		EnabledField: cfg.Enabled,
		PublicName:   cfg.PublicName,
		InnerSNI:     cfg.InnerSNI,
		Configs:      configs,
		RequireECH:   cfg.RequireECH,
	}
}

// Name returns "ech"
func (o *ECHOverlay) Name() string {
	return "ech"
}

// Enabled returns whether this overlay is enabled
func (o *ECHOverlay) Enabled() bool {
	return o.EnabledField
}

// Apply applies ECH behavior to the connection
func (o *ECHOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}
	cfgs := make([][]byte, 0, len(o.Configs))
	for _, cfg := range o.Configs {
		if len(cfg) == 0 {
			continue
		}
		cp := make([]byte, len(cfg))
		copy(cp, cfg)
		cfgs = append(cfgs, cp)
	}
	return &echConn{
		Conn:       conn,
		publicName: o.PublicName,
		innerSNI:   o.InnerSNI,
		configs:    cfgs,
		requireECH: o.RequireECH,
	}, nil
}

// PrepareContext wires ECH options into the dial pipeline before TLS is established.
func (o *ECHOverlay) PrepareContext(ctx context.Context) (context.Context, error) {
	if !o.EnabledField {
		return ctx, nil
	}

	opts := tlsutil.ECHDialOptions{
		Enabled:    true,
		RequireECH: o.RequireECH,
		PublicName: strings.TrimSpace(o.PublicName),
		InnerSNI:   strings.TrimSpace(o.InnerSNI),
		ConfigList: flattenECHConfigs(o.Configs),
	}

	if len(opts.ConfigList) == 0 {
		host := opts.InnerSNI
		if host == "" {
			host = opts.PublicName
		}
		if host != "" {
			resolver := tlsutil.NewECHResolver(tlsutil.ECHConfig{
				Enabled:      true,
				RetryWithout: !opts.RequireECH,
			})
			record, err := resolver.Resolve(ctx, host)
			if err != nil && opts.RequireECH {
				return nil, fmt.Errorf("resolve ECH config for %s: %w", host, err)
			}
			if err == nil {
				opts.ConfigList = tlsutil.NormalizeECHConfigList(record.Config)
			}
		}
	}

	return tlsutil.WithECHDialOptions(ctx, opts), nil
}

// echConn wraps a connection with ECH behavior
type echConn struct {
	net.Conn
	publicName    string
	innerSNI      string
	configs       [][]byte
	requireECH    bool
	handshakeDone bool
}

// ClientHandshake performs the ECH client handshake
func (c *echConn) ClientHandshake(tlsConfig *tls.Config) (*tls.Conn, error) {
	if c.handshakeDone {
		return nil, fmt.Errorf("handshake already completed")
	}

	echTLSConfig := tlsConfig.Clone()
	if echTLSConfig == nil {
		echTLSConfig = &tls.Config{}
	}

	if c.publicName != "" {
		echTLSConfig.ServerName = c.publicName
	}

	if len(c.configs) > 0 && c.requireECH {
		echTLSConfig.EncryptedClientHelloConfigList = flattenECHConfigs(c.configs)
	}

	tlsConn := tls.Client(c.Conn, echTLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("ECH handshake: %w", err)
	}

	c.handshakeDone = true
	return tlsConn, nil
}

// ServerHandshake performs the ECH server handshake
func (c *echConn) ServerHandshake(tlsConfig *tls.Config) (*tls.Conn, error) {
	if c.handshakeDone {
		return nil, fmt.Errorf("handshake already completed")
	}

	if len(c.configs) > 0 && tlsConfig != nil {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.EncryptedClientHelloConfigList = flattenECHConfigs(c.configs)
	}

	tlsConn := tls.Server(c.Conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("ECH server handshake: %w", err)
	}

	c.handshakeDone = true
	return tlsConn, nil
}

// flattenECHConfigs concatenates multiple ECH configs into a single byte slice
func flattenECHConfigs(configs [][]byte) []byte {
	if len(configs) == 0 {
		return nil
	}
	if len(configs) == 1 {
		return tlsutil.NormalizeECHConfigList(configs[0])
	}
	totalEntries := 0
	for _, cfg := range configs {
		totalEntries += 2 + len(cfg)
	}
	if totalEntries > 0xFFFF {
		return nil
	}
	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result[:2], uint16(totalEntries))
	for _, cfg := range configs {
		if len(cfg) > 0xFFFF {
			return nil
		}
		result = binary.BigEndian.AppendUint16(result, uint16(len(cfg)))
		result = append(result, cfg...)
	}
	return result
}

// Read reads data from the connection
func (c *echConn) Read(p []byte) (int, error) {
	return c.Conn.Read(p)
}

// Write writes data to the connection
func (c *echConn) Write(p []byte) (int, error) {
	return c.Conn.Write(p)
}

// Ensure echConn implements net.Conn
var _ net.Conn = (*echConn)(nil)

// ECHConfig represents an ECH configuration
type ECHConfig struct {
	Version           uint16
	ConfigID          uint8
	KEMID             uint16
	PublicKey         []byte
	CipherSuites      []uint32
	MaximumNameLength uint8
}

// DecodeECHConfig decodes an ECH configuration from bytes
func DecodeECHConfig(data []byte) (*ECHConfig, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("ECH config too short")
	}

	cfg := &ECHConfig{
		Version:  binary.BigEndian.Uint16(data[0:2]),
		ConfigID: data[2],
		KEMID:    binary.BigEndian.Uint16(data[3:5]),
	}

	// Parse public key length and key
	pubKeyLen := binary.BigEndian.Uint16(data[5:7])
	if len(data) < 7+int(pubKeyLen)+3 {
		return nil, fmt.Errorf("ECH config truncated")
	}
	cfg.PublicKey = data[7 : 7+pubKeyLen]

	offset := 7 + int(pubKeyLen)

	// Parse cipher suites
	cipherSuiteLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	for i := 0; i < int(cipherSuiteLen)/4; i++ {
		if offset+4 > len(data) {
			break
		}
		kdfID := binary.BigEndian.Uint16(data[offset : offset+2])
		aeadID := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		// Combine KDF and AEID into a cipher suite identifier
		cfg.CipherSuites = append(cfg.CipherSuites, (uint32(kdfID)<<16)|uint32(aeadID))
		offset += 4
	}

	if offset < len(data) {
		cfg.MaximumNameLength = data[offset]
	}

	return cfg, nil
}

// SelectConfig selects the best ECH config from available configs
func SelectConfig(configs []*ECHConfig) *ECHConfig {
	if len(configs) == 0 {
		return nil
	}

	// Prefer configs with higher version numbers (newer)
	var best *ECHConfig
	for _, cfg := range configs {
		if best == nil || cfg.Version > best.Version {
			best = cfg
		}
	}

	return best
}

// ECHClientConfig holds ECH client configuration
type ECHClientConfig struct {
	PublicName string
	InnerSNI   string
	Configs    []*ECHConfig
	RequireECH bool
}

// ECHClient represents an ECH client
type ECHClient struct {
	config         *ECHClientConfig
	selectedConfig *ECHConfig
}

// NewECHClient creates a new ECH client
func NewECHClient(config *ECHClientConfig) (*ECHClient, error) {
	if len(config.Configs) == 0 {
		return nil, fmt.Errorf("no ECH configs provided")
	}

	selected := SelectConfig(config.Configs)
	if selected == nil {
		return nil, fmt.Errorf("no valid ECH config found")
	}

	return &ECHClient{
		config:         config,
		selectedConfig: selected,
	}, nil
}

// GetSelectedConfig returns the selected ECH config
func (c *ECHClient) GetSelectedConfig() *ECHConfig {
	return c.selectedConfig
}
