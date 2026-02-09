// Package psiphon implements Psiphon protocol support
// including OSSH (Obfuscated SSH), meek (CDN tunneling), and TLS parrot.
package psiphon

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
	"golang.org/x/crypto/ssh"
)

// ProtocolType represents Psiphon transport protocol type
type ProtocolType string

const (
	ProtocolOSSH         ProtocolType = "OSSH"         // Obfuscated SSH
	ProtocolSSH          ProtocolType = "SSH"          // Plain SSH
	ProtocolMeek         ProtocolType = "meek"         // CDN-based HTTP
	ProtocolMeekHTTPS    ProtocolType = "meek_https"   // CDN with HTTPS
	ProtocolFronted      ProtocolType = "fronted"      // Domain fronting
	ProtocolTLS          ProtocolType = "tls"          // TLS parrot
	ProtocolObfs4        ProtocolType = "obfs4"        // obfs4
	ProtocolScrambleSuit ProtocolType = "scramblesuit" // ScrambleSuit
)

// Config configures Psiphon transport
type Config struct {
	// Server discovery
	DiscoveryURL string
	ClientID     string

	// Static server config (if not using discovery)
	Servers []ServerEntry

	// Protocol preferences
	Protocols []ProtocolType

	// TLS configuration
	TLSConfig *tls.Config

	// Authentication
	SshUsername string
	SshPassword string
	SshPrivateKey string

	// Meek settings
	MeekCDNFrontingHosts []string
	MeekUTLSFingerprint  string

	// OSSH settings
	OSSHKey string

	// Timeouts
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	Keepalive        time.Duration
}

// ServerEntry represents a Psiphon server
type ServerEntry struct {
	IPAddress          string         `json:"ipAddress"`
	Region             string         `json:"region"`
	Protocol           ProtocolType   `json:"protocol"`
	Port               int            `json:"port"`
	SSHHostKey         string         `json:"sshHostKey"`
	SSHUsername        string         `json:"sshUsername"`
	SSHPassword        string         `json:"sshPassword"`
	SSHObfuscatedKey   string         `json:"sshObfuscatedKey"`
	MeekFrontingDomain string         `json:"meekFrontingDomain"`
	MeekFrontingHosts  []string       `json:"meekFrontingHosts"`
	MeekCookieEncryptionPublicKey string `json:"meekCookieEncryptionPublicKey"`
	TLSDisableSNI      bool           `json:"tlsDisableSNI"`
	TLSServerName      string         `json:"tlsServerName"`
}

// DefaultConfig returns default Psiphon configuration
func DefaultConfig() *Config {
	return &Config{
		Protocols:        []ProtocolType{ProtocolOSSH, ProtocolMeek, ProtocolSSH},
		DialTimeout:      30 * time.Second,
		HandshakeTimeout: 60 * time.Second,
		Keepalive:        30 * time.Second,
		ClientID:         generateClientID(),
	}
}

// generateClientID generates a random client ID
func generateClientID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Psiphon represents a Psiphon client connection
type Psiphon struct {
	config     *Config
	server     *ServerEntry
	protocol   ProtocolType

	// Connection
	conn     net.Conn
	sshConn  *ssh.Client
	mu       sync.RWMutex

	// State
	closed   atomic.Bool
	closeCh  chan struct{}

	// Metrics
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
}

// Dial connects to a Psiphon server using best available protocol
func Dial(ctx context.Context, config *Config) (*Psiphon, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Fetch servers if discovery URL is set
	var servers []ServerEntry
	if config.DiscoveryURL != "" {
		var err error
		servers, err = discoverServers(ctx, config.DiscoveryURL, config.ClientID)
		if err != nil {
			servers = config.Servers
		}
	} else {
		servers = config.Servers
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers available")
	}

	// Try each protocol in order
	for _, protocol := range config.Protocols {
		for _, server := range servers {
			if server.Protocol != protocol && server.Protocol != "" {
				continue
			}

			p, err := tryConnect(ctx, config, &server, protocol)
			if err == nil {
				return p, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to connect with any protocol")
}

// discoverServers fetches server list from discovery service
func discoverServers(ctx context.Context, discoveryURL, clientID string) ([]ServerEntry, error) {
	u, err := url.Parse(discoveryURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("client_id", clientID)
	q.Set("client_region", "US") // Should be detected
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery failed: %s", resp.Status)
	}

	// Decode server list (may be base64 encoded)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Try base64 decode
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		decoded = body
	}

	var servers []ServerEntry
	if err := json.Unmarshal(decoded, &servers); err != nil {
		return nil, err
	}

	return servers, nil
}

// tryConnect attempts to connect with a specific protocol
func tryConnect(ctx context.Context, config *Config, server *ServerEntry, protocol ProtocolType) (*Psiphon, error) {
	switch protocol {
	case ProtocolOSSH:
		return connectOSSH(ctx, config, server)
	case ProtocolSSH:
		return connectSSH(ctx, config, server)
	case ProtocolMeek, ProtocolMeekHTTPS:
		return connectMeek(ctx, config, server)
	case ProtocolTLS:
		return connectTLS(ctx, config, server)
	case ProtocolObfs4:
		return connectObfs4(ctx, config, server)
	case ProtocolScrambleSuit:
		return connectScrambleSuit(ctx, config, server)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// connectOSSH connects using Obfuscated SSH
func connectOSSH(ctx context.Context, config *Config, server *ServerEntry) (*Psiphon, error) {
	addr := net.JoinHostPort(server.IPAddress, fmt.Sprintf("%d", server.Port))

	// Connect to server
	conn, err := net.DialTimeout("tcp", addr, config.DialTimeout)
	if err != nil {
		return nil, err
	}

	// Create OSSH obfuscation layer
	obfConn, err := newOSSHObfuscator(conn, server.SSHObfuscatedKey)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Perform SSH handshake
	sshConfig := &ssh.ClientConfig{
		User: server.SSHUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(server.SSHPassword),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// Verify host key
			expectedKey, err := base64.StdEncoding.DecodeString(server.SSHHostKey)
			if err != nil {
				return err
			}
			if !strings.Contains(string(expectedKey), string(key.Marshal())) {
				return fmt.Errorf("host key mismatch")
			}
			return nil
		},
		Timeout: config.HandshakeTimeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(obfConn, addr, sshConfig)
	if err != nil {
		obfConn.Close()
		return nil, err
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	p := &Psiphon{
		config:   config,
		server:   server,
		protocol: ProtocolOSSH,
		conn:     obfConn,
		sshConn:  client,
		closeCh:  make(chan struct{}),
	}

	// Start keepalive
	go p.keepaliveLoop()

	return p, nil
}

// connectSSH connects using plain SSH
func connectSSH(ctx context.Context, config *Config, server *ServerEntry) (*Psiphon, error) {
	addr := net.JoinHostPort(server.IPAddress, fmt.Sprintf("%d", server.Port))

	conn, err := net.DialTimeout("tcp", addr, config.DialTimeout)
	if err != nil {
		return nil, err
	}

	sshConfig := &ssh.ClientConfig{
		User: server.SSHUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(server.SSHPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Should verify in production
		Timeout:         config.HandshakeTimeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	p := &Psiphon{
		config:   config,
		server:   server,
		protocol: ProtocolSSH,
		conn:     conn,
		sshConn:  client,
		closeCh:  make(chan struct{}),
	}

	go p.keepaliveLoop()

	return p, nil
}

// connectMeek connects using meek (CDN tunneling)
func connectMeek(ctx context.Context, config *Config, server *ServerEntry) (*Psiphon, error) {
	// Build meek configuration
	meekConfig := &MeekConfig{
		FrontingDomain: server.MeekFrontingDomain,
		FrontingHosts:  server.MeekFrontingHosts,
		Path:           "/",
		MaxBodySize:    65536,
		PollInterval:   100 * time.Millisecond,
		DisableSNI:     server.TLSDisableSNI,
	}

	// Construct server URL
	scheme := "https"
	if server.Protocol == ProtocolMeek {
		scheme = "http"
	}
	serverURL := fmt.Sprintf("%s://%s:%d", scheme, server.IPAddress, server.Port)

	// Create underlying TCP connection
	tcpConn, err := net.DialTimeout("tcp", net.JoinHostPort(server.IPAddress, fmt.Sprintf("%d", server.Port)), config.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	// Wrap with TLS if using meek_https
	var conn net.Conn = tcpConn
	if server.Protocol == ProtocolMeekHTTPS {
		tlsConfig := config.TLSConfig.Clone()
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}

		if server.TLSServerName != "" {
			tlsConfig.ServerName = server.TLSServerName
		}

		if server.TLSDisableSNI {
			tlsConfig.ServerName = ""
		}

		conn = tls.Client(tcpConn, tlsConfig)
		if err := conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}
	}

	// Wrap with meek
	meekConn, err := DialMeek(serverURL, meekConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("meek dial failed: %w", err)
	}

	// Perform SSH handshake over meek
	sshConfig := &ssh.ClientConfig{
		User: server.SSHUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(server.SSHPassword),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			expectedKey, err := base64.StdEncoding.DecodeString(server.SSHHostKey)
			if err != nil {
				return err
			}
			if !strings.Contains(string(expectedKey), string(key.Marshal())) {
				return fmt.Errorf("host key mismatch")
			}
			return nil
		},
		Timeout: config.HandshakeTimeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(meekConn, serverURL, sshConfig)
	if err != nil {
		meekConn.Close()
		return nil, fmt.Errorf("ssh handshake failed: %w", err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	p := &Psiphon{
		config:   config,
		server:   server,
		protocol: server.Protocol,
		conn:     meekConn,
		sshConn:  client,
		closeCh:  make(chan struct{}),
	}

	go p.keepaliveLoop()
	return p, nil
}

// connectTLS connects using TLS parrot
func connectTLS(ctx context.Context, config *Config, server *ServerEntry) (*Psiphon, error) {
	addr := net.JoinHostPort(server.IPAddress, fmt.Sprintf("%d", server.Port))

	tlsConfig := config.TLSConfig.Clone()
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	if server.TLSServerName != "" {
		tlsConfig.ServerName = server.TLSServerName
	}

	if server.TLSDisableSNI {
		tlsConfig.ServerName = ""
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}

	p := &Psiphon{
		config:   config,
		server:   server,
		protocol: ProtocolTLS,
		conn:     conn,
		closeCh:  make(chan struct{}),
	}

	return p, nil
}

// keepaliveLoop sends periodic SSH keepalives
func (p *Psiphon) keepaliveLoop() {
	ticker := time.NewTicker(p.config.Keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			if p.sshConn != nil {
				_, _, err := p.sshConn.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					p.Close()
					return
				}
			}
		}
	}
}

// OpenStream opens a new stream through the SSH connection
func (p *Psiphon) OpenStream() (net.Conn, error) {
	p.mu.RLock()
	sshConn := p.sshConn
	p.mu.RUnlock()

	if sshConn == nil {
		return nil, fmt.Errorf("no SSH connection")
	}

	return sshConn.Dial("tcp", "0.0.0.0:0") // Dynamic forwarding
}

// Close closes the Psiphon connection
func (p *Psiphon) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(p.closeCh)

	p.mu.Lock()
	if p.sshConn != nil {
		p.sshConn.Close()
	}
	if p.conn != nil {
		p.conn.Close()
	}
	p.mu.Unlock()

	return nil
}

// GetStats returns connection statistics
func (p *Psiphon) GetStats() PsiphonStats {
	return PsiphonStats{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
		Protocol: string(p.protocol),
		Server:   p.server.IPAddress,
	}
}

// PsiphonStats contains connection statistics
type PsiphonStats struct {
	BytesIn  uint64
	BytesOut uint64
	Protocol string
	Server   string
}

// OSSHOConnection wraps a connection with SSH obfuscation
type OSSHOConnection struct {
	net.Conn
	cipher cipher.Stream
}

// newOSSHObfuscator creates a new OSSH obfuscation layer
func newOSSHObfuscator(conn net.Conn, key string) (*OSSHOConnection, error) {
	// Derive key from string
	hash := sha256.Sum256([]byte(key))

	// Create AES-CTR cipher
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}

	// Use random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Send IV
	if _, err := conn.Write(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)

	return &OSSHOConnection{
		Conn:   conn,
		cipher: stream,
	}, nil
}

func (c *OSSHOConnection) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if n > 0 {
		c.cipher.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (c *OSSHOConnection) Write(p []byte) (n int, err error) {
	// Encrypt in place
	c.cipher.XORKeyStream(p, p)
	return c.Conn.Write(p)
}

// connectObfs4 connects using obfs4 protocol
func connectObfs4(ctx context.Context, config *Config, server *ServerEntry) (*Psiphon, error) {
	addr := net.JoinHostPort(server.IPAddress, fmt.Sprintf("%d", server.Port))

	// Connect to server
	conn, err := net.DialTimeout("tcp", addr, config.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	// Generate or use provided obfs4 keys
	obfs4Config, err := GenerateObfs4Keys()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate obfs4 keys: %w", err)
	}

	// Wrap with obfs4
	obfs4Conn, err := DialObfs4(conn, obfs4Config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("obfs4 handshake failed: %w", err)
	}

	// Perform SSH handshake over obfs4
	sshConfig := &ssh.ClientConfig{
		User: server.SSHUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(server.SSHPassword),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			expectedKey, err := base64.StdEncoding.DecodeString(server.SSHHostKey)
			if err != nil {
				return err
			}
			if !strings.Contains(string(expectedKey), string(key.Marshal())) {
				return fmt.Errorf("host key mismatch")
			}
			return nil
		},
		Timeout: config.HandshakeTimeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(obfs4Conn, addr, sshConfig)
	if err != nil {
		obfs4Conn.Close()
		return nil, fmt.Errorf("ssh handshake failed: %w", err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	p := &Psiphon{
		config:   config,
		server:   server,
		protocol: ProtocolObfs4,
		conn:     obfs4Conn,
		sshConn:  client,
		closeCh:  make(chan struct{}),
	}

	go p.keepaliveLoop()
	return p, nil
}

// connectScrambleSuit connects using ScrambleSuit protocol
func connectScrambleSuit(ctx context.Context, config *Config, server *ServerEntry) (*Psiphon, error) {
	addr := net.JoinHostPort(server.IPAddress, fmt.Sprintf("%d", server.Port))

	// Connect to server
	conn, err := net.DialTimeout("tcp", addr, config.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	// Create ScrambleSuit config using OSSH key as password
	scConfig := &ScrambleSuitConfig{
		Password:   server.SSHObfuscatedKey,
		MaxPadding: 1399,
		IATMode:    0,
	}

	// Wrap with ScrambleSuit
	ssConn, err := DialScrambleSuit(conn, scConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("scramblesuit handshake failed: %w", err)
	}

	// Perform SSH handshake over ScrambleSuit
	sshConfig := &ssh.ClientConfig{
		User: server.SSHUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(server.SSHPassword),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			expectedKey, err := base64.StdEncoding.DecodeString(server.SSHHostKey)
			if err != nil {
				return err
			}
			if !strings.Contains(string(expectedKey), string(key.Marshal())) {
				return fmt.Errorf("host key mismatch")
			}
			return nil
		},
		Timeout: config.HandshakeTimeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(ssConn, addr, sshConfig)
	if err != nil {
		ssConn.Close()
		return nil, fmt.Errorf("ssh handshake failed: %w", err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	p := &Psiphon{
		config:   config,
		server:   server,
		protocol: ProtocolScrambleSuit,
		conn:     ssConn,
		sshConn:  client,
		closeCh:  make(chan struct{}),
	}

	go p.keepaliveLoop()
	return p, nil
}

// Dialer implements Psiphon dialer
type Dialer struct {
	config *Config
	smux   *smux.Config
}

// NewDialer creates a new Psiphon dialer
func NewDialer(config *Config, smuxCfg *smux.Config) *Dialer {
	return &Dialer{
		config: config,
		smux:   smuxCfg,
	}
}

// Dial connects to a Psiphon server
func (d *Dialer) Dial(ctx context.Context) (*smux.Session, error) {
	psiphon, err := Dial(ctx, d.config)
	if err != nil {
		return nil, err
	}

	// Create stream for smux
	stream, err := psiphon.OpenStream()
	if err != nil {
		psiphon.Close()
		return nil, err
	}

	return smux.Client(stream, d.smux)
}
