package carrier

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stealthlink/internal/tlsutil"

	"github.com/xtaci/smux"
	"golang.org/x/crypto/ssh"
)

// ChiselCarrier implements a Chisel-style SSH-over-HTTP carrier for UQSP.
// It tunnels SSH over HTTP CONNECT, then runs UQSP over the SSH channel.
type ChiselCarrier struct {
	config    ChiselConfig
	smuxCfg   *smux.Config
	sshConfig *ssh.ClientConfig
}

// ChiselConfig configures the Chisel carrier.
type ChiselConfig struct {
	// Server is the Chisel server address (host:port)
	Server string

	// Path is the HTTP path (usually "/")
	Path string

	// Auth is the authentication string (user:pass)
	Auth string

	// Fingerprint is the expected SSH server fingerprint
	Fingerprint string

	// Headers are additional HTTP headers
	Headers map[string]string

	// UserAgent for HTTP requests
	UserAgent string

	// TLS config
	TLSInsecureSkipVerify bool
	TLSServerName         string
	TLSFingerprint        string
	KeepAliveInterval     time.Duration
}

// NewChiselCarrier creates a new Chisel carrier.
func NewChiselCarrier(cfg ChiselConfig, smuxCfg *smux.Config) *ChiselCarrier {
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	if cfg.KeepAliveInterval <= 0 {
		cfg.KeepAliveInterval = 15 * time.Second
	}

	// Setup SSH client config
	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if strings.TrimSpace(cfg.Fingerprint) != "" {
		expected := strings.TrimSpace(cfg.Fingerprint)
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != expected {
				return fmt.Errorf("host key fingerprint mismatch")
			}
			return nil
		}
	}
	sshConfig := &ssh.ClientConfig{
		User: "chisel",
		Auth: []ssh.AuthMethod{
			ssh.Password(cfg.Auth),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	return &ChiselCarrier{
		config:    cfg,
		smuxCfg:   smuxCfg,
		sshConfig: sshConfig,
	}
}

// Dial connects to the Chisel server.
func (c *ChiselCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	// Step 1: Establish HTTP CONNECT tunnel
	tunnelConn, err := c.establishConnectTunnel(ctx)
	if err != nil {
		return nil, fmt.Errorf("establish connect tunnel: %w", err)
	}

	// Step 2: Perform SSH handshake over the tunnel
	sshConn, chans, reqs, err := ssh.NewClientConn(tunnelConn, c.config.Server, c.sshConfig)
	if err != nil {
		tunnelConn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	// Discard global requests
	go ssh.DiscardRequests(reqs)
	go keepaliveSSH(sshConn, c.config.KeepAliveInterval)

	// Reject incoming channel requests (we only open outbound channels)
	go func() {
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "channels not supported")
		}
	}()

	// Open a session channel for data transport
	channel, channelReqs, err := sshConn.OpenChannel("session", nil)
	if err != nil {
		sshConn.Close()
		return nil, fmt.Errorf("open ssh channel: %w", err)
	}

	// Discard channel-level requests
	go ssh.DiscardRequests(channelReqs)

	return &ChiselConn{
		channel: channel,
		local:   tunnelConn.LocalAddr(),
		remote:  tunnelConn.RemoteAddr(),
	}, nil
}

// establishConnectTunnel establishes an HTTP CONNECT tunnel.
func (c *ChiselCarrier) establishConnectTunnel(ctx context.Context) (net.Conn, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.config.TLSInsecureSkipVerify,
		ServerName:         c.config.TLSServerName,
	}

	conn, err := dialCarrierTLS(ctx, "tcp", c.config.Server, tlsConfig, c.config.TLSFingerprint)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}

	// Build CONNECT request
	hostHeader := c.config.Server
	connectTarget := c.config.Server
	if frontOpts, ok := tlsutil.FrontDialOptionsFromContext(ctx); ok && frontOpts.Enabled {
		if frontOpts.RealHost != "" {
			hostHeader = frontOpts.RealHost
		}
		if frontOpts.ConnectIP != "" {
			_, port, splitErr := net.SplitHostPort(c.config.Server)
			if splitErr == nil && port != "" {
				connectTarget = net.JoinHostPort(frontOpts.ConnectIP, port)
			}
		}
	}
	connectReq := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n",
		connectTarget,
		hostHeader,
		c.config.UserAgent,
	)
	if frontOpts, ok := tlsutil.FrontDialOptionsFromContext(ctx); ok && frontOpts.Enabled && frontOpts.CFWorker != "" {
		connectReq += fmt.Sprintf("CF-Worker: %s\r\n", frontOpts.CFWorker)
	}

	// Add authentication if provided
	if c.config.Auth != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.config.Auth))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}

	// Add custom headers
	for k, v := range c.config.Headers {
		connectReq += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	connectReq += "\r\n"

	// Send CONNECT request
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write connect request: %w", err)
	}

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read connect response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("connect failed: %s", resp.Status)
	}

	return conn, nil
}

// Network returns the network type.
func (c *ChiselCarrier) Network() string {
	return "tcp"
}

// Listen is not supported for Chisel (client-only in this implementation).
func (c *ChiselCarrier) Listen(addr string) (Listener, error) {
	return nil, fmt.Errorf("chisel carrier does not support listening (client-only)")
}

// Close closes the carrier.
func (c *ChiselCarrier) Close() error {
	return nil
}

// IsAvailable returns true if Chisel is available.
func (c *ChiselCarrier) IsAvailable() bool {
	return true
}

// Name returns the carrier name.
func (c *ChiselCarrier) Name() string {
	return "chisel"
}

// ChiselServer implements a Chisel server.
type ChiselServer struct {
	listener  net.Listener
	sshConfig *ssh.ServerConfig
	users     map[string]string // username -> password
}

// NewChiselServer creates a new Chisel server.
func NewChiselServer(addr string, tlsConfig *tls.Config) (*ChiselServer, error) {
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}

	server := &ChiselServer{
		listener: ln,
		users:    make(map[string]string),
	}

	// Setup SSH server config
	server.sshConfig = &ssh.ServerConfig{
		PasswordCallback: server.authenticate,
	}

	// Generate host key
	hostKey, err := generateSSHHostKey()
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	server.sshConfig.AddHostKey(hostKey)

	// Start accepting connections
	go server.serve()

	return server, nil
}

// AddUser adds a user to the server.
func (s *ChiselServer) AddUser(username, password string) {
	s.users[username] = password
}

// authenticate authenticates a user.
func (s *ChiselServer) authenticate(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	user := conn.User()
	expectedPass, ok := s.users[user]
	if !ok {
		return nil, fmt.Errorf("unknown user: %s", user)
	}
	exp := []byte(expectedPass)
	if len(password) != len(exp) || subtle.ConstantTimeCompare(password, exp) != 1 {
		return nil, fmt.Errorf("invalid password")
	}
	return nil, nil
}

// serve accepts and handles connections.
func (s *ChiselServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			continue
		}
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single connection.
func (s *ChiselServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read HTTP CONNECT request
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method != "CONNECT" {
		http.Error(&chiselResponseWriter{conn}, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Send 200 OK
	fmt.Fprintf(conn, "HTTP/1.1 200 Connection established\r\n\r\n")

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		return
	}
	defer sshConn.Close()

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for ch := range chans {
		go s.handleChannel(ch)
	}
}

// handleChannel handles an SSH channel.
func (s *ChiselServer) handleChannel(ch ssh.NewChannel) {
	// Accept the channel
	channel, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	// Discard requests
	go ssh.DiscardRequests(reqs)

	// In a real implementation, we'd forward to a target
	// For now, just echo back
	buf := make([]byte, 1024)
	for {
		n, err := channel.Read(buf)
		if err != nil {
			return
		}
		if _, err := channel.Write(buf[:n]); err != nil {
			return
		}
	}
}

// chiselResponseWriter implements http.ResponseWriter.
type chiselResponseWriter struct {
	conn net.Conn
}

func (w *chiselResponseWriter) Header() http.Header {
	return http.Header{}
}

func (w *chiselResponseWriter) Write(b []byte) (int, error) {
	return w.conn.Write(b)
}

func (w *chiselResponseWriter) WriteHeader(code int) {
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n\r\n", code, http.StatusText(code))
}

// generateSSHHostKey generates an SSH host key using ECDSA P-256.
func generateSSHHostKey() (ssh.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("create ssh signer: %w", err)
	}
	return signer, nil
}

func keepaliveSSH(conn ssh.Conn, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		if conn == nil {
			return
		}
		if _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			return
		}
	}
}

// ChiselConn wraps an SSH channel as a net.Conn.
type ChiselConn struct {
	channel ssh.Channel
	local   net.Addr
	remote  net.Addr
}

// Read reads from the channel.
func (c *ChiselConn) Read(b []byte) (int, error) {
	return c.channel.Read(b)
}

// Write writes to the channel.
func (c *ChiselConn) Write(b []byte) (int, error) {
	return c.channel.Write(b)
}

// Close closes the channel.
func (c *ChiselConn) Close() error {
	return c.channel.Close()
}

// LocalAddr returns the local address.
func (c *ChiselConn) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr returns the remote address.
func (c *ChiselConn) RemoteAddr() net.Addr {
	return c.remote
}

// SetDeadline sets the deadline.
func (c *ChiselConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *ChiselConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *ChiselConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// extractTarget extracts the target address from an HTTP request.
func extractTarget(req *http.Request) string {
	// Check X-Forwarded-For header
	target := req.Header.Get("X-Target")
	if target != "" {
		return target
	}

	// Use the Host header
	return req.Host
}

// parseAuth parses the Authorization header.
func parseAuth(auth string) (username, password string, err error) {
	if auth == "" {
		return "", "", fmt.Errorf("no authorization")
	}

	const prefix = "Basic "
	if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
		return "", "", fmt.Errorf("invalid authorization type")
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", err
	}

	parts := split(string(decoded), ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid authorization format")
	}

	return parts[0], parts[1], nil
}

// split splits a string by a separator.
func split(s, sep string) []string {
	var result []string
	for {
		idx := 0
		for i := 0; i < len(s); i++ {
			if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
				idx = i
				break
			}
			idx = len(s)
		}
		if idx >= len(s) {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	return result
}

// ChiselClient is a simplified Chisel client.
type ChiselClient struct {
	config ChiselConfig
}

// NewChiselClient creates a new Chisel client.
func NewChiselClient(config ChiselConfig) *ChiselClient {
	return &ChiselClient{config: config}
}

// Connect connects to the Chisel server and returns a tunnel.
func (c *ChiselClient) Connect(ctx context.Context) (net.Conn, error) {
	carrier := NewChiselCarrier(c.config, nil)
	return carrier.Dial(ctx, c.config.Server)
}

// ChiselProxyURL returns the proxy URL for Chisel.
func ChiselProxyURL(server string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   server,
		Path:   "/",
	}
}
