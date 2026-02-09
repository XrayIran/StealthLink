// Package psiphon implements Psiphon protocol support
package psiphon

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// MeekConfig configures the meek protocol
// Meek uses HTTP to tunnel through CDNs by encoding data in HTTP request/response bodies
type MeekConfig struct {
	// CDN fronting domain (the actual domain being contacted)
	FrontingDomain string

	// Fronting hosts (additional Host headers to try)
	FrontingHosts []string

	// URL path for meek requests
	Path string

	// Maximum body size for requests
	MaxBodySize int

	// Polling interval
	PollInterval time.Duration

	// Session ID (generated if empty)
	SessionID string

	// Encryption key for cookie-based sessions
	CookieEncryptionKey []byte

	// Disable SNI in TLS handshake
	DisableSNI bool

	// Alternative SNI to use
	FakeSNI string
}

// DefaultMeekConfig returns default meek configuration
func DefaultMeekConfig() *MeekConfig {
	return &MeekConfig{
		Path:         "/",
		MaxBodySize:  65536,
		PollInterval: 100 * time.Millisecond,
		SessionID:    generateSessionID(),
	}
}

func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// MeekConn represents a meek connection
type MeekConn struct {
	config     *MeekConfig
	httpClient *http.Client

	// Session state
	sessionID   string
	serverToken string
	closed      atomic.Bool

	// Data channels
	writeCh   chan []byte
	readBuf   []byte
	readMu    sync.Mutex
	writeMu   sync.Mutex

	// Background goroutine
	pollStopCh chan struct{}
	pollWg     sync.WaitGroup

	// Metrics
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
}

// DialMeek creates a new meek connection
func DialMeek(serverURL string, config *MeekConfig) (*MeekConn, error) {
	if config == nil {
		config = DefaultMeekConfig()
	}

	// Parse server URL
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	// Use fronting domain if specified
	host := u.Host
	if config.FrontingDomain != "" {
		host = config.FrontingDomain
	}

	// Create HTTP client with custom transport
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	conn := &MeekConn{
		config:     config,
		httpClient: httpClient,
		sessionID:  config.SessionID,
		writeCh:    make(chan []byte, 32),
		pollStopCh: make(chan struct{}),
	}

	// Perform initial handshake
	if err := conn.handshake(host, u.Scheme); err != nil {
		return nil, fmt.Errorf("meek handshake failed: %w", err)
	}

	// Start polling goroutine
	conn.pollWg.Add(1)
	go conn.pollLoop(host, u.Scheme)

	return conn, nil
}

// handshake performs the initial meek handshake
func (c *MeekConn) handshake(host, scheme string) error {
	// Build handshake request
	u := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   c.config.Path,
	}

	// Send empty POST to establish session
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return err
	}

	// Set headers for CDN fronting
	req.Header.Set("X-Session-Id", c.sessionID)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/octet-stream")

	// Use fronting host if different from target
	if c.config.FrontingDomain != "" {
		req.Host = c.config.FrontingDomain
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("handshake failed: %s", resp.Status)
	}

	// Read server token if provided
	c.serverToken = resp.Header.Get("X-Server-Token")

	return nil
}

// pollLoop continuously polls for data from the server
func (c *MeekConn) pollLoop(host, scheme string) {
	defer c.pollWg.Done()

	ticker := time.NewTicker(c.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.pollStopCh:
			return
		case <-ticker.C:
			c.poll(host, scheme)
		}
	}
}

// poll performs a single poll operation
func (c *MeekConn) poll(host, scheme string) {
	u := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   c.config.Path,
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return
	}

	req.Header.Set("X-Session-Id", c.sessionID)
	if c.serverToken != "" {
		req.Header.Set("X-Server-Token", c.serverToken)
	}

	if c.config.FrontingDomain != "" {
		req.Host = c.config.FrontingDomain
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	// Read response body
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(c.config.MaxBodySize)))
	if err != nil || len(data) == 0 {
		return
	}

	// Store in read buffer
	c.readMu.Lock()
	c.readBuf = append(c.readBuf, data...)
	c.readMu.Unlock()

	c.bytesIn.Add(uint64(len(data)))
}

// Read reads data from the meek connection
func (c *MeekConn) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, fmt.Errorf("connection closed")
	}

	// Wait for data
	for {
		c.readMu.Lock()
		if len(c.readBuf) > 0 {
			n := copy(p, c.readBuf)
			c.readBuf = c.readBuf[n:]
			c.readMu.Unlock()
			return n, nil
		}
		c.readMu.Unlock()

		if c.closed.Load() {
			return 0, fmt.Errorf("connection closed")
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// Write writes data to the meek connection
func (c *MeekConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, fmt.Errorf("connection closed")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Build URL
	scheme := "https"
	host := c.config.FrontingDomain
	if host == "" {
		host = "localhost"
	}

	u := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   c.config.Path,
	}

	// Send data as POST body
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(p))
	if err != nil {
		return 0, err
	}

	req.Header.Set("X-Session-Id", c.sessionID)
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.serverToken != "" {
		req.Header.Set("X-Server-Token", c.serverToken)
	}

	if c.config.FrontingDomain != "" {
		req.Host = c.config.FrontingDomain
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("write failed: %s", resp.Status)
	}

	c.bytesOut.Add(uint64(len(p)))
	return len(p), nil
}

// Close closes the meek connection
func (c *MeekConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(c.pollStopCh)
	c.pollWg.Wait()

	// Send close notification
	scheme := "https"
	host := c.config.FrontingDomain
	if host == "" {
		host = "localhost"
	}

	u := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   c.config.Path,
	}

	req, _ := http.NewRequest("DELETE", u.String(), nil)
	req.Header.Set("X-Session-Id", c.sessionID)
	if c.serverToken != "" {
		req.Header.Set("X-Server-Token", c.serverToken)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req = req.WithContext(ctx)
	c.httpClient.Do(req)

	return nil
}

// LocalAddr returns the local address
func (c *MeekConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

// RemoteAddr returns the remote address
func (c *MeekConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 443}
}

// SetDeadline sets the deadline
func (c *MeekConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the read deadline
func (c *MeekConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline
func (c *MeekConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Ensure MeekConn implements net.Conn
var _ net.Conn = (*MeekConn)(nil)

// MeekCookieSession manages cookie-based session encryption
type MeekCookieSession struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	aesKey     []byte
}

// NewMeekCookieSession creates a new cookie session handler
func NewMeekCookieSession() (*MeekCookieSession, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Generate AES key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}

	return &MeekCookieSession{
		publicKey:  &privateKey.PublicKey,
		privateKey: privateKey,
		aesKey:     aesKey,
	}, nil
}

// EncryptSession encrypts session data for cookie
func (m *MeekCookieSession) EncryptSession(data []byte) (string, error) {
	// Generate nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(m.aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptSession decrypts session data from cookie
func (m *MeekCookieSession) DecryptSession(cookie string) ([]byte, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(cookie)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]

	block, err := aes.NewCipher(m.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// GetPublicKey returns the public key for server
func (m *MeekCookieSession) GetPublicKey() []byte {
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(m.publicKey)
	return pubKeyBytes
}

// MeekServer handles server-side meek connections
type MeekServer struct {
	sessions   map[string]*meekSession
	sessionMu  sync.RWMutex
	cookieKey  []byte
	path       string
	maxBodySize int
}

type meekSession struct {
	id        string
	dataCh    chan []byte
	createdAt time.Time
	lastActive time.Time
}

// NewMeekServer creates a new meek server
func NewMeekServer(cookieKey []byte) *MeekServer {
	if len(cookieKey) != 32 {
		cookieKey = make([]byte, 32)
		rand.Read(cookieKey)
	}

	return &MeekServer{
		sessions:    make(map[string]*meekSession),
		cookieKey:   cookieKey,
		path:        "/",
		maxBodySize: 65536,
	}
}

// ServeHTTP handles HTTP requests
func (s *MeekServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != s.path {
		http.NotFound(w, r)
		return
	}

	sessionID := r.Header.Get("X-Session-Id")
	if sessionID == "" {
		sessionID = r.URL.Query().Get("sid")
	}

	switch r.Method {
	case "POST":
		s.handlePost(w, r, sessionID)
	case "GET":
		s.handleGet(w, r, sessionID)
	case "DELETE":
		s.handleDelete(w, r, sessionID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePost handles POST requests (client sending data)
func (s *MeekServer) handlePost(w http.ResponseWriter, r *http.Request, sessionID string) {
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(s.maxBodySize)))
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	s.sessionMu.Lock()
	session, exists := s.sessions[sessionID]
	if !exists {
		session = &meekSession{
			id:         sessionID,
			dataCh:     make(chan []byte, 32),
			createdAt:  time.Now(),
			lastActive: time.Now(),
		}
		s.sessions[sessionID] = session
	}
	s.sessionMu.Unlock()

	// Send data to session channel
	select {
	case session.dataCh <- data:
		session.lastActive = time.Now()
	default:
	}

	w.WriteHeader(http.StatusOK)
}

// handleGet handles GET requests (client polling for data)
func (s *MeekServer) handleGet(w http.ResponseWriter, r *http.Request, sessionID string) {
	s.sessionMu.RLock()
	session, exists := s.sessions[sessionID]
	s.sessionMu.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Wait for data with timeout
	select {
	case data := <-session.dataCh:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
		session.lastActive = time.Now()
	case <-time.After(30 * time.Second):
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleDelete handles DELETE requests (client closing session)
func (s *MeekServer) handleDelete(w http.ResponseWriter, r *http.Request, sessionID string) {
	s.sessionMu.Lock()
	if session, exists := s.sessions[sessionID]; exists {
		close(session.dataCh)
		delete(s.sessions, sessionID)
	}
	s.sessionMu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// Cleanup removes expired sessions
func (s *MeekServer) Cleanup(maxAge time.Duration) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.Sub(session.lastActive) > maxAge {
			close(session.dataCh)
			delete(s.sessions, id)
		}
	}
}
