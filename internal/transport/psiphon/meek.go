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
	"hash/fnv"
	"io"
	"math"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MeekConfig configures the meek protocol
// Meek uses HTTP to tunnel through CDNs by encoding data in HTTP request/response bodies
type MeekFrontPair struct {
	Host string
	Path string
}

type MeekConfig struct {
	// CDN fronting domain (the actual domain being contacted)
	FrontingDomain string

	// Fronting hosts (additional Host headers to try)
	FrontingHosts []string

	// FrontPairs is an ordered list of (host,path) candidates.
	// If FrontingDomain is set, host values are applied as Host headers while
	// the TCP/TLS dial target remains FrontingDomain.
	FrontPairs []MeekFrontPair

	// PathCandidates are additional request paths used when FrontPairs is empty.
	PathCandidates []string

	// URL path for meek requests
	Path string

	// Maximum body size for requests
	MaxBodySize int

	// Polling interval
	PollInterval time.Duration

	// Failover/backoff tuning for fronting hosts+paths.
	FailureBaseBackoff  time.Duration
	FailureMaxBackoff   time.Duration
	MaxFailoverAttempts int

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
		Path:               "/",
		MaxBodySize:        65536,
		PollInterval:       100 * time.Millisecond,
		FailureBaseBackoff: 500 * time.Millisecond,
		FailureMaxBackoff:  30 * time.Second,
		SessionID:          generateSessionID(),
	}
}

func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func seedFromSession(sessionID string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(sessionID))
	return int64(h.Sum64())
}

func normalizeMeekPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func buildMeekTargets(serverURL *url.URL, config *MeekConfig) []meekTarget {
	if config == nil {
		config = DefaultMeekConfig()
	}

	seen := make(map[string]struct{})
	add := func(t meekTarget, out []meekTarget) []meekTarget {
		t.dialHost = strings.TrimSpace(t.dialHost)
		t.hostHeader = strings.TrimSpace(t.hostHeader)
		if t.hostHeader == "" {
			t.hostHeader = t.dialHost
		}
		t.path = normalizeMeekPath(t.path)
		if t.dialHost == "" {
			return out
		}
		key := t.dialHost + "|" + t.hostHeader + "|" + t.path
		if _, ok := seen[key]; ok {
			return out
		}
		seen[key] = struct{}{}
		return append(out, t)
	}

	var targets []meekTarget
	if len(config.FrontPairs) > 0 {
		for _, pair := range config.FrontPairs {
			host := strings.TrimSpace(pair.Host)
			if host == "" {
				continue
			}
			path := pair.Path
			if strings.TrimSpace(path) == "" {
				path = config.Path
			}
			if strings.TrimSpace(path) == "" && serverURL != nil {
				path = serverURL.Path
			}

			dialHost := host
			hostHeader := host
			if strings.TrimSpace(config.FrontingDomain) != "" {
				dialHost = strings.TrimSpace(config.FrontingDomain)
				hostHeader = host
			}
			targets = add(meekTarget{
				dialHost:   dialHost,
				hostHeader: hostHeader,
				path:       path,
			}, targets)
		}
		return targets
	}

	dialHost := strings.TrimSpace(config.FrontingDomain)
	if dialHost == "" && serverURL != nil {
		dialHost = strings.TrimSpace(serverURL.Host)
	}

	paths := make([]string, 0, 1+len(config.PathCandidates))
	if p := strings.TrimSpace(config.Path); p != "" {
		paths = append(paths, p)
	}
	for _, p := range config.PathCandidates {
		if strings.TrimSpace(p) != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 && serverURL != nil && strings.TrimSpace(serverURL.Path) != "" {
		paths = append(paths, serverURL.Path)
	}
	if len(paths) == 0 {
		paths = append(paths, "/")
	}

	hostHeaders := make([]string, 0, 1+len(config.FrontingHosts))
	for _, h := range config.FrontingHosts {
		h = strings.TrimSpace(h)
		if h != "" {
			hostHeaders = append(hostHeaders, h)
		}
	}
	if len(hostHeaders) == 0 {
		hostHeaders = append(hostHeaders, dialHost)
	}

	for _, h := range hostHeaders {
		for _, p := range paths {
			targets = add(meekTarget{
				dialHost:   dialHost,
				hostHeader: h,
				path:       p,
			}, targets)
		}
	}

	return targets
}

// MeekConn represents a meek connection
type MeekConn struct {
	config     *MeekConfig
	httpClient *http.Client
	scheme     string

	// Session state
	sessionID   string
	serverToken string
	closed      atomic.Bool

	targetMu     sync.Mutex
	targets      []meekTarget
	targetState  []meekTargetState
	targetCursor atomic.Uint32
	randMu       sync.Mutex
	rng          *mathrand.Rand

	// Data channels
	writeCh chan []byte
	readBuf []byte
	readMu  sync.Mutex
	writeMu sync.Mutex

	// Background goroutine
	pollStopCh chan struct{}
	pollWg     sync.WaitGroup

	// Metrics
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
}

type meekTarget struct {
	dialHost   string
	hostHeader string
	path       string
}

type meekTargetState struct {
	failures     int
	successes    int
	cooldownEnd  time.Time
	avgLatencyMs float64
	lastSuccess  time.Time
	healthScore  float64
}

func (s *meekTargetState) computeHealthScore() float64 {
	total := s.successes + s.failures
	var ratioScore float64
	if total > 0 {
		ratioScore = float64(s.successes) / float64(total) * 100
	}

	var latencyScore float64
	if s.avgLatencyMs > 0 {
		latencyScore = 100.0 / (1.0 + s.avgLatencyMs/500.0)
	} else {
		latencyScore = 50
	}

	var recencyScore float64
	if !s.lastSuccess.IsZero() {
		age := time.Since(s.lastSuccess).Seconds()
		recencyScore = 100.0 / (1.0 + age/60.0)
	}

	score := ratioScore*0.4 + latencyScore*0.3 + recencyScore*0.3
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
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

	targets := buildMeekTargets(u, config)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no meek fronting targets available")
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

	initialState := make([]meekTargetState, len(targets))
	now := time.Now()
	for i := range initialState {
		initialState[i] = meekTargetState{
			healthScore: 50,
			lastSuccess: now,
		}
	}

	conn := &MeekConn{
		config:      config,
		httpClient:  httpClient,
		scheme:      u.Scheme,
		sessionID:   config.SessionID,
		writeCh:     make(chan []byte, 32),
		pollStopCh:  make(chan struct{}),
		targets:     targets,
		targetState: initialState,
		rng:         mathrand.New(mathrand.NewSource(seedFromSession(config.SessionID))),
	}

	// Perform initial handshake
	if err := conn.handshake(); err != nil {
		return nil, fmt.Errorf("meek handshake failed: %w", err)
	}

	// Start polling goroutine
	conn.pollWg.Add(1)
	go conn.pollLoop()

	return conn, nil
}

// handshake performs the initial meek handshake
func (c *MeekConn) handshake() error {
	resp, err := c.doRequestWithFailover(http.MethodPost, nil, func(req *http.Request) {
		req.Header.Set("X-Session-Id", c.sessionID)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Accept", "application/octet-stream")
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read server token if provided
	c.serverToken = resp.Header.Get("X-Server-Token")
	return nil
}

// pollLoop continuously polls for data from the server
func (c *MeekConn) pollLoop() {
	defer c.pollWg.Done()

	ticker := time.NewTicker(c.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.pollStopCh:
			return
		case <-ticker.C:
			c.poll()
		}
	}
}

// poll performs a single poll operation
func (c *MeekConn) poll() {
	resp, err := c.doRequestWithFailover(http.MethodGet, nil, func(req *http.Request) {
		req.Header.Set("X-Session-Id", c.sessionID)
		if c.serverToken != "" {
			req.Header.Set("X-Server-Token", c.serverToken)
		}
	})
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

func (c *MeekConn) orderedTargetIndexes() []int {
	c.targetMu.Lock()
	defer c.targetMu.Unlock()

	n := len(c.targets)
	if n == 0 {
		return nil
	}
	now := time.Now()

	ready := make([]int, 0, n)
	cooling := make([]int, 0, n)
	for i := 0; i < n; i++ {
		st := c.targetState[i]
		if st.cooldownEnd.IsZero() || !now.Before(st.cooldownEnd) {
			ready = append(ready, i)
		} else {
			cooling = append(cooling, i)
		}
	}

	if len(ready) > 0 {
		sort.SliceStable(ready, func(i, j int) bool {
			return c.targetState[ready[i]].healthScore > c.targetState[ready[j]].healthScore
		})
		if len(ready) > 1 {
			topScore := c.targetState[ready[0]].healthScore
			group := 1
			for group < len(ready) && c.targetState[ready[group]].healthScore == topScore {
				group++
			}
			if group > 1 {
				offset := int(c.targetCursor.Add(1)-1) % group
				head := append([]int(nil), ready[:group]...)
				head = append(head[offset:], head[:offset]...)
				ready = append(head, ready[group:]...)
			}
		}
		return append([]int(nil), ready...)
	}

	sort.SliceStable(cooling, func(i, j int) bool {
		a := c.targetState[cooling[i]].cooldownEnd
		b := c.targetState[cooling[j]].cooldownEnd
		if a.Equal(b) {
			return c.targetState[cooling[i]].healthScore > c.targetState[cooling[j]].healthScore
		}
		return a.Before(b)
	})
	return append([]int(nil), cooling...)
}

func (c *MeekConn) markTargetResult(idx int, ok bool) {
	c.markTargetResultWithLatency(idx, ok, 0)
}

func (c *MeekConn) jitterFrac(max float64) float64 {
	if max <= 0 {
		return 0
	}
	c.randMu.Lock()
	defer c.randMu.Unlock()
	if c.rng == nil {
		return 0
	}
	return c.rng.Float64() * max
}

func (c *MeekConn) markTargetResultWithLatency(idx int, ok bool, latencyMs float64) {
	c.targetMu.Lock()
	defer c.targetMu.Unlock()

	if idx < 0 || idx >= len(c.targetState) {
		return
	}
	st := &c.targetState[idx]
	if ok {
		st.successes++
		st.cooldownEnd = time.Time{}
		if latencyMs > 0 {
			const alpha = 0.3
			if st.avgLatencyMs <= 0 {
				st.avgLatencyMs = latencyMs
			} else {
				st.avgLatencyMs = alpha*latencyMs + (1-alpha)*st.avgLatencyMs
			}
		}
		st.lastSuccess = time.Now()
		st.healthScore = st.computeHealthScore()
		return
	}
	st.failures++
	base := c.config.FailureBaseBackoff
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	maxBackoff := c.config.FailureMaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 30 * time.Second
	}
	backoff := time.Duration(float64(base) * math.Pow(2, float64(st.failures-1)))
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	// Add bounded deterministic jitter to avoid fixed, fingerprintable failover cadence.
	backoff += time.Duration(float64(backoff) * c.jitterFrac(0.2))
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	st.cooldownEnd = time.Now().Add(backoff)
	st.healthScore = st.computeHealthScore()
}

func (c *MeekConn) doRequestWithFailover(method string, payload []byte, configure func(*http.Request)) (*http.Response, error) {
	order := c.orderedTargetIndexes()
	if len(order) == 0 {
		return nil, fmt.Errorf("no meek targets configured")
	}

	limit := len(order)
	if c.config.MaxFailoverAttempts > 0 && c.config.MaxFailoverAttempts < limit {
		limit = c.config.MaxFailoverAttempts
	}

	var lastErr error
	for i := 0; i < limit; i++ {
		idx := order[i]
		target := c.targets[idx]

		u := url.URL{
			Scheme: c.scheme,
			Host:   target.dialHost,
			Path:   target.path,
		}

		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}

		req, err := http.NewRequest(method, u.String(), body)
		if err != nil {
			lastErr = err
			c.markTargetResult(idx, false)
			continue
		}
		if target.hostHeader != "" {
			req.Host = target.hostHeader
		}
		if configure != nil {
			configure(req)
		}

		reqStart := time.Now()
		resp, err := c.httpClient.Do(req)
		latencyMs := float64(time.Since(reqStart).Microseconds()) / 1000.0
		if err != nil {
			lastErr = err
			c.markTargetResult(idx, false)
			continue
		}
		if resp.StatusCode/100 != 2 {
			lastErr = fmt.Errorf("%s %s via %s/%s failed: %s", method, c.sessionID, target.hostHeader, target.path, resp.Status)
			resp.Body.Close()
			c.markTargetResult(idx, false)
			continue
		}

		c.markTargetResultWithLatency(idx, true, latencyMs)
		return resp, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("all meek targets exhausted")
	}
	return nil, lastErr
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

	resp, err := c.doRequestWithFailover(http.MethodPost, p, func(req *http.Request) {
		req.Header.Set("X-Session-Id", c.sessionID)
		req.Header.Set("Content-Type", "application/octet-stream")
		if c.serverToken != "" {
			req.Header.Set("X-Server-Token", c.serverToken)
		}
	})
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.doRequestWithFailover(http.MethodDelete, nil, func(req *http.Request) {
		req.Header.Set("X-Session-Id", c.sessionID)
		if c.serverToken != "" {
			req.Header.Set("X-Server-Token", c.serverToken)
		}
		*req = *req.WithContext(ctx)
	})

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
	sessions    map[string]*meekSession
	sessionMu   sync.RWMutex
	cookieKey   []byte
	path        string
	maxBodySize int
}

type meekSession struct {
	id         string
	dataCh     chan []byte
	createdAt  time.Time
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
