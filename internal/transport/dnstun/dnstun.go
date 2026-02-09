// Package dnstun implements DNS tunneling transport for StealthLink.
// It encapsulates traffic in DNS queries/responses to bypass TCP/UDP blocking.
package dnstun

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport"

	"github.com/miekg/dns"
	"github.com/xtaci/smux"
)

// Config configures DNS tunneling.
type Config struct {
	Domain       string        `yaml:"domain"`         // Base domain for tunneling
	ServerAddr   string        `yaml:"server_addr"`    // DNS server address
	QueryType    string        `yaml:"query_type"`     // TXT, NULL, CNAME, or A
	MaxUDPPacket int           `yaml:"max_udp_packet"` // Max packet size (default: 512)
	Timeout      time.Duration `yaml:"timeout"`        // Query timeout
	Retries      int           `yaml:"retries"`        // Query retries
	Encoder      string        `yaml:"encoder"`        // base32, base64, or hex
	CheckDomain  string        `yaml:"check_domain"`   // Domain for connectivity check
}

// ApplyDefaults sets default values for DNS tunnel configuration.
func (c *Config) ApplyDefaults() {
	if c.Domain == "" {
		c.Domain = "tunnel.example.com"
	}
	if c.MaxUDPPacket <= 0 {
		c.MaxUDPPacket = 512 // Traditional DNS UDP limit
	}
	if c.MaxUDPPacket > 4096 {
		c.MaxUDPPacket = 4096 // EDNS0 max
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Retries <= 0 {
		c.Retries = 3
	}
	if c.QueryType == "" {
		c.QueryType = "TXT"
	}
	if c.Encoder == "" {
		c.Encoder = "base32"
	}
}

// Dialer implements transport.Dialer for DNS tunnel.
type Dialer struct {
	config    *Config
	client    *dns.Client
	resolver  *net.Resolver
	smux      *smux.Config
	guard     string
	sessionID string
}

// NewDialer creates a new DNS tunnel dialer.
func NewDialer(cfg *Config, smuxCfg *smux.Config, guard string) (*Dialer, error) {
	cfg.ApplyDefaults()

	d := &Dialer{
		config:    cfg,
		smux:      smuxCfg,
		guard:     guard,
		sessionID: generateSessionID(),
	}

	// Configure DNS client
	d.client = &dns.Client{
		Net:            "udp",
		Timeout:        cfg.Timeout,
		ReadTimeout:    cfg.Timeout,
		WriteTimeout:   cfg.Timeout,
		SingleInflight: true,
	}

	return d, nil
}

// Dial connects to a DNS tunnel server.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	// Parse server address for nameserver
	serverAddr := d.config.ServerAddr
	if serverAddr == "" {
		// Use addr as nameserver
		serverAddr = addr
	}

	// Create DNS tunnel connection
	conn, err := d.createTunnelConn(ctx, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("create tunnel: %w", err)
	}

	// Send guard token
	if err := transport.SendGuard(conn, d.guard); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send guard: %w", err)
	}

	// Start smux over DNS tunnel
	sess, err := smux.Client(conn, d.smux)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create smux: %w", err)
	}

	return &dnsSession{
		conn: conn,
		sess: sess,
	}, nil
}

// createTunnelConn creates a virtual connection over DNS.
func (d *Dialer) createTunnelConn(ctx context.Context, serverAddr string) (*dnsConn, error) {
	conn := &dnsConn{
		config:    d.config,
		client:    d.client,
		server:    serverAddr,
		sessionID: d.sessionID,
		readCh:    make(chan []byte, 100),
		writeCh:   make(chan []byte, 100),
		closeCh:   make(chan struct{}),
		sendSeq:   0,
		recvSeq:   0,
	}

	// Start send/receive goroutines
	go conn.sendLoop(ctx)
	go conn.receiveLoop(ctx)

	return conn, nil
}

// dnsConn implements net.Conn over DNS queries/responses.
type dnsConn struct {
	config    *Config
	client    *dns.Client
	server    string
	sessionID string

	readCh  chan []byte
	writeCh chan []byte
	closeCh chan struct{}
	closed  atomic.Bool

	sendSeq uint32
	recvSeq uint32

	mu sync.RWMutex
}

// sendLoop sends data via DNS queries.
func (c *dnsConn) sendLoop(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closeCh:
			return
		case data := <-c.writeCh:
			if err := c.sendData(data); err != nil {
				if !c.closed.Load() {
					// Retry
					time.Sleep(time.Second)
					if err := c.sendData(data); err != nil {
						// Give up
						return
					}
				}
			}
		case <-ticker.C:
			// Send keepalive
			if err := c.sendKeepalive(); err != nil {
				// Continue anyway
			}
		}
	}
}

// sendData sends data chunk via DNS queries.
func (c *dnsConn) sendData(data []byte) error {
	chunks := c.chunkData(data)

	for i, chunk := range chunks {
		subdomain := c.encodeSubdomain(chunk, uint32(i), uint32(len(chunks)))

		queryType := c.queryType()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(subdomain+"."+c.config.Domain), queryType)
		m.RecursionDesired = true

		// Add EDNS0 for larger responses
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.SetUDPSize(uint16(c.config.MaxUDPPacket))
		m.Extra = append(m.Extra, opt)

		// Send query
		r, _, err := c.client.Exchange(m, c.server)
		if err != nil {
			return fmt.Errorf("DNS query failed: %w", err)
		}

		// Check response for acknowledgment
		if r != nil && r.Rcode == dns.RcodeSuccess {
			// Could check for specific response format
		}
	}

	return nil
}

// sendKeepalive sends a keepalive query.
func (c *dnsConn) sendKeepalive() error {
	subdomain := fmt.Sprintf("ka-%s-%d", c.sessionID, time.Now().Unix())

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(subdomain+"."+c.config.Domain), dns.TypeTXT)
	m.RecursionDesired = true

	_, _, err := c.client.Exchange(m, c.server)
	return err
}

// receiveLoop receives data via DNS responses.
func (c *dnsConn) receiveLoop(ctx context.Context) {
	// For client side, we poll for data using special queries
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closeCh:
			return
		case <-ticker.C:
			c.pollForData()
		}
	}
}

// pollForData sends a poll query to check for pending data.
func (c *dnsConn) pollForData() {
	subdomain := fmt.Sprintf("poll-%s-%d", c.sessionID, c.recvSeq)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(subdomain+"."+c.config.Domain), dns.TypeTXT)
	m.RecursionDesired = true

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.SetUDPSize(uint16(c.config.MaxUDPPacket))
	m.Extra = append(m.Extra, opt)

	r, _, err := c.client.Exchange(m, c.server)
	if err != nil {
		return
	}

	if r == nil || r.Rcode != dns.RcodeSuccess {
		return
	}

	// Parse response data
	for _, rr := range r.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			if len(txt.Txt) > 0 {
				data := c.decodeData(txt.Txt[0])
				select {
				case c.readCh <- data:
					c.recvSeq++
				default:
				}
			}
		}
	}
}

// chunkData splits data into DNS-compatible chunks.
func (c *dnsConn) chunkData(data []byte) [][]byte {
	// Account for encoding overhead
	// base32: 8 chars for 5 bytes
	maxChunkSize := (c.config.MaxUDPPacket - 100) * 5 / 8

	var chunks [][]byte
	for offset := 0; offset < len(data); offset += maxChunkSize {
		end := offset + maxChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[offset:end])
	}

	return chunks
}

// encodeSubdomain encodes data as a subdomain.
func (c *dnsConn) encodeSubdomain(data []byte, seq, total uint32) string {
	var encoded string

	switch c.config.Encoder {
	case "base64":
		// URL-safe base64
		encoded = base64.URLEncoding.EncodeToString(data)
	case "hex":
		encoded = fmt.Sprintf("%x", data)
	default:
		// base32 (DNS-friendly)
		encoded = base32.HexEncoding.EncodeToString(data)
	}

	// Add prefix with sequence info
	prefix := fmt.Sprintf("d-%s-%d-%d-", c.sessionID, seq, total)

	// Split into labels if too long
	maxLabelLen := 63
	maxDomainLen := 253

	result := prefix + encoded
	if len(result) > maxDomainLen {
		// Split into multiple labels
		var labels []string
		for len(result) > 0 {
			labelLen := min(len(result), maxLabelLen)
			labels = append(labels, result[:labelLen])
			result = result[labelLen:]
		}
		return strings.Join(labels, ".")
	}

	return result
}

// decodeData decodes data from DNS response.
func (c *dnsConn) decodeData(encoded string) []byte {
	// Extract data part (remove prefix)
	parts := strings.Split(encoded, "-")
	if len(parts) >= 2 {
		encoded = parts[len(parts)-1]
	}

	switch c.config.Encoder {
	case "base64":
		data, err := base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return []byte(encoded)
		}
		return data
	case "hex":
		data, err := hexDecode(encoded)
		if err != nil {
			return []byte(encoded)
		}
		return data
	default:
		// base32
		data, err := base32.HexEncoding.DecodeString(encoded)
		if err != nil {
			return []byte(encoded)
		}
		return data
	}
}

func hexDecode(s string) ([]byte, error) {
	data := make([]byte, len(s)/2)
	_, err := fmt.Sscanf(s, "%x", &data)
	return data, err
}

// queryType returns the DNS query type.
func (c *dnsConn) queryType() uint16 {
	switch strings.ToUpper(c.config.QueryType) {
	case "TXT":
		return dns.TypeTXT
	case "NULL":
		return dns.TypeNULL
	case "CNAME":
		return dns.TypeCNAME
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	default:
		return dns.TypeTXT
	}
}

// Read implements net.Conn.
func (c *dnsConn) Read(p []byte) (n int, err error) {
	select {
	case <-c.closeCh:
		return 0, fmt.Errorf("connection closed")
	case data := <-c.readCh:
		n = copy(p, data)
		return n, nil
	}
}

// Write implements net.Conn.
func (c *dnsConn) Write(p []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, fmt.Errorf("connection closed")
	}

	select {
	case c.writeCh <- p:
		return len(p), nil
	case <-c.closeCh:
		return 0, fmt.Errorf("connection closed")
	}
}

// Close implements net.Conn.
func (c *dnsConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
		close(c.readCh)
		close(c.writeCh)
	}
	return nil
}

// LocalAddr implements net.Conn.
func (c *dnsConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// RemoteAddr implements net.Conn.
func (c *dnsConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(c.server), Port: 53}
}

// SetDeadline implements net.Conn.
func (c *dnsConn) SetDeadline(t time.Time) error {
	return nil // Not supported
}

// SetReadDeadline implements net.Conn.
func (c *dnsConn) SetReadDeadline(t time.Time) error {
	return nil // Not supported
}

// SetWriteDeadline implements net.Conn.
func (c *dnsConn) SetWriteDeadline(t time.Time) error {
	return nil // Not supported
}

// dnsSession implements transport.Session.
type dnsSession struct {
	conn *dnsConn
	sess *smux.Session
}

func (s *dnsSession) OpenStream() (net.Conn, error) {
	return s.sess.OpenStream()
}

func (s *dnsSession) AcceptStream() (net.Conn, error) {
	return s.sess.AcceptStream()
}

func (s *dnsSession) Close() error {
	if s.sess != nil {
		_ = s.sess.Close()
	}
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *dnsSession) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *dnsSession) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// Listener implements transport.Listener for DNS tunnel.
type Listener struct {
	config   *Config
	smux     *smux.Config
	guard    string
	server   *dns.Server
	sessions chan *dnsSession
	closeCh  chan struct{}
	closed   atomic.Bool
}

// Listen creates a DNS tunnel listener.
func Listen(addr string, cfg *Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	cfg.ApplyDefaults()

	l := &Listener{
		config:   cfg,
		smux:     smuxCfg,
		guard:    guard,
		sessions: make(chan *dnsSession, 16),
		closeCh:  make(chan struct{}),
	}

	// Create DNS server
	handler := &dnsHandler{
		config:   cfg,
		sessions: l.sessions,
		smux:     smuxCfg,
		guard:    guard,
	}

	server := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: handler,
		UDPSize: cfg.MaxUDPPacket,
	}

	l.server = server

	// Start DNS server
	go func() {
		_ = server.ListenAndServe()
	}()

	return l, nil
}

// Accept accepts a DNS tunnel connection.
func (l *Listener) Accept() (transport.Session, error) {
	select {
	case <-l.closeCh:
		return nil, fmt.Errorf("listener closed")
	case session := <-l.sessions:
		return session, nil
	}
}

// Close closes the listener.
func (l *Listener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.closeCh)
		return l.server.Shutdown()
	}
	return nil
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", l.server.Addr)
	return addr
}

// dnsHandler handles DNS queries for tunneling.
type dnsHandler struct {
	config   *Config
	sessions chan *dnsSession
	smux     *smux.Config
	guard    string

	mu         sync.RWMutex
	pending    map[string][][]byte // session ID -> pending chunks
	sessionSeq map[string]uint32   // session ID -> receive sequence
}

// ServeDNS handles DNS requests.
func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Parse query
	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	name := strings.TrimSuffix(q.Name, "."+h.config.Domain)
	name = strings.TrimSuffix(name, ".")

	// Parse subdomain
	parts := strings.Split(name, ".")

	// Check if this is a tunnel query
	if len(parts) == 0 {
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}

	prefix := parts[0]

	// Handle different query types
	switch {
	case strings.HasPrefix(prefix, "d-"):
		// Data query
		h.handleDataQuery(prefix, w, r, m)
	case strings.HasPrefix(prefix, "poll-"):
		// Poll query
		h.handlePollQuery(prefix, w, r, m)
	case strings.HasPrefix(prefix, "ka-"):
		// Keepalive - just acknowledge
		h.addTXTRecord(m, "ok")
	default:
		// Unknown query - return NXDOMAIN
		m.SetRcode(r, dns.RcodeNameError)
	}

	_ = w.WriteMsg(m)
}

func (h *dnsHandler) handleDataQuery(prefix string, w dns.ResponseWriter, r *dns.Msg, m *dns.Msg) {
	// Parse session ID and sequence
	// Format: d-{session}-{seq}-{total}-{data}
	parts := strings.Split(prefix, "-")
	if len(parts) < 4 {
		m.SetRcode(r, dns.RcodeFormatError)
		return
	}

	sessionID := parts[1]
	h.addTXTRecord(m, "ack")

	// Decode data from remaining parts
	var data []byte
	for i := 3; i < len(parts); i++ {
		decoded := h.decodeData(parts[i])
		data = append(data, decoded...)
	}

	// Store data for session (would need proper session management)
	h.mu.Lock()
	if h.pending == nil {
		h.pending = make(map[string][][]byte)
	}
	h.pending[sessionID] = append(h.pending[sessionID], data)
	h.mu.Unlock()
}

func (h *dnsHandler) handlePollQuery(prefix string, w dns.ResponseWriter, r *dns.Msg, m *dns.Msg) {
	// Parse session ID
	// Format: poll-{session}-{seq}
	parts := strings.Split(prefix, "-")
	if len(parts) < 2 {
		m.SetRcode(r, dns.RcodeFormatError)
		return
	}

	sessionID := parts[1]

	// Check for pending data
	h.mu.Lock()
	defer h.mu.Unlock()

	if pending, ok := h.pending[sessionID]; ok && len(pending) > 0 {
		// Send first pending chunk
		data := pending[0]
		h.pending[sessionID] = pending[1:]

		// Encode and add as TXT record
		encoded := h.encodeData(data)
		h.addTXTRecord(m, encoded)
	} else {
		// No data
		h.addTXTRecord(m, "nodata")
	}
}

func (h *dnsHandler) encodeData(data []byte) string {
	return base32.HexEncoding.EncodeToString(data)
}

func (h *dnsHandler) decodeData(encoded string) []byte {
	data, err := base32.HexEncoding.DecodeString(encoded)
	if err != nil {
		return []byte(encoded)
	}
	return data
}

func (h *dnsHandler) addTXTRecord(m *dns.Msg, value string) {
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Txt: []string{value},
	}
	m.Answer = append(m.Answer, rr)
}

// generateSessionID generates a unique session ID.
func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// CheckConnectivity tests DNS connectivity.
func CheckConnectivity(serverAddr string) error {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("www.google.com."), dns.TypeA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, serverAddr)
	if err != nil {
		return fmt.Errorf("DNS query failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS query returned error code: %s", dns.RcodeToString[r.Rcode])
	}

	return nil
}

// AvailableDNSTypes returns available DNS query types for tunneling.
func AvailableDNSTypes() []string {
	return []string{"TXT", "NULL", "CNAME", "A", "AAAA"}
}

// RecommendedTypeForServer returns the recommended DNS type for a server.
func RecommendedTypeForServer(server string) string {
	// Most servers support TXT
	return "TXT"
}
