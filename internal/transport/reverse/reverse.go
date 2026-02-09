// Package reverse implements reverse connection mode for StealthLink.
// In reverse mode, the agent initiates outbound connections to the gateway,
// bypassing inbound connection filtering and firewall restrictions.
package reverse

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport"

	"github.com/xtaci/smux"
)

// Config configures reverse connection mode.
type Config struct {
	// ListenAddr is the address the agent listens on for internal connections
	ListenAddr string `yaml:"listen_addr"`

	// ConnectAddr is the gateway address that agents connect to
	ConnectAddr string `yaml:"connect_addr"`

	// RetryInterval is how often to retry connections
	RetryInterval time.Duration `yaml:"retry_interval"`

	// KeepAliveInterval is the keepalive interval for established connections
	KeepAliveInterval time.Duration `yaml:"keepalive_interval"`

	// MaxConnections is the maximum number of reverse connections to maintain
	MaxConnections int `yaml:"max_connections"`

	// RegistrationPath is the HTTP path for agent registration (for HTTP-based reverse)
	RegistrationPath string `yaml:"registration_path"`
}

// ApplyDefaults sets default values for reverse configuration.
func (c *Config) ApplyDefaults() {
	if c.RetryInterval <= 0 {
		c.RetryInterval = 10 * time.Second
	}
	if c.KeepAliveInterval <= 0 {
		c.KeepAliveInterval = 30 * time.Second
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 3
	}
	if c.RegistrationPath == "" {
		c.RegistrationPath = "/_reverse_register"
	}
}

// Dialer implements the agent-side reverse dialer.
// It maintains persistent outbound connections to the gateway.
type Dialer struct {
	config    *Config
	tlsConfig *tls.Config
	smux      *smux.Config
	guard     string
	agentID   string

	sessions chan *reverseSession
	closeCh  chan struct{}
	closed   atomic.Bool

	// Connection management
	connections map[string]*reverseConn // Connection ID -> connection
	connMu      sync.RWMutex
	connCounter atomic.Uint64
}

// NewDialer creates a new reverse dialer for the agent.
func NewDialer(cfg *Config, tlsCfg *tls.Config, smuxCfg *smux.Config, guard, agentID string) *Dialer {
	cfg.ApplyDefaults()

	return &Dialer{
		config:      cfg,
		tlsConfig:   tlsCfg,
		smux:        smuxCfg,
		guard:       guard,
		agentID:     agentID,
		sessions:    make(chan *reverseSession, 16),
		closeCh:     make(chan struct{}),
		connections: make(map[string]*reverseConn),
	}
}

// Start begins maintaining reverse connections.
func (d *Dialer) Start(ctx context.Context) error {
	// Start multiple connection maintainers
	for i := 0; i < d.config.MaxConnections; i++ {
		go d.maintainConnection(ctx, i)
	}

	return nil
}

// maintainConnection maintains a single reverse connection.
func (d *Dialer) maintainConnection(ctx context.Context, index int) {
	ticker := time.NewTicker(d.config.RetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.closeCh:
			return
		default:
		}

		// Try to establish connection
		conn, err := d.establishConnection(ctx, index)
		if err != nil {
			// Wait before retry
			select {
			case <-ticker.C:
				continue
			case <-ctx.Done():
				return
			case <-d.closeCh:
				return
			}
		}

		// Connection established, maintain it
		d.maintainSession(ctx, conn)

		// Connection lost, retry
	}
}

// establishConnection establishes a new reverse connection.
func (d *Dialer) establishConnection(ctx context.Context, index int) (*reverseConn, error) {
	// Dial gateway
	var conn net.Conn
	var err error

	if d.tlsConfig != nil {
		conn, err = tls.Dial("tcp", d.config.ConnectAddr, d.tlsConfig)
	} else {
		conn, err = net.Dial("tcp", d.config.ConnectAddr)
	}

	if err != nil {
		return nil, fmt.Errorf("dial gateway: %w", err)
	}

	// Create reverse connection wrapper
	connID := fmt.Sprintf("%s-%d-%d", d.agentID, index, time.Now().Unix())
	reverseConn := &reverseConn{
		Conn:    conn,
		connID:  connID,
		agentID: d.agentID,
		index:   index,
		readCh:  make(chan []byte, 100),
		writeCh: make(chan []byte, 100),
		closeCh: make(chan struct{}),
	}

	// Send registration message
	regMsg := d.buildRegistrationMessage(connID)
	if _, err := conn.Write(regMsg); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send registration: %w", err)
	}

	// Send guard token
	if err := transport.SendGuard(conn, d.guard); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send guard: %w", err)
	}

	// Start smux session
	smuxSession, err := smux.Client(conn, d.smux)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create smux: %w", err)
	}

	// Store connection
	d.connMu.Lock()
	d.connections[connID] = reverseConn
	d.connMu.Unlock()

	reverseConn.session = smuxSession
	reverseConn.established.Store(true)

	// Start keepalive
	go reverseConn.keepalive(d.config.KeepAliveInterval)

	return reverseConn, nil
}

// buildRegistrationMessage builds the reverse registration message.
func (d *Dialer) buildRegistrationMessage(connID string) []byte {
	// Format:
	// 4 bytes: magic "REVC"
	// 4 bytes: message length
	// 4 bytes: protocol version
	// N bytes: agent ID
	// N bytes: connection ID
	// 8 bytes: timestamp

	const magic = "REVC"

	msg := make([]byte, 0, 256)
	msg = append(msg, []byte(magic)...)
	msg = append(msg, make([]byte, 4)...) // Length placeholder
	msg = append(msg, make([]byte, 4)...) // Version

	// Agent ID
	agentIDBytes := []byte(d.agentID)
	msg = append(msg, byte(len(agentIDBytes)>>8), byte(len(agentIDBytes)))
	msg = append(msg, agentIDBytes...)

	// Connection ID
	connIDBytes := []byte(connID)
	msg = append(msg, byte(len(connIDBytes)>>8), byte(len(connIDBytes)))
	msg = append(msg, connIDBytes...)

	// Timestamp
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()))
	msg = append(msg, timestamp...)

	// Fill in length
	binary.BigEndian.PutUint32(msg[4:8], uint32(len(msg)-8))

	return msg
}

// maintainSession maintains an established reverse connection.
func (d *Dialer) maintainSession(ctx context.Context, conn *reverseConn) {
	// Monitor connection health
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.closeCh:
			return
		case <-conn.closeCh:
			return
		case <-ticker.C:
			// Check if connection is still alive
			if !conn.isAlive() {
				return
			}
		}
	}
}

// Dial connects through the reverse tunnel.
// This accepts an incoming stream from the gateway through the persistent connection.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	// Wait for an incoming connection from the gateway
	select {
	case session := <-d.sessions:
		return session, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.closeCh:
		return nil, fmt.Errorf("dialer closed")
	}
}

// Close closes the reverse dialer.
func (d *Dialer) Close() error {
	if d.closed.CompareAndSwap(false, true) {
		close(d.closeCh)

		// Close all connections
		d.connMu.Lock()
		defer d.connMu.Unlock()

		for _, conn := range d.connections {
			_ = conn.Close()
		}
	}
	return nil
}

// reverseConn wraps a connection in reverse mode.
type reverseConn struct {
	net.Conn
	session     *smux.Session
	connID      string
	agentID     string
	index       int
	established atomic.Bool
	closeCh     chan struct{}

	readCh  chan []byte
	writeCh chan []byte
}

func (rc *reverseConn) keepalive(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-rc.closeCh:
			return
		case <-ticker.C:
			// smux keepalive is configured at session level; keep loop for liveness.
			if rc.session == nil || !rc.established.Load() {
				return
			}
		}
	}
}

func (rc *reverseConn) isAlive() bool {
	if !rc.established.Load() {
		return false
	}

	if rc.session != nil {
		select {
		case <-rc.closeCh:
			return false
		default:
			return true
		}
	}

	return true
}

func (rc *reverseConn) Close() error {
	close(rc.closeCh)

	if rc.session != nil {
		_ = rc.session.Close()
	}

	if rc.Conn != nil {
		return rc.Conn.Close()
	}

	return nil
}

// reverseSession wraps a smux session.
type reverseSession struct {
	conn *reverseConn
}

func (rs *reverseSession) OpenStream() (net.Conn, error) {
	if rs.conn.session == nil {
		return nil, fmt.Errorf("no session")
	}
	return rs.conn.session.OpenStream()
}

func (rs *reverseSession) AcceptStream() (net.Conn, error) {
	if rs.conn.session == nil {
		return nil, fmt.Errorf("no session")
	}
	return rs.conn.session.AcceptStream()
}

func (rs *reverseSession) Close() error {
	if rs.conn != nil {
		return rs.conn.Close()
	}
	return nil
}

func (rs *reverseSession) LocalAddr() net.Addr {
	if rs.conn != nil {
		return rs.conn.LocalAddr()
	}
	return nil
}

func (rs *reverseSession) RemoteAddr() net.Addr {
	if rs.conn != nil {
		return rs.conn.RemoteAddr()
	}
	return nil
}

// Listener implements the gateway-side reverse listener.
// It waits for agents to connect and accepts connections from them.
type Listener struct {
	config    *Config
	tlsConfig *tls.Config
	smux      *smux.Config
	guard     string

	listener net.Listener
	sessions chan *reverseSession
	closeCh  chan struct{}
	closed   atomic.Bool

	// Agent management
	agents      map[string]*agentInfo // agent ID -> agent info
	agentMu     sync.RWMutex
	pendingConn chan net.Conn
}

// agentInfo holds information about a connected agent.
type agentInfo struct {
	agentID      string
	connections  []*reverseConn
	lastSeen     time.Time
	registration []byte
}

// Listen creates a reverse listener.
func Listen(addr string, cfg *Config, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	cfg.ApplyDefaults()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	l := &Listener{
		config:      cfg,
		tlsConfig:   tlsCfg,
		smux:        smuxCfg,
		guard:       guard,
		listener:    ln,
		sessions:    make(chan *reverseSession, 16),
		closeCh:     make(chan struct{}),
		agents:      make(map[string]*agentInfo),
		pendingConn: make(chan net.Conn, 16),
	}

	// Start accepting connections
	go l.acceptLoop()

	return l, nil
}

// acceptLoop accepts incoming reverse connections.
func (l *Listener) acceptLoop() {
	for {
		select {
		case <-l.closeCh:
			return
		default:
		}

		conn, err := l.listener.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			continue
		}

		// Handle connection in goroutine
		go l.handleConnection(conn)
	}
}

// handleConnection handles an incoming reverse connection.
func (l *Listener) handleConnection(conn net.Conn) {
	// Read registration message
	regMsg := make([]byte, 4096)
	n, err := io.ReadFull(conn, regMsg[:16]) // Read header first
	if err != nil {
		_ = conn.Close()
		return
	}

	// Validate magic
	if string(regMsg[:4]) != "REVC" {
		_ = conn.Close()
		return
	}

	// Read full message
	msgLen := binary.BigEndian.Uint32(regMsg[4:8])
	if msgLen > 4096 {
		_ = conn.Close()
		return
	}

	totalLen := int(msgLen) + 8
	if n < totalLen {
		extra, err := io.ReadFull(conn, regMsg[n:totalLen])
		if err != nil {
			_ = conn.Close()
			return
		}
		n += extra
	}

	// Parse registration message
	agentID, connID, err := l.parseRegistration(regMsg[:totalLen])
	if err != nil {
		_ = conn.Close()
		return
	}

	// Verify guard token
	if err := transport.RecvGuard(conn, l.guard); err != nil {
		_ = conn.Close()
		return
	}

	// Create smux session
	smuxSession, err := smux.Server(conn, l.smux)
	if err != nil {
		_ = conn.Close()
		return
	}

	// Create reverse connection wrapper
	rconn := &reverseConn{
		Conn:        conn,
		connID:      connID,
		agentID:     agentID,
		session:     smuxSession,
		established: atomic.Bool{},
		closeCh:     make(chan struct{}),
	}
	rconn.established.Store(true)

	// Update agent info
	l.agentMu.Lock()
	info := l.agents[agentID]
	if info == nil {
		info = &agentInfo{
			agentID:     agentID,
			connections: make([]*reverseConn, 0),
		}
		l.agents[agentID] = info
	}
	info.connections = append(info.connections, rconn)
	info.lastSeen = time.Now()
	l.agentMu.Unlock()

	// Start keepalive
	go rconn.keepalive(l.config.KeepAliveInterval)

	// Create session and notify
	session := &reverseSession{
		conn: rconn,
	}

	select {
	case l.sessions <- session:
	case <-l.closeCh:
		_ = conn.Close()
	}
}

// parseRegistration parses the reverse registration message.
func (l *Listener) parseRegistration(data []byte) (agentID, connID string, err error) {
	if len(data) < 20 {
		return "", "", fmt.Errorf("message too short")
	}

	offset := 12 // Skip magic, length, version

	// Read agent ID
	if offset+2 > len(data) {
		return "", "", fmt.Errorf("truncated agent ID length")
	}
	agentIDLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+agentIDLen > len(data) {
		return "", "", fmt.Errorf("truncated agent ID")
	}
	agentID = string(data[offset : offset+agentIDLen])
	offset += agentIDLen

	// Read connection ID
	if offset+2 > len(data) {
		return "", "", fmt.Errorf("truncated conn ID length")
	}
	connIDLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+connIDLen > len(data) {
		return "", "", fmt.Errorf("truncated conn ID")
	}
	connID = string(data[offset : offset+connIDLen])

	return agentID, connID, nil
}

// Accept accepts a reverse connection.
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
		return l.listener.Close()
	}
	return nil
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// GetAgents returns information about connected agents.
func (l *Listener) GetAgents() []string {
	l.agentMu.RLock()
	defer l.agentMu.RUnlock()

	agents := make([]string, 0, len(l.agents))
	for agentID := range l.agents {
		agents = append(agents, agentID)
	}
	return agents
}

// GetAgentConnections returns the number of connections for an agent.
func (l *Listener) GetAgentConnections(agentID string) int {
	l.agentMu.RLock()
	defer l.agentMu.RUnlock()

	info := l.agents[agentID]
	if info == nil {
		return 0
	}
	return len(info.connections)
}

// Cleanup removes stale agent connections.
func (l *Listener) Cleanup(maxAge time.Duration) {
	l.agentMu.Lock()
	defer l.agentMu.Unlock()

	now := time.Now()
	for agentID, info := range l.agents {
		if now.Sub(info.lastSeen) > maxAge {
			// Close all connections for this agent
			for _, conn := range info.connections {
				_ = conn.Close()
			}
			delete(l.agents, agentID)
		}
	}
}

// ClientPool manages a pool of reverse connections for load balancing.
type ClientPool struct {
	dialer *Dialer
	mu     sync.RWMutex
}

// NewClientPool creates a new client pool.
func NewClientPool(dialer *Dialer) *ClientPool {
	return &ClientPool{dialer: dialer}
}

// GetConnection returns the best available connection.
func (p *ClientPool) GetConnection() *reverseConn {
	p.dialer.connMu.RLock()
	defer p.dialer.connMu.RUnlock()

	// Return the first healthy connection
	for _, conn := range p.dialer.connections {
		if conn.isAlive() {
			return conn
		}
	}

	return nil
}

// HealthChecker performs health checks on reverse connections.
type HealthChecker struct {
	dialer   *Dialer
	interval time.Duration
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(dialer *Dialer, interval time.Duration) *HealthChecker {
	return &HealthChecker{
		dialer:   dialer,
		interval: interval,
	}
}

// Start begins health checking.
func (hc *HealthChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hc.checkAll()
		}
	}
}

func (hc *HealthChecker) checkAll() {
	hc.dialer.connMu.Lock()
	defer hc.dialer.connMu.Unlock()

	for connID, conn := range hc.dialer.connections {
		if !conn.isAlive() {
			// Remove unhealthy connection
			delete(hc.dialer.connections, connID)
			_ = conn.Close()
		}
	}
}
