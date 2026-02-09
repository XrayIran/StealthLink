// Package tcpstat provides TCP_INFO collection integration with metrics.
package tcpstat

import (
	"net"
	"sync"
	"time"

	"stealthlink/internal/metrics"
)

// CollectorConfig configures the TCP statistics collector.
type CollectorConfig struct {
	// Enabled enables TCP_INFO collection
	Enabled bool

	// Interval is how often to collect statistics
	Interval time.Duration

	// CarrierName is the transport/carrier name for metrics attribution
	CarrierName string
}

// ApplyDefaults sets default values.
func (c *CollectorConfig) ApplyDefaults() {
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.CarrierName == "" {
		c.CarrierName = "tcp"
	}
}

// SessionCollector manages TCP_INFO collection for active sessions.
type SessionCollector struct {
	config    CollectorConfig
	sessions  map[string]*monitoredSession
	mu        sync.RWMutex
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// monitoredSession tracks a single session for metrics collection.
type monitoredSession struct {
	SessionID   string
	Carrier     string
	Conn        net.Conn
	LocalAddr   string
	RemoteAddr  string
	ConnectedAt time.Time
	lastMetrics *TCPInfo
}

// NewSessionCollector creates a new TCP_INFO collector.
func NewSessionCollector(config CollectorConfig) *SessionCollector {
	config.ApplyDefaults()
	return &SessionCollector{
		config:   config,
		sessions: make(map[string]*monitoredSession),
		stopCh:   make(chan struct{}),
	}
}

// Start begins collecting TCP statistics.
func (c *SessionCollector) Start() {
	if !c.config.Enabled {
		return
	}

	c.wg.Add(1)
	go c.collectLoop()
}

// Stop stops the collector.
func (c *SessionCollector) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

// AddSession adds a session to monitor.
func (c *SessionCollector) AddSession(sessionID string, conn net.Conn) {
	if !c.config.Enabled {
		return
	}

	// Only monitor TCP connections
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		// Try to unwrap if it's a wrapped connection
		tcpConn = extractTCPConn(conn)
		if tcpConn == nil {
			return
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.sessions[sessionID] = &monitoredSession{
		SessionID:   sessionID,
		Carrier:     c.config.CarrierName,
		Conn:        tcpConn,
		LocalAddr:   conn.LocalAddr().String(),
		RemoteAddr:  conn.RemoteAddr().String(),
		ConnectedAt: time.Now(),
	}

	// Record initial connection
	metrics.RecordCarrierConnection(c.config.CarrierName)

	// Collect initial metrics
	go c.collectForSession(sessionID)
}

// RemoveSession removes a session from monitoring.
func (c *SessionCollector) RemoveSession(sessionID string) {
	if !c.config.Enabled {
		return
	}

	c.mu.Lock()
	_, exists := c.sessions[sessionID]
	delete(c.sessions, sessionID)
	c.mu.Unlock()

	if exists {
		metrics.RecordCarrierDisconnection(c.config.CarrierName)
		metrics.RemoveTCPSessionMetrics(sessionID)
	}
}

func (c *SessionCollector) collectLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.collectAll()
		case <-c.stopCh:
			return
		}
	}
}

func (c *SessionCollector) collectAll() {
	c.mu.RLock()
	sessionIDs := make([]string, 0, len(c.sessions))
	for id := range c.sessions {
		sessionIDs = append(sessionIDs, id)
	}
	c.mu.RUnlock()

	for _, id := range sessionIDs {
		select {
		case <-c.stopCh:
			return
		default:
			c.collectForSession(id)
		}
	}
}

func (c *SessionCollector) collectForSession(sessionID string) {
	c.mu.RLock()
	session, ok := c.sessions[sessionID]
	c.mu.RUnlock()

	if !ok {
		return
	}

	tcpConn, ok := session.Conn.(*net.TCPConn)
	if !ok {
		return
	}

	info, err := GetTCPInfo(tcpConn)
	if err != nil {
		// Connection may have closed
		return
	}

	session.lastMetrics = info

	// Create metrics snapshot
	snapshot := &metrics.TCPSessionMetricsSnapshot{
		SessionID:   sessionID,
		Carrier:     session.Carrier,
		LocalAddr:   session.LocalAddr,
		RemoteAddr:  session.RemoteAddr,
		ConnectedAt: session.ConnectedAt,
		Metrics: metrics.TCPSessionMetrics{
			RTT:           info.RTT,
			RTTVar:        info.RTTVar,
			SndCwnd:       info.SndCwnd,
			PacingRate:    info.PacingRate,
			DeliveryRate:  info.DeliveryRate,
			BytesRetrans:  info.BytesRetrans,
			TotalRetrans:  info.TotalRetrans,
			MinRTT:        info.MinRTT,
			BytesAcked:    info.BytesAcked,
			BytesReceived: info.BytesReceived,
			SegsOut:       uint32(info.SegsOut),
			SegsIn:        uint32(info.SegsIn),
			DataSegsOut:   info.DataSegsOut,
			DataSegsIn:    info.DataSegsIn,
			Lost:          info.Lost,
		},
		UpdatedAt: time.Now(),
	}

	metrics.RecordTCPSessionMetrics(sessionID, snapshot)
}

// extractTCPConn attempts to extract a *net.TCPConn from a wrapped connection.
func extractTCPConn(conn net.Conn) *net.TCPConn {
	// Common wrapper types to unwrap
	type unwrapper interface {
		NetConn() net.Conn
	}

	type connWrapper interface {
		Conn() net.Conn
	}

	// Try to unwrap
	if u, ok := conn.(unwrapper); ok {
		return extractTCPConn(u.NetConn())
	}

	if u, ok := conn.(connWrapper); ok {
		return extractTCPConn(u.Conn())
	}

	// Check if it's directly a TCPConn
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		return tcpConn
	}

	return nil
}

// GetSessionInfo returns the latest TCP_INFO for a session.
func (c *SessionCollector) GetSessionInfo(sessionID string) (*TCPInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if session, ok := c.sessions[sessionID]; ok {
		return session.lastMetrics, true
	}
	return nil, false
}

// SessionCount returns the number of monitored sessions.
func (c *SessionCollector) SessionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}
