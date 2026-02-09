package uqsp

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds UQSP-specific metrics
type Metrics struct {
	// Session metrics
	sessionsTotal     uint64
	sessionsActive    int64
	sessionsFailed    uint64

	// Stream metrics
	streamsOpened     uint64
	streamsClosed     uint64
	streamsActive     int64

	// Datagram metrics
	datagramsSent     uint64
	datagramsReceived uint64
	datagramsDropped  uint64

	// UDP session metrics
	udpSessionsOpened uint64
	udpSessionsClosed uint64
	udpSessionsActive int64

	// Capsule metrics
	capsulesSent      uint64
	capsulesReceived  uint64

	// Obfuscation metrics
	obfuscationOps    uint64

	// Congestion metrics
	congestionEvents  uint64

	// Security metrics
	replayDrops       uint64
	authFailures      uint64

	// Handshake metrics
	handshakeTotal    uint64
	handshakeSuccess  uint64
	handshakeDuration uint64 // nanoseconds, for histogram

	// Bytes transferred
	bytesSent         uint64
	bytesReceived     uint64

	// Last update time
	lastUpdate        time.Time
	mu                sync.RWMutex
}

// NewMetrics creates a new metrics collector
func NewMetrics() *Metrics {
	return &Metrics{
		lastUpdate: time.Now(),
	}
}

// RecordSessionEstablished records a successful session establishment
func (m *Metrics) RecordSessionEstablished() {
	atomic.AddUint64(&m.sessionsTotal, 1)
	atomic.AddInt64(&m.sessionsActive, 1)
	m.updateLastUpdate()
}

// RecordSessionClosed records a session close
func (m *Metrics) RecordSessionClosed() {
	atomic.AddInt64(&m.sessionsActive, -1)
	m.updateLastUpdate()
}

// RecordSessionFailed records a failed session attempt
func (m *Metrics) RecordSessionFailed() {
	atomic.AddUint64(&m.sessionsFailed, 1)
	m.updateLastUpdate()
}

// RecordStreamOpened records a stream open
func (m *Metrics) RecordStreamOpened() {
	atomic.AddUint64(&m.streamsOpened, 1)
	atomic.AddInt64(&m.streamsActive, 1)
	m.updateLastUpdate()
}

// RecordStreamClosed records a stream close
func (m *Metrics) RecordStreamClosed() {
	atomic.AddUint64(&m.streamsClosed, 1)
	atomic.AddInt64(&m.streamsActive, -1)
	m.updateLastUpdate()
}

// RecordDatagramSent records a sent datagram
func (m *Metrics) RecordDatagramSent(bytes uint64) {
	atomic.AddUint64(&m.datagramsSent, 1)
	atomic.AddUint64(&m.bytesSent, bytes)
	m.updateLastUpdate()
}

// RecordDatagramReceived records a received datagram
func (m *Metrics) RecordDatagramReceived(bytes uint64) {
	atomic.AddUint64(&m.datagramsReceived, 1)
	atomic.AddUint64(&m.bytesReceived, bytes)
	m.updateLastUpdate()
}

// RecordDatagramDropped records a dropped datagram
func (m *Metrics) RecordDatagramDropped() {
	atomic.AddUint64(&m.datagramsDropped, 1)
	m.updateLastUpdate()
}

// RecordUDPSessionOpened records a UDP session open
func (m *Metrics) RecordUDPSessionOpened() {
	atomic.AddUint64(&m.udpSessionsOpened, 1)
	atomic.AddInt64(&m.udpSessionsActive, 1)
	m.updateLastUpdate()
}

// RecordUDPSessionClosed records a UDP session close
func (m *Metrics) RecordUDPSessionClosed() {
	atomic.AddUint64(&m.udpSessionsClosed, 1)
	atomic.AddInt64(&m.udpSessionsActive, -1)
	m.updateLastUpdate()
}

// RecordCapsuleSent records a sent capsule
func (m *Metrics) RecordCapsuleSent() {
	atomic.AddUint64(&m.capsulesSent, 1)
	m.updateLastUpdate()
}

// RecordCapsuleReceived records a received capsule
func (m *Metrics) RecordCapsuleReceived() {
	atomic.AddUint64(&m.capsulesReceived, 1)
	m.updateLastUpdate()
}

// RecordObfuscation records an obfuscation operation
func (m *Metrics) RecordObfuscation() {
	atomic.AddUint64(&m.obfuscationOps, 1)
	m.updateLastUpdate()
}

// RecordCongestionEvent records a congestion event
func (m *Metrics) RecordCongestionEvent() {
	atomic.AddUint64(&m.congestionEvents, 1)
	m.updateLastUpdate()
}

// RecordReplayDrop records a dropped replay packet
func (m *Metrics) RecordReplayDrop() {
	atomic.AddUint64(&m.replayDrops, 1)
	m.updateLastUpdate()
}

// RecordAuthFailure records an authentication failure
func (m *Metrics) RecordAuthFailure() {
	atomic.AddUint64(&m.authFailures, 1)
	m.updateLastUpdate()
}

// RecordHandshake records a handshake attempt and duration
func (m *Metrics) RecordHandshake(duration time.Duration, success bool) {
	atomic.AddUint64(&m.handshakeTotal, 1)
	atomic.AddUint64(&m.handshakeDuration, uint64(duration.Nanoseconds()))
	if success {
		atomic.AddUint64(&m.handshakeSuccess, 1)
	}
	m.updateLastUpdate()
}

// RecordBytesTransferred records bytes transferred
func (m *Metrics) RecordBytesTransferred(sent, received uint64) {
	atomic.AddUint64(&m.bytesSent, sent)
	atomic.AddUint64(&m.bytesReceived, received)
	m.updateLastUpdate()
}

// Getters for metrics

// SessionsTotal returns the total sessions established
func (m *Metrics) SessionsTotal() uint64 {
	return atomic.LoadUint64(&m.sessionsTotal)
}

// SessionsActive returns the currently active sessions
func (m *Metrics) SessionsActive() int64 {
	return atomic.LoadInt64(&m.sessionsActive)
}

// SessionsFailed returns the failed session attempts
func (m *Metrics) SessionsFailed() uint64 {
	return atomic.LoadUint64(&m.sessionsFailed)
}

// StreamsActive returns the currently active streams
func (m *Metrics) StreamsActive() int64 {
	return atomic.LoadInt64(&m.streamsActive)
}

// StreamsOpened returns the total streams opened
func (m *Metrics) StreamsOpened() uint64 {
	return atomic.LoadUint64(&m.streamsOpened)
}

// DatagramsSent returns the datagrams sent
func (m *Metrics) DatagramsSent() uint64 {
	return atomic.LoadUint64(&m.datagramsSent)
}

// DatagramsReceived returns the datagrams received
func (m *Metrics) DatagramsReceived() uint64 {
	return atomic.LoadUint64(&m.datagramsReceived)
}

// DatagramsDropped returns the datagrams dropped
func (m *Metrics) DatagramsDropped() uint64 {
	return atomic.LoadUint64(&m.datagramsDropped)
}

// UDPSessionsActive returns the active UDP sessions
func (m *Metrics) UDPSessionsActive() int64 {
	return atomic.LoadInt64(&m.udpSessionsActive)
}

// CapsulesTotal returns the total capsules processed
func (m *Metrics) CapsulesTotal() uint64 {
	sent := atomic.LoadUint64(&m.capsulesSent)
	received := atomic.LoadUint64(&m.capsulesReceived)
	return sent + received
}

// ObfuscationOps returns the obfuscation operations count
func (m *Metrics) ObfuscationOps() uint64 {
	return atomic.LoadUint64(&m.obfuscationOps)
}

// CongestionEvents returns the congestion events count
func (m *Metrics) CongestionEvents() uint64 {
	return atomic.LoadUint64(&m.congestionEvents)
}

// ReplayDrops returns the replay drops count
func (m *Metrics) ReplayDrops() uint64 {
	return atomic.LoadUint64(&m.replayDrops)
}

// AuthFailures returns the authentication failures count
func (m *Metrics) AuthFailures() uint64 {
	return atomic.LoadUint64(&m.authFailures)
}

// HandshakeTotal returns the total handshake attempts
func (m *Metrics) HandshakeTotal() uint64 {
	return atomic.LoadUint64(&m.handshakeTotal)
}

// HandshakeSuccess returns the successful handshakes
func (m *Metrics) HandshakeSuccess() uint64 {
	return atomic.LoadUint64(&m.handshakeSuccess)
}

// HandshakeAverageDuration returns the average handshake duration
func (m *Metrics) HandshakeAverageDuration() time.Duration {
	total := atomic.LoadUint64(&m.handshakeTotal)
	if total == 0 {
		return 0
	}
	duration := atomic.LoadUint64(&m.handshakeDuration)
	return time.Duration(duration/total) * time.Nanosecond
}

// BytesSent returns the bytes sent
func (m *Metrics) BytesSent() uint64 {
	return atomic.LoadUint64(&m.bytesSent)
}

// BytesReceived returns the bytes received
func (m *Metrics) BytesReceived() uint64 {
	return atomic.LoadUint64(&m.bytesReceived)
}

// Snapshot returns a snapshot of all metrics
func (m *Metrics) Snapshot() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"sessions_total":       m.SessionsTotal(),
		"sessions_active":      m.SessionsActive(),
		"sessions_failed":      m.SessionsFailed(),
		"streams_active":       m.StreamsActive(),
		"streams_opened":       m.StreamsOpened(),
		"datagrams_sent":       m.DatagramsSent(),
		"datagrams_received":   m.DatagramsReceived(),
		"datagrams_dropped":    m.DatagramsDropped(),
		"udp_sessions_active":  m.UDPSessionsActive(),
		"capsules_total":       m.CapsulesTotal(),
		"obfuscation_ops":      m.ObfuscationOps(),
		"congestion_events":    m.CongestionEvents(),
		"replay_drops":         m.ReplayDrops(),
		"auth_failures":        m.AuthFailures(),
		"handshake_total":      m.HandshakeTotal(),
		"handshake_success":    m.HandshakeSuccess(),
		"handshake_avg_ms":     m.HandshakeAverageDuration().Milliseconds(),
		"bytes_sent":           m.BytesSent(),
		"bytes_received":       m.BytesReceived(),
		"last_update":          m.lastUpdate,
	}
}

func (m *Metrics) updateLastUpdate() {
	m.mu.Lock()
	m.lastUpdate = time.Now()
	m.mu.Unlock()
}

// MetricsCollector is a global metrics collector
var MetricsCollector = NewMetrics()

// Reset resets all metrics (useful for testing)
func (m *Metrics) Reset() {
	atomic.StoreUint64(&m.sessionsTotal, 0)
	atomic.StoreInt64(&m.sessionsActive, 0)
	atomic.StoreUint64(&m.sessionsFailed, 0)
	atomic.StoreUint64(&m.streamsOpened, 0)
	atomic.StoreUint64(&m.streamsClosed, 0)
	atomic.StoreInt64(&m.streamsActive, 0)
	atomic.StoreUint64(&m.datagramsSent, 0)
	atomic.StoreUint64(&m.datagramsReceived, 0)
	atomic.StoreUint64(&m.datagramsDropped, 0)
	atomic.StoreUint64(&m.udpSessionsOpened, 0)
	atomic.StoreUint64(&m.udpSessionsClosed, 0)
	atomic.StoreInt64(&m.udpSessionsActive, 0)
	atomic.StoreUint64(&m.capsulesSent, 0)
	atomic.StoreUint64(&m.capsulesReceived, 0)
	atomic.StoreUint64(&m.obfuscationOps, 0)
	atomic.StoreUint64(&m.congestionEvents, 0)
	atomic.StoreUint64(&m.replayDrops, 0)
	atomic.StoreUint64(&m.authFailures, 0)
	atomic.StoreUint64(&m.handshakeTotal, 0)
	atomic.StoreUint64(&m.handshakeSuccess, 0)
	atomic.StoreUint64(&m.handshakeDuration, 0)
	atomic.StoreUint64(&m.bytesSent, 0)
	atomic.StoreUint64(&m.bytesReceived, 0)
	m.lastUpdate = time.Now()
}
