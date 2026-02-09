package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// TCPSessionMetrics holds TCP_INFO-derived metrics for a session.
type TCPSessionMetrics struct {
	RTT           uint32  // microseconds
	RTTVar        uint32  // microseconds
	SndCwnd       uint32  // sending congestion window
	PacingRate    int64   // bytes per second
	DeliveryRate  int64   // bytes per second
	BytesRetrans  int64   // bytes retransmitted
	TotalRetrans  uint32  // total retransmits
	MinRTT        uint32  // minimum RTT seen
	BytesAcked    int64   // bytes acknowledged
	BytesReceived int64   // bytes received
	SegsOut       uint32  // segments sent
	SegsIn        uint32  // segments received
	DataSegsOut   uint32  // data segments sent
	DataSegsIn    uint32  // data segments received
	Lost          uint32  // lost packets
}

// CalculateLossRate returns the loss rate as a percentage.
func (m *TCPSessionMetrics) CalculateLossRate() float64 {
	if m.SegsOut == 0 {
		return 0
	}
	return float64(m.Lost) / float64(m.SegsOut) * 100
}

// CalculateRetransRate returns the retransmission rate as a percentage.
func (m *TCPSessionMetrics) CalculateRetransRate() float64 {
	if m.DataSegsOut == 0 {
		return 0
	}
	return float64(m.TotalRetrans) / float64(m.DataSegsOut) * 100
}

// CarrierMetrics holds per-carrier (transport type) metrics.
type CarrierMetrics struct {
	Name           string
	Connections    atomic.Int64
	ActiveConns    atomic.Int64
	BytesSent      atomic.Int64
	BytesRecv      atomic.Int64
	Errors         atomic.Int64
	Switches       atomic.Int64 // Carrier switch events
	RTTSum         atomic.Int64 // Sum of RTTs for averaging
	RTTCount       atomic.Int64
	LossEvents     atomic.Int64
	RetransEvents  atomic.Int64
	lastUpdate     atomic.Int64 // Unix timestamp
}

// AverageRTT returns the average RTT in milliseconds.
func (c *CarrierMetrics) AverageRTT() float64 {
	count := c.RTTCount.Load()
	if count == 0 {
		return 0
	}
	return float64(c.RTTSum.Load()) / float64(count) / 1000.0
}

var (
	// TCP session metrics storage
	tcpSessionMetrics sync.Map // sessionID -> *TCPSessionMetricsSnapshot

	// Per-carrier metrics
	carrierMetrics sync.Map // carrierName -> *CarrierMetrics

	// Global TCP telemetry counters
	tcpRTTTotal       atomic.Int64 // microseconds
	tcpRTTCount       atomic.Int64
	tcpLossTotal      atomic.Int64
	tcpRetransTotal   atomic.Int64
	tcpCwndTotal      atomic.Int64
	tcpPacingAvg      atomic.Int64
	tcpDeliveryAvg    atomic.Int64
)

// TCPSessionMetricsSnapshot includes the metrics plus metadata.
type TCPSessionMetricsSnapshot struct {
	SessionID   string            `json:"session_id"`
	Carrier     string            `json:"carrier"`
	LocalAddr   string            `json:"local_addr"`
	RemoteAddr  string            `json:"remote_addr"`
	ConnectedAt time.Time         `json:"connected_at"`
	Metrics     TCPSessionMetrics `json:"metrics"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// RecordTCPSessionMetrics records metrics for a TCP session.
func RecordTCPSessionMetrics(sessionID string, metrics *TCPSessionMetricsSnapshot) {
	tcpSessionMetrics.Store(sessionID, metrics)

	// Update global averages
	if metrics.Metrics.RTT > 0 {
		tcpRTTTotal.Add(int64(metrics.Metrics.RTT))
		tcpRTTCount.Add(1)
	}
	if metrics.Metrics.Lost > 0 {
		tcpLossTotal.Add(int64(metrics.Metrics.Lost))
	}
	if metrics.Metrics.TotalRetrans > 0 {
		tcpRetransTotal.Add(int64(metrics.Metrics.TotalRetrans))
	}
	if metrics.Metrics.SndCwnd > 0 {
		tcpCwndTotal.Add(int64(metrics.Metrics.SndCwnd))
	}

	// Update carrier metrics
	if metrics.Carrier != "" {
		cm := GetOrCreateCarrierMetrics(metrics.Carrier)
		cm.lastUpdate.Store(time.Now().Unix())
		if metrics.Metrics.RTT > 0 {
			cm.RTTSum.Add(int64(metrics.Metrics.RTT))
			cm.RTTCount.Add(1)
		}
		if metrics.Metrics.Lost > 0 {
			cm.LossEvents.Add(1)
		}
		if metrics.Metrics.TotalRetrans > 0 {
			cm.RetransEvents.Add(1)
		}
	}
}

// RemoveTCPSessionMetrics removes metrics for a closed session.
func RemoveTCPSessionMetrics(sessionID string) {
	tcpSessionMetrics.Delete(sessionID)
}

// GetTCPSessionMetrics retrieves metrics for a specific session.
func GetTCPSessionMetrics(sessionID string) (*TCPSessionMetricsSnapshot, bool) {
	if v, ok := tcpSessionMetrics.Load(sessionID); ok {
		return v.(*TCPSessionMetricsSnapshot), true
	}
	return nil, false
}

// GetAllTCPSessionMetrics returns all TCP session metrics.
func GetAllTCPSessionMetrics() []TCPSessionMetricsSnapshot {
	var result []TCPSessionMetricsSnapshot
	tcpSessionMetrics.Range(func(k, v any) bool {
		snapshot := *v.(*TCPSessionMetricsSnapshot)
		result = append(result, snapshot)
		return true
	})
	return result
}

// GetOrCreateCarrierMetrics gets or creates carrier metrics.
func GetOrCreateCarrierMetrics(carrierName string) *CarrierMetrics {
	v, _ := carrierMetrics.LoadOrStore(carrierName, &CarrierMetrics{
		Name: carrierName,
	})
	return v.(*CarrierMetrics)
}

// RecordCarrierConnection records a new connection for a carrier.
func RecordCarrierConnection(carrierName string) {
	cm := GetOrCreateCarrierMetrics(carrierName)
	cm.Connections.Add(1)
	cm.ActiveConns.Add(1)
}

// RecordCarrierDisconnection records a disconnection for a carrier.
func RecordCarrierDisconnection(carrierName string) {
	cm := GetOrCreateCarrierMetrics(carrierName)
	cm.ActiveConns.Add(-1)
}

// RecordCarrierTraffic records traffic for a carrier.
func RecordCarrierTraffic(carrierName string, sent, recv int64) {
	cm := GetOrCreateCarrierMetrics(carrierName)
	if sent > 0 {
		cm.BytesSent.Add(sent)
	}
	if recv > 0 {
		cm.BytesRecv.Add(recv)
	}
}

// RecordCarrierError records an error for a carrier.
func RecordCarrierError(carrierName string) {
	cm := GetOrCreateCarrierMetrics(carrierName)
	cm.Errors.Add(1)
}

// RecordCarrierSwitch records a carrier switch event.
func RecordCarrierSwitch(fromCarrier, toCarrier string) {
	if fromCarrier != "" {
		cm := GetOrCreateCarrierMetrics(fromCarrier)
		cm.Switches.Add(1)
	}
}

// GetCarrierMetrics returns metrics for all carriers.
func GetCarrierMetrics() map[string]*CarrierMetricsSnapshot {
	result := make(map[string]*CarrierMetricsSnapshot)
	carrierMetrics.Range(func(k, v any) bool {
		cm := v.(*CarrierMetrics)
		result[k.(string)] = &CarrierMetricsSnapshot{
			Name:          cm.Name,
			Connections:   cm.Connections.Load(),
			ActiveConns:   cm.ActiveConns.Load(),
			BytesSent:     cm.BytesSent.Load(),
			BytesRecv:     cm.BytesRecv.Load(),
			Errors:        cm.Errors.Load(),
			Switches:      cm.Switches.Load(),
			AverageRTT:    cm.AverageRTT(),
			LossEvents:    cm.LossEvents.Load(),
			RetransEvents: cm.RetransEvents.Load(),
			LastUpdate:    cm.lastUpdate.Load(),
		}
		return true
	})
	return result
}

// CarrierMetricsSnapshot is a serializable snapshot of carrier metrics.
type CarrierMetricsSnapshot struct {
	Name          string  `json:"name"`
	Connections   int64   `json:"connections"`
	ActiveConns   int64   `json:"active_connections"`
	BytesSent     int64   `json:"bytes_sent"`
	BytesRecv     int64   `json:"bytes_received"`
	Errors        int64   `json:"errors"`
	Switches      int64   `json:"switch_events"`
	AverageRTT    float64 `json:"average_rtt_ms"`
	LossEvents    int64   `json:"loss_events"`
	RetransEvents int64   `json:"retrans_events"`
	LastUpdate    int64   `json:"last_update_unix"`
}

// TCPTelemetrySnapshot provides a global view of TCP telemetry.
type TCPTelemetrySnapshot struct {
	AverageRTTMs     float64                        `json:"average_rtt_ms"`
	TotalLossEvents  int64                          `json:"total_loss_events"`
	TotalRetransmits int64                          `json:"total_retransmits"`
	AverageCwnd      int64                          `json:"average_cwnd"`
	SessionCount     int                            `json:"session_count"`
	Carriers         map[string]*CarrierMetricsSnapshot `json:"carriers"`
}

// GetTCPTelemetry returns a snapshot of global TCP telemetry.
func GetTCPTelemetry() TCPTelemetrySnapshot {
	avgRTT := 0.0
	if count := tcpRTTCount.Load(); count > 0 {
		avgRTT = float64(tcpRTTTotal.Load()) / float64(count) / 1000.0
	}

	cwnd := int64(0)
	if count := tcpRTTCount.Load(); count > 0 {
		cwnd = tcpCwndTotal.Load() / count
	}

	sessionCount := 0
	tcpSessionMetrics.Range(func(_, _ any) bool {
		sessionCount++
		return true
	})

	return TCPTelemetrySnapshot{
		AverageRTTMs:     avgRTT,
		TotalLossEvents:  tcpLossTotal.Load(),
		TotalRetransmits: tcpRetransTotal.Load(),
		AverageCwnd:      cwnd,
		SessionCount:     sessionCount,
		Carriers:         GetCarrierMetrics(),
	}
}

// TCPTelemetryCollector collects TCP telemetry at regular intervals.
type TCPTelemetryCollector struct {
	interval time.Duration
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewTCPTelemetryCollector creates a new collector.
func NewTCPTelemetryCollector(interval time.Duration) *TCPTelemetryCollector {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &TCPTelemetryCollector{
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start begins collecting telemetry.
func (c *TCPTelemetryCollector) Start(collectFunc func()) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if collectFunc != nil {
					collectFunc()
				}
			case <-c.stopCh:
				return
			}
		}
	}()
}

// Stop stops the collector.
func (c *TCPTelemetryCollector) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}
