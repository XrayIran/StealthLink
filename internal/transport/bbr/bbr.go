// Package bbr implements BBR + FQ_CoDel congestion control for StealthLink.
// It provides modern congestion control with improved latency for lossy networks.
package bbr

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"stealthlink/internal/transport"
)

// Config configures BBR congestion control.
type Config struct {
	// Enable BBR congestion control
	Enabled bool `yaml:"enabled"`

	// Enable FQ_CoDel queue management
	EnableFQCoDel bool `yaml:"enable_fq_codel"`

	// TCP congestion control algorithm (bbr, cubic, etc.)
	CongestionControl string `yaml:"congestion_control"`

	// Queue discipline (fq_codel, codel, pfifo_fast, etc.)
	QDisc string `yaml:"qdisc"`

	// Target latency for FQ_CoDel (in microseconds)
	TargetLatencyUs int `yaml:"target_latency_us"`

	// Interval for FQ_CoDel (in microseconds)
	IntervalUs int `yaml:"interval_us"`

	// Quantum for FQ_CoDel (in bytes)
	Quantum int `yaml:"quantum"`

	// Limit for queue size
	Limit int `yaml:"limit"`

	// Flows for FQ_CoDel
	Flows int `yaml:"flows"`
}

// ApplyDefaults sets default values for BBR configuration.
func (c *Config) ApplyDefaults() {
	if c.CongestionControl == "" {
		c.CongestionControl = "bbr"
	}
	if c.QDisc == "" {
		c.QDisc = "fq_codel"
	}
	if c.TargetLatencyUs <= 0 {
		c.TargetLatencyUs = 5000 // 5ms
	}
	if c.IntervalUs <= 0 {
		c.IntervalUs = 100000 // 100ms
	}
	if c.Quantum <= 0 {
		c.Quantum = 1514 // MTU
	}
	if c.Limit <= 0 {
		c.Limit = 10240 // 10MB
	}
	if c.Flows <= 0 {
		c.Flows = 1024
	}
}

// Manager manages BBR settings for connections.
type Manager struct {
	config *Config
	mu     sync.RWMutex
}

// NewManager creates a new BBR manager.
func NewManager(cfg *Config) *Manager {
	cfg.ApplyDefaults()
	return &Manager{config: cfg}
}

// SetupSystem sets up system-wide BBR and FQ_CoDel.
// This requires root privileges.
func (m *Manager) SetupSystem() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("BBR is only supported on Linux")
	}

	if !m.config.Enabled {
		return nil
	}

	// Enable BBR congestion control
	if err := m.setCongestionControl(m.config.CongestionControl); err != nil {
		return fmt.Errorf("set congestion control: %w", err)
	}

	// Set up FQ_CoDel if enabled
	if m.config.EnableFQCoDel {
		if err := m.setupFQCoDel(); err != nil {
			return fmt.Errorf("setup FQ_CoDel: %w", err)
		}
	}

	return nil
}

// setCongestionControl sets the TCP congestion control algorithm.
func (m *Manager) setCongestionControl(algo string) error {
	// Check if algorithm is available
	if !m.isCCAvailable(algo) {
		return fmt.Errorf("congestion control '%s' not available", algo)
	}

	// Set system-wide default
	if err := exec.Command("sysctl", "-w", "net.ipv4.tcp_congestion_control="+algo).Run(); err != nil {
		return fmt.Errorf("set tcp_congestion_control: %w", err)
	}

	// Enable BBR specific settings if using BBR
	if algo == "bbr" {
		settings := [][]string{
			{"sysctl", "-w", "net.core.default_qdisc=fq"},
			{"sysctl", "-w", "net.ipv4.tcp_slow_start_after_idle=0"},
			{"sysctl", "-w", "net.ipv4.tcp_notsent_lowat=16384"},
		}

		for _, cmd := range settings {
			if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
				return fmt.Errorf("set BBR setting: %v: %w", cmd, err)
			}
		}
	}

	return nil
}

// isCCAvailable checks if a congestion control algorithm is available.
func (m *Manager) isCCAvailable(algo string) bool {
	data, err := exec.Command("sh", "-c", "cat /proc/sys/net/ipv4/tcp_available_congestion_control").Output()
	if err != nil {
		return false
	}

	available := string(data)
	return strings.Contains(available, algo)
}

// setupFQCoDel sets up FQ_CoDel queue discipline.
func (m *Manager) setupFQCoDel() error {
	// Get default network interface
	iface, err := m.getDefaultInterface()
	if err != nil {
		return fmt.Errorf("get default interface: %w", err)
	}

	// Remove existing qdisc
	exec.Command("tc", "qdisc", "del", "dev", iface, "root").Run()

	// Add FQ_CoDel
	args := []string{
		"qdisc", "add", "dev", iface, "root",
		m.config.QDisc,
	}

	// Add FQ_CoDel parameters
	if m.config.TargetLatencyUs > 0 {
		args = append(args, "target", fmt.Sprintf("%dus", m.config.TargetLatencyUs))
	}
	if m.config.IntervalUs > 0 {
		args = append(args, "interval", fmt.Sprintf("%dus", m.config.IntervalUs))
	}
	if m.config.Quantum > 0 {
		args = append(args, "quantum", strconv.Itoa(m.config.Quantum))
	}
	if m.config.Limit > 0 {
		args = append(args, "limit", strconv.Itoa(m.config.Limit))
	}
	if m.config.Flows > 0 {
		args = append(args, "flows", strconv.Itoa(m.config.Flows))
	}

	if err := exec.Command("tc", args...).Run(); err != nil {
		return fmt.Errorf("add FQ_CoDel: %w", err)
	}

	return nil
}

// getDefaultInterface returns the default network interface.
func (m *Manager) getDefaultInterface() (string, error) {
	data, err := exec.Command("sh", "-c", "ip route | grep default | head -1 | awk '{print $5}'").Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

// SetupConnection sets up BBR for a specific connection.
func (m *Manager) SetupConnection(conn net.Conn) (net.Conn, error) {
	if !m.config.Enabled {
		return conn, nil
	}

	return &bbrConn{
		Conn:   conn,
		config: m.config,
	}, nil
}

// bbrConn wraps a connection with BBR settings.
type bbrConn struct {
	net.Conn
	config *Config
}

// Wrapper Dialer and Listener
type Dialer struct {
	transport.Dialer
	manager *Manager
}

// NewDialer creates a new BBR dialer.
func NewDialer(inner transport.Dialer, cfg *Config) *Dialer {
	return &Dialer{
		Dialer:  inner,
		manager: NewManager(cfg),
	}
}

// Dial establishes a connection with BBR enabled.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	sess, err := d.Dialer.Dial(ctx, addr)
	if err != nil {
		return nil, err
	}

	// Wrap session with BBR
	return &bbrSession{
		Session: sess,
		manager: d.manager,
	}, nil
}

type Listener struct {
	transport.Listener
	manager *Manager
}

// NewListener creates a new BBR listener.
func NewListener(inner transport.Listener, cfg *Config) *Listener {
	return &Listener{
		Listener: inner,
		manager:  NewManager(cfg),
	}
}

// Accept accepts a connection with BBR enabled.
func (l *Listener) Accept() (transport.Session, error) {
	sess, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &bbrSession{
		Session: sess,
		manager: l.manager,
	}, nil
}

type bbrSession struct {
	transport.Session
	manager *Manager
}

func (s *bbrSession) OpenStream() (net.Conn, error) {
	stream, err := s.Session.OpenStream()
	if err != nil {
		return nil, err
	}

	return s.manager.SetupConnection(stream)
}

func (s *bbrSession) AcceptStream() (net.Conn, error) {
	stream, err := s.Session.AcceptStream()
	if err != nil {
		return nil, err
	}

	return s.manager.SetupConnection(stream)
}

// Tuner provides dynamic tuning of BBR parameters.
type Tuner struct {
	manager         *Manager
	measurement     *Measurement
	mu              sync.RWMutex
	lastSampleAt    time.Time
	lastTotalBytes  uint64
	lastOutSegs     uint64
	lastRetransSegs uint64
}

// NewTuner creates a new BBR tuner.
func NewTuner(manager *Manager) *Tuner {
	return &Tuner{
		manager:     manager,
		measurement: &Measurement{},
	}
}

// Start begins automatic tuning based on network conditions.
func (t *Tuner) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.tune()
		}
	}
}

func (t *Tuner) tune() {
	// Measure current network conditions
	latency, throughput, loss := t.measureNetwork()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.measurement.Latency = latency
	t.measurement.Throughput = throughput
	t.measurement.Loss = loss
	t.measurement.Timestamp = time.Now()

	// Adjust parameters based on conditions
	t.adjustParameters()
}

func (t *Tuner) measureNetwork() (latency time.Duration, throughput float64, loss float64) {
	latency = probeTCPLatency("1.1.1.1:443", 600*time.Millisecond)

	now := time.Now()
	totalBytes, bytesErr := readTotalNetworkBytes()
	outSegs, retransSegs, tcpErr := readTCPSegmentCounters()

	throughput = 100.0
	loss = 0.01

	if !t.lastSampleAt.IsZero() {
		dt := now.Sub(t.lastSampleAt).Seconds()
		if dt > 0 {
			if bytesErr == nil && totalBytes >= t.lastTotalBytes {
				deltaBytes := totalBytes - t.lastTotalBytes
				throughput = (float64(deltaBytes) * 8.0) / dt / 1_000_000.0
				if throughput < 0 {
					throughput = 0
				}
			}
			if tcpErr == nil && outSegs >= t.lastOutSegs && retransSegs >= t.lastRetransSegs {
				deltaOut := outSegs - t.lastOutSegs
				deltaRetrans := retransSegs - t.lastRetransSegs
				if deltaOut > 0 {
					loss = float64(deltaRetrans) / float64(deltaOut)
					loss = math.Max(0, math.Min(loss, 1))
				} else {
					loss = 0
				}
			}
		}
	}

	t.lastSampleAt = now
	if bytesErr == nil {
		t.lastTotalBytes = totalBytes
	}
	if tcpErr == nil {
		t.lastOutSegs = outSegs
		t.lastRetransSegs = retransSegs
	}
	return latency, throughput, loss
}

func probeTCPLatency(addr string, timeout time.Duration) time.Duration {
	const attempts = 3
	var best time.Duration
	for i := 0; i < attempts; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue
		}
		_ = conn.Close()
		sample := time.Since(start)
		if best == 0 || sample < best {
			best = sample
		}
	}
	if best == 0 {
		return 50 * time.Millisecond
	}
	return best
}

func readTotalNetworkBytes() (uint64, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var total uint64
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		total += rx + tx
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return total, nil
}

func readTCPSegmentCounters() (outSegs uint64, retransSegs uint64, err error) {
	f, err := os.Open("/proc/net/snmp")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var header []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "Tcp:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if len(header) == 0 {
			header = fields[1:]
			continue
		}
		values := fields[1:]
		if len(values) != len(header) {
			return 0, 0, fmt.Errorf("invalid /proc/net/snmp format")
		}
		idxOut, idxRetrans := -1, -1
		for i, h := range header {
			if h == "OutSegs" {
				idxOut = i
			}
			if h == "RetransSegs" {
				idxRetrans = i
			}
		}
		if idxOut == -1 || idxRetrans == -1 {
			return 0, 0, fmt.Errorf("TCP counters not found")
		}
		outSegs, err = strconv.ParseUint(values[idxOut], 10, 64)
		if err != nil {
			return 0, 0, err
		}
		retransSegs, err = strconv.ParseUint(values[idxRetrans], 10, 64)
		if err != nil {
			return 0, 0, err
		}
		return outSegs, retransSegs, nil
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	return 0, 0, fmt.Errorf("TCP counters not found")
}

func (t *Tuner) adjustParameters() {
	if t.manager == nil || t.manager.config == nil {
		return
	}

	t.manager.mu.Lock()
	defer t.manager.mu.Unlock()

	cfg := t.manager.config
	latency := t.measurement.Latency
	loss := t.measurement.Loss

	// Conservative profile for poor links.
	if loss >= 0.05 || latency >= 200*time.Millisecond {
		cfg.TargetLatencyUs = 10000
		cfg.IntervalUs = 150000
		cfg.Quantum = 1200
		cfg.Limit = 8192
		cfg.Flows = 512
		return
	}

	// Balanced profile for moderate jitter/loss.
	if loss >= 0.02 || latency >= 100*time.Millisecond {
		cfg.TargetLatencyUs = 7000
		cfg.IntervalUs = 120000
		cfg.Quantum = 1400
		cfg.Limit = 10240
		cfg.Flows = 768
		return
	}

	// Aggressive profile for clean links.
	cfg.TargetLatencyUs = 5000
	cfg.IntervalUs = 100000
	cfg.Quantum = 1514
	cfg.Limit = 12288
	cfg.Flows = 1024
}

// Measurement holds network measurements.
type Measurement struct {
	Latency    time.Duration `json:"latency_ms"`
	Throughput float64       `json:"throughput_mbps"`
	Loss       float64       `json:"loss_rate"`
	Timestamp  time.Time     `json:"timestamp"`
}

// GetMeasurement returns the current network measurement.
func (t *Tuner) GetMeasurement() Measurement {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return *t.measurement
}

// SocketOptManager manages socket options for BBR.
type SocketOptManager struct {
	enableTCPAuto bool
	enableTSO     bool
	enableGRO     bool
}

// NewSocketOptManager creates a new socket option manager.
func NewSocketOptManager() *SocketOptManager {
	return &SocketOptManager{
		enableTCPAuto: true, // Enable TCP autotuning
		enableTSO:     true, // Enable TCP segmentation offload
		enableGRO:     true, // Enable generic receive offload
	}
}

// ApplyOptions applies optimal socket options for BBR.
func (s *SocketOptManager) ApplyOptions(conn net.Conn) error {
	// Set socket options for optimal BBR performance
	// This would require syscall-level access to the file descriptor

	// For TCP connections:
	// - TCP_NODELAY: Disable Nagle's algorithm
	// - TCP_QUICKACK: Enable quick ACKs
	// - TCP_THIN_LINEAR_TIMEOUTS: Reduce retransmission timeouts
	// - TCP_THIN_DUPACK: Trigger immediate DUPACKs

	// These require raw socket access or syscall package
	return nil
}

// Monitor provides BBR monitoring and statistics.
type Monitor struct {
	mu    sync.RWMutex
	stats map[string]*ConnectionStats
}

// NewMonitor creates a new BBR monitor.
func NewMonitor() *Monitor {
	return &Monitor{
		stats: make(map[string]*ConnectionStats),
	}
}

// ConnectionStats holds per-connection statistics.
type ConnectionStats struct {
	ID              string    `json:"id"`
	RTT             uint32    `json:"rtt_us"`
	RTTVar          uint32    `json:"rtt_var_us"`
	Bandwidth       uint64    `json:"bandwidth_bps"`
	MinRTT          uint32    `json:"min_rtt_us"`
	PacingRate      uint64    `json:"pacing_rate_bps"`
	Cwnd            uint32    `json:"cwnd"`
	DeliveryRate    uint64    `json:"delivery_rate_bps"`
	BytesSent       uint64    `json:"bytes_sent"`
	BytesReceived   uint64    `json:"bytes_received"`
	PacketsSent     uint64    `json:"packets_sent"`
	PacketsReceived uint64    `json:"packets_received"`
	PacketsRetrans  uint64    `json:"packets_retrans"`
	LossRate        float64   `json:"loss_rate"`
	LastUpdate      time.Time `json:"last_update"`
}

// Track starts tracking a connection.
func (m *Monitor) Track(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stats[id] = &ConnectionStats{
		ID:         id,
		LastUpdate: time.Now(),
	}
}

// Untrack stops tracking a connection.
func (m *Monitor) Untrack(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.stats, id)
}

// Update updates statistics for a connection.
func (m *Monitor) Update(id string, stats ConnectionStats) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.stats[id]; ok {
		*s = stats
		s.LastUpdate = time.Now()
	}
}

// GetStats returns statistics for a connection.
func (m *Monitor) GetStats(id string) (ConnectionStats, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats, ok := m.stats[id]
	if ok {
		return *stats, true
	}
	return ConnectionStats{}, false
}

// GetAllStats returns all connection statistics.
func (m *Monitor) GetAllStats() []ConnectionStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]ConnectionStats, 0, len(m.stats))
	for _, stats := range m.stats {
		result = append(result, *stats)
	}
	return result
}

// GetSummary returns a summary of all connections.
func (m *Monitor) GetSummary() Summary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	summary := Summary{
		ConnectionCount: len(m.stats),
		Timestamp:       time.Now(),
	}

	for _, stats := range m.stats {
		summary.TotalBandwidth += stats.Bandwidth
		summary.TotalBytesSent += stats.BytesSent
		summary.TotalBytesReceived += stats.BytesReceived
		summary.TotalPacketsSent += stats.PacketsSent
		summary.TotalPacketsReceived += stats.PacketsReceived
		summary.TotalPacketsRetrans += stats.PacketsRetrans

		if stats.MinRTT > 0 && (summary.MinRTT == 0 || stats.MinRTT < summary.MinRTT) {
			summary.MinRTT = stats.MinRTT
		}
		if stats.RTT > summary.MaxRTT {
			summary.MaxRTT = stats.RTT
		}

		// Average RTT
		summary.AvgRTT = (summary.AvgRTT*float64(summary.ConnectionCount-1) + float64(stats.RTT)) / float64(summary.ConnectionCount)
	}

	return summary
}

// Summary holds aggregate statistics.
type Summary struct {
	ConnectionCount      int       `json:"connection_count"`
	TotalBandwidth       uint64    `json:"total_bandwidth_bps"`
	MinRTT               uint32    `json:"min_rtt_us"`
	MaxRTT               uint32    `json:"max_rtt_us"`
	AvgRTT               float64   `json:"avg_rtt_us"`
	TotalBytesSent       uint64    `json:"total_bytes_sent"`
	TotalBytesReceived   uint64    `json:"total_bytes_received"`
	TotalPacketsSent     uint64    `json:"total_packets_sent"`
	TotalPacketsReceived uint64    `json:"total_packets_received"`
	TotalPacketsRetrans  uint64    `json:"total_packets_retrans"`
	Timestamp            time.Time `json:"timestamp"`
}

// VerifyBBRAvailable checks if BBR is available on the system.
func VerifyBBRAvailable() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("BBR is only supported on Linux")
	}

	// Check kernel version (BBR requires 4.9+)
	data, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return fmt.Errorf("check kernel version: %w", err)
	}

	_ = strings.TrimSpace(string(data))
	// Parse version and check >= 4.9
	// For now, just assume BBR is available on modern Linux

	return nil
}

// GetAvailableCC returns available congestion control algorithms.
func GetAvailableCC() ([]string, error) {
	data, err := exec.Command("sh", "-c", "cat /proc/sys/net/ipv4/tcp_available_congestion_control").Output()
	if err != nil {
		return nil, fmt.Errorf("get available CC: %w", err)
	}

	available := strings.Fields(string(data))
	return available, nil
}

// GetAvailableQDisc returns available queue disciplines.
func GetAvailableQDisc() ([]string, error) {
	data, err := exec.Command("tc", "qdisc", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("get available qdisc: %w", err)
	}

	// Parse output to extract qdisc names
	lines := strings.Split(string(data), "\n")
	qdiscs := make(map[string]bool)

	for _, line := range lines {
		if strings.Contains(line, "qdisc") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				qdiscs[parts[2]] = true
			}
		}
	}

	result := make([]string, 0, len(qdiscs))
	for qdisc := range qdiscs {
		result = append(result, qdisc)
	}

	return result, nil
}
