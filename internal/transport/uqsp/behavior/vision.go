package behavior

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// VisionOverlay implements XTLS Vision flow detection and passthrough.
// Vision detects TLS 1.3 traffic and passes it through without re-encryption
// to avoid double encryption overhead and traffic analysis.
type VisionOverlay struct {
	EnabledField bool `yaml:"enabled"`

	// FlowAutoDetect enables automatic detection of TLS flows
	FlowAutoDetect bool `yaml:"flow_auto_detect"`

	// AllowInsecure allows passthrough of non-TLS 1.3 traffic
	AllowInsecure bool `yaml:"allow_insecure"`

	// BufferSize is the size of the read buffer for flow detection
	BufferSize int `yaml:"buffer_size"`

	// DetectionTimeout is how long to wait for TLS detection
	DetectionTimeout time.Duration `yaml:"detection_timeout"`
}

// Name returns the name of this overlay
func (v *VisionOverlay) Name() string {
	return "vision"
}

// Enabled returns whether this overlay is enabled (for Overlay interface)
func (v *VisionOverlay) Enabled() bool {
	return v.EnabledField
}

// Apply applies the Vision overlay to a connection
func (v *VisionOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !v.EnabledField {
		return conn, nil
	}

	if v.BufferSize <= 0 {
		v.BufferSize = 4096
	}
	if v.DetectionTimeout <= 0 {
		v.DetectionTimeout = 5 * time.Second
	}

	return &visionConn{
		Conn:             conn,
		overlay:          v,
		buffer:           make([]byte, v.BufferSize),
		detectionBuf:     make([]byte, 0, v.BufferSize),
		state:            visionStateDetecting,
		readDeadline:     time.Now().Add(v.DetectionTimeout),
	}, nil
}

// visionState represents the connection state
type visionState int

const (
	visionStateDetecting visionState = iota
	visionStateDirect    // Direct passthrough (non-TLS or TLS 1.3)
	visionStateProxy     // Proxy mode (needs re-encryption)
)

// visionConn wraps a connection with Vision flow detection
type visionConn struct {
	net.Conn
	overlay      *VisionOverlay
	buffer       []byte
	detectionBuf []byte
	state        visionState
	mu           sync.Mutex
	readDeadline time.Time
	tlsVersion   uint16
	isTLS13      bool
}

// Read implements net.Conn.Read with Vision flow detection
func (c *visionConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If we have buffered detection data, return it first
	if len(c.detectionBuf) > 0 {
		n := copy(b, c.detectionBuf)
		c.detectionBuf = c.detectionBuf[n:]
		return n, nil
	}

	// If still detecting, try to detect the flow type
	if c.state == visionStateDetecting {
		if err := c.detectFlow(); err != nil {
			// Detection failed or timeout, default to proxy mode
			c.state = visionStateProxy
		}
	}

	// Read from underlying connection
	return c.Conn.Read(b)
}

// detectFlow attempts to detect if this is a TLS 1.3 flow
func (c *visionConn) detectFlow() error {
	// Set a read deadline for detection
	if err := c.Conn.SetReadDeadline(c.readDeadline); err != nil {
		return err
	}
	defer c.Conn.SetReadDeadline(time.Time{}) // Clear deadline

	// Read initial bytes for detection
	n, err := c.Conn.Read(c.buffer)
	if err != nil {
		return err
	}

	data := c.buffer[:n]

	// Check if this looks like TLS
	if !c.isTLSClientHello(data) {
		// Not TLS traffic, use direct mode
		c.state = visionStateDirect
		c.detectionBuf = append(c.detectionBuf, data...)
		return nil
	}

	// Parse TLS version
	c.tlsVersion = c.extractTLSVersion(data)
	c.isTLS13 = c.tlsVersion == 0x0304 // TLS 1.3

	if c.isTLS13 {
		// TLS 1.3 detected, use direct passthrough
		c.state = visionStateDirect
	} else {
		// Older TLS version, use proxy mode
		c.state = visionStateProxy
	}

	// Buffer the data we read
	c.detectionBuf = append(c.detectionBuf, data...)
	return nil
}

// isTLSClientHello checks if data looks like a TLS ClientHello
func (c *visionConn) isTLSClientHello(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	// Check for TLS record layer
	// Content type: Handshake (0x16)
	// Version: TLS 1.0 (0x0301) or higher
	// Length: varies
	if data[0] != 0x16 {
		return false
	}

	// Check for valid TLS versions in record layer
	version := uint16(data[1])<<8 | uint16(data[2])
	if version < 0x0301 || version > 0x0304 {
		return false
	}

	// Check handshake type: ClientHello (0x01)
	if len(data) < 6 {
		return false
	}
	if data[5] != 0x01 {
		return false
	}

	return true
}

// extractTLSVersion extracts the TLS version from ClientHello
func (c *visionConn) extractTLSVersion(data []byte) uint16 {
	if len(data) < 43 {
		return 0
	}

	// ClientHello structure:
	// - Record layer: 5 bytes
	// - Handshake type: 1 byte
	// - Handshake length: 3 bytes
	// - Client version: 2 bytes (at offset 9)
	clientVersion := uint16(data[9])<<8 | uint16(data[10])

	// For TLS 1.3, the record layer version is often 0x0301 (TLS 1.0)
	// but the ClientHello version is 0x0303 (TLS 1.2) with supported_versions extension
	// Check for supported_versions extension to detect TLS 1.3
	if c.hasTLS13Extension(data) {
		return 0x0304 // TLS 1.3
	}

	return clientVersion
}

// hasTLS13Extension checks if the ClientHello has TLS 1.3 supported_versions extension
func (c *visionConn) hasTLS13Extension(data []byte) bool {
	if len(data) < 43 {
		return false
	}

	// Skip to extensions
	// ClientHello format after first 11 bytes:
	// - Random: 32 bytes
	// - Session ID length: 1 byte
	// - Session ID: variable
	// - Cipher suites length: 2 bytes
	// - Cipher suites: variable
	// - Compression methods length: 1 byte
	// - Compression methods: variable
	// - Extensions length: 2 bytes
	// - Extensions: variable

	offset := 11 + 32 // Skip record layer, handshake header, and random

	// Session ID
	if len(data) <= offset {
		return false
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher suites
	if len(data) <= offset+1 {
		return false
	}
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	// Compression methods
	if len(data) <= offset {
		return false
	}
	compressionLen := int(data[offset])
	offset += 1 + compressionLen

	// Extensions
	if len(data) <= offset+1 {
		return false
	}
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	// Parse extensions
	extEnd := offset + extensionsLen
	for offset < extEnd && offset < len(data)-4 {
		extType := uint16(data[offset])<<8 | uint16(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		// supported_versions extension (type 43)
		if extType == 43 {
			// Check if 0x0304 (TLS 1.3) is in the list
			if offset+extLen <= len(data) {
				for i := 0; i+1 < extLen; i += 2 {
					version := uint16(data[offset+i])<<8 | uint16(data[offset+i+1])
					if version == 0x0304 {
						return true
					}
				}
			}
		}

		offset += extLen
	}

	return false
}

// Write implements net.Conn.Write
func (c *visionConn) Write(b []byte) (int, error) {
	// In Vision, writes pass through directly
	return c.Conn.Write(b)
}

// Close implements net.Conn.Close
func (c *visionConn) Close() error {
	return c.Conn.Close()
}

// LocalAddr implements net.Conn.LocalAddr
func (c *visionConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr implements net.Conn.RemoteAddr
func (c *visionConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// SetDeadline implements net.Conn.SetDeadline
func (c *visionConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn.SetReadDeadline
func (c *visionConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline
func (c *visionConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// IsTLS13 returns true if the connection is using TLS 1.3
func (c *visionConn) IsTLS13() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isTLS13
}

// State returns the current Vision state
func (c *visionConn) State() visionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// VisionConfig configures the Vision overlay
type VisionConfig struct {
	Enabled          bool          `yaml:"enabled"`
	FlowAutoDetect   bool          `yaml:"flow_auto_detect"`
	AllowInsecure    bool          `yaml:"allow_insecure"`
	BufferSize       int           `yaml:"buffer_size"`
	DetectionTimeout time.Duration `yaml:"detection_timeout"`
}

// ToOverlay converts config to overlay
func (c *VisionConfig) ToOverlay() *VisionOverlay {
	return &VisionOverlay{
		EnabledField:     c.Enabled,
		FlowAutoDetect:   c.FlowAutoDetect,
		AllowInsecure:    c.AllowInsecure,
		BufferSize:       c.BufferSize,
		DetectionTimeout: c.DetectionTimeout,
	}
}

// VisionTLSConn wraps a TLS connection with Vision optimizations
type VisionTLSConn struct {
	*tls.Conn
	vision *visionConn
}

// NewVisionTLSConn creates a new Vision-optimized TLS connection
func NewVisionTLSConn(conn net.Conn, config *tls.Config, visionOverlay *VisionOverlay) (*VisionTLSConn, error) {
	// Apply vision overlay first
	wrappedConn, err := visionOverlay.Apply(conn)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS
	tlsConn := tls.Client(wrappedConn, config)

	return &VisionTLSConn{
		Conn:   tlsConn,
		vision: wrappedConn.(*visionConn),
	}, nil
}

// Handshake performs the TLS handshake
func (c *VisionTLSConn) Handshake() error {
	// If Vision detected TLS 1.3, we might skip the handshake
	// and use the existing TLS connection directly
	if c.vision.IsTLS13() {
		// In a real implementation, we'd check if the underlying
		// connection is already TLS 1.3 and pass it through
	}

	return c.Conn.Handshake()
}

// isXTLSRecord checks if data is an XTLS record (0x17 = application data)
func isXTLSRecord(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// TLS record type: 0x17 = Application Data
	return data[0] == 0x17
}

// VisionFlow represents a detected Vision flow
type VisionFlow struct {
	Source      net.Addr
	Destination net.Addr
	TLSVersion  uint16
	IsTLS13     bool
	StartTime   time.Time
	BytesIn     uint64
	BytesOut    uint64
}

// VisionFlowTracker tracks Vision flows
type VisionFlowTracker struct {
	flows map[string]*VisionFlow
	mu    sync.RWMutex
}

// NewVisionFlowTracker creates a new flow tracker
func NewVisionFlowTracker() *VisionFlowTracker {
	return &VisionFlowTracker{
		flows: make(map[string]*VisionFlow),
	}
}

// AddFlow adds a new flow
func (t *VisionFlowTracker) AddFlow(key string, flow *VisionFlow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flows[key] = flow
}

// GetFlow gets a flow by key
func (t *VisionFlowTracker) GetFlow(key string) (*VisionFlow, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	flow, ok := t.flows[key]
	return flow, ok
}

// RemoveFlow removes a flow
func (t *VisionFlowTracker) RemoveFlow(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.flows, key)
}

// ListFlows returns all active flows
func (t *VisionFlowTracker) ListFlows() []*VisionFlow {
	t.mu.RLock()
	defer t.mu.RUnlock()

	flows := make([]*VisionFlow, 0, len(t.flows))
	for _, flow := range t.flows {
		flows = append(flows, flow)
	}
	return flows
}

// VisionFlowDetector detects Vision flows from packet data
func VisionFlowDetector(data []byte) (*VisionFlow, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short")
	}

	// Check for TLS record
	if data[0] != 0x16 && data[0] != 0x17 {
		return nil, fmt.Errorf("not TLS traffic")
	}

	flow := &VisionFlow{
		StartTime: time.Now(),
	}

	// Extract TLS version
	flow.TLSVersion = uint16(data[1])<<8 | uint16(data[2])
	flow.IsTLS13 = flow.TLSVersion == 0x0304

	return flow, nil
}
