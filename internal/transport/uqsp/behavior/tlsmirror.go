package behavior

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
)

// TLSMirrorOverlay ports TLSMirror behaviors as a UQSP overlay.
// TLSMirror mirrors TLS record structures to blend in with TLS traffic.
type TLSMirrorOverlay struct {
	EnabledField       bool
	ControlChannel     string
	EnrollmentRequired bool
}

// NewTLSMirrorOverlay creates a new TLSMirror overlay from config
func NewTLSMirrorOverlay(cfg config.TLSMirrorBehaviorConfig) *TLSMirrorOverlay {
	return &TLSMirrorOverlay{
		EnabledField:       cfg.Enabled,
		ControlChannel:     cfg.ControlChannel,
		EnrollmentRequired: cfg.EnrollmentRequired,
	}
}

// Name returns "tlsmirror"
func (o *TLSMirrorOverlay) Name() string {
	return "tlsmirror"
}

// Enabled returns whether this overlay is enabled
func (o *TLSMirrorOverlay) Enabled() bool {
	return o.EnabledField
}

// Apply applies TLSMirror behavior to the connection
func (o *TLSMirrorOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}

	wrapper := &tlsMirrorConn{
		Conn:               conn,
		controlChannel:     o.ControlChannel,
		enrollmentRequired: o.EnrollmentRequired,
		recordBuf:          make([]byte, 0, 16384),
	}

	// Perform enrollment if required
	if o.EnrollmentRequired {
		if err := wrapper.enroll(); err != nil {
			return nil, fmt.Errorf("tlsmirror enrollment: %w", err)
		}
	}

	return wrapper, nil
}

// mirrorConfig holds mirror parameters received from the control channel.
type mirrorConfig struct {
	RecordSizes    []int   // Common record sizes to mimic
	PaddingPolicy  string  // "random", "bucket", "none"
	ContentWeights [4]int  // Weights for content types 0x14-0x17
	MaxRecordSize  int     // Max TLS record size
}

func defaultMirrorConfig() *mirrorConfig {
	return &mirrorConfig{
		RecordSizes:    []int{256, 512, 1024, 2048, 4096, 8192, 16384},
		PaddingPolicy:  "bucket",
		ContentWeights: [4]int{1, 1, 5, 93}, // CCS, Alert, Handshake, AppData
		MaxRecordSize:  16384,
	}
}

// tlsMirrorConn wraps a connection with TLSMirror behavior
type tlsMirrorConn struct {
	net.Conn
	controlChannel     string
	enrollmentRequired bool
	enrolled           bool
	recordBuf          []byte
	mu                 sync.Mutex
	mirror             *mirrorConfig
}

// enroll performs TLSMirror enrollment by connecting to the control channel,
// exchanging capabilities, and receiving mirror configuration.
func (c *tlsMirrorConn) enroll() error {
	if c.enrolled {
		return nil
	}

	if c.controlChannel == "" {
		// No control channel — use defaults
		c.mirror = defaultMirrorConfig()
		c.enrolled = true
		return nil
	}

	// Connect to control channel
	ctlConn, err := net.DialTimeout("tcp", c.controlChannel, 5*time.Second)
	if err != nil {
		// Fallback to defaults on connection failure
		c.mirror = defaultMirrorConfig()
		c.enrolled = true
		return nil
	}
	defer ctlConn.Close()
	_ = ctlConn.SetDeadline(time.Now().Add(5 * time.Second))

	// Exchange capabilities: send magic + version + caps
	magic := []byte("TLSM")
	version := []byte{0x01}
	caps := []byte{0x01} // Supports record mirroring
	envelope := append(magic, version...)
	envelope = append(envelope, caps...)
	if _, err := ctlConn.Write(envelope); err != nil {
		c.mirror = defaultMirrorConfig()
		c.enrolled = true
		return nil
	}

	// Receive mirror config: [record_count(1)][sizes(2*N)][padding_policy(1)][max_record(2)]
	header := make([]byte, 1)
	if _, err := ctlConn.Read(header); err != nil {
		c.mirror = defaultMirrorConfig()
		c.enrolled = true
		return nil
	}
	recordCount := int(header[0])
	if recordCount == 0 || recordCount > 32 {
		recordCount = 7
	}

	cfg := defaultMirrorConfig()
	sizeBuf := make([]byte, 2*recordCount)
	if n, _ := ctlConn.Read(sizeBuf); n == len(sizeBuf) {
		cfg.RecordSizes = make([]int, recordCount)
		for i := 0; i < recordCount; i++ {
			cfg.RecordSizes[i] = int(binary.BigEndian.Uint16(sizeBuf[i*2 : i*2+2]))
		}
	}

	policyBuf := make([]byte, 3) // policy(1) + max_record(2)
	if n, _ := ctlConn.Read(policyBuf); n >= 1 {
		switch policyBuf[0] {
		case 0x00:
			cfg.PaddingPolicy = "none"
		case 0x01:
			cfg.PaddingPolicy = "random"
		case 0x02:
			cfg.PaddingPolicy = "bucket"
		}
		if n >= 3 {
			cfg.MaxRecordSize = int(binary.BigEndian.Uint16(policyBuf[1:3]))
			if cfg.MaxRecordSize <= 0 || cfg.MaxRecordSize > 16384 {
				cfg.MaxRecordSize = 16384
			}
		}
	}

	c.mirror = cfg
	c.enrolled = true
	return nil
}

// Read reads data from the connection with TLS record mirroring
func (c *tlsMirrorConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If we have buffered record data, return it
	if len(c.recordBuf) > 0 {
		n := copy(p, c.recordBuf)
		c.recordBuf = c.recordBuf[n:]
		return n, nil
	}

	// Read TLS record from underlying connection
	record, err := c.readTLSRecord()
	if err != nil {
		return 0, err
	}

	// Extract payload from TLS record
	payload, err := c.extractPayload(record)
	if err != nil {
		return 0, err
	}

	// Copy to output buffer
	n := copy(p, payload)
	if n < len(payload) {
		// Buffer remaining data
		c.recordBuf = append(c.recordBuf[:0], payload[n:]...)
	}

	return n, nil
}

// Write writes data to the connection with TLS record mirroring
func (c *tlsMirrorConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Wrap payload in TLS record structure
	records := c.wrapInTLSRecords(p)

	// Write records to underlying connection
	written := 0
	for _, record := range records {
		if _, err := c.Conn.Write(record); err != nil {
			return written, err
		}
		written += len(record) - 5 // Subtract TLS record header
	}

	return written, nil
}

// readTLSRecord reads a complete TLS record from the connection
func (c *tlsMirrorConn) readTLSRecord() ([]byte, error) {
	// TLS record header is 5 bytes:
	// - Content type (1 byte)
	// - Version (2 bytes)
	// - Length (2 bytes)

	header := make([]byte, 5)
	if _, err := c.Conn.Read(header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[3:5])
	payload := make([]byte, length)
	if _, err := c.Conn.Read(payload); err != nil {
		return nil, err
	}

	return append(header, payload...), nil
}

// extractPayload extracts the actual payload from a TLS record
func (c *tlsMirrorConn) extractPayload(record []byte) ([]byte, error) {
	if len(record) < 5 {
		return nil, fmt.Errorf("record too short")
	}

	contentType := record[0]
	length := binary.BigEndian.Uint16(record[3:5])

	// Validate content type
	switch contentType {
	case 0x14, 0x15, 0x16, 0x17: // ChangeCipherSpec, Alert, Handshake, ApplicationData
		// Valid TLS content types
	default:
		return nil, fmt.Errorf("invalid content type: %d", contentType)
	}

	if int(length) > len(record)-5 {
		return nil, fmt.Errorf("record length mismatch")
	}

	return record[5 : 5+length], nil
}

// wrapInTLSRecords wraps payload in TLS ApplicationData records,
// using mirror config record sizes when available.
func (c *tlsMirrorConn) wrapInTLSRecords(payload []byte) [][]byte {
	maxRecordSize := 16384
	if c.mirror != nil && c.mirror.MaxRecordSize > 0 {
		maxRecordSize = c.mirror.MaxRecordSize
	}

	var records [][]byte
	for len(payload) > 0 {
		size := len(payload)
		if size > maxRecordSize {
			size = maxRecordSize
		}

		// Use bucket sizes from mirror config if available
		if c.mirror != nil && c.mirror.PaddingPolicy == "bucket" && len(c.mirror.RecordSizes) > 0 {
			// Find the smallest bucket that fits
			for _, bs := range c.mirror.RecordSizes {
				if bs >= size {
					size = bs
					break
				}
			}
			if size > len(payload) {
				size = len(payload)
			}
		}

		record := make([]byte, 5+size)
		record[0] = 0x17 // ApplicationData content type
		record[1] = 0x03 // TLS 1.2
		record[2] = 0x03
		binary.BigEndian.PutUint16(record[3:5], uint16(size))
		copy(record[5:], payload[:tlsMin(size, len(payload))])
		// Zero-pad if bucket size exceeds payload (padding)

		records = append(records, record)
		if size >= len(payload) {
			break
		}
		payload = payload[size:]
	}

	return records
}

func tlsMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Ensure tlsMirrorConn implements net.Conn
var _ net.Conn = (*tlsMirrorConn)(nil)

// TLSMirrorRecord represents a TLS record structure
type TLSMirrorRecord struct {
	ContentType uint8
	Version     uint16
	Payload     []byte
}

// Encode encodes a TLS record
func (r *TLSMirrorRecord) Encode() []byte {
	record := make([]byte, 5+len(r.Payload))
	record[0] = r.ContentType
	binary.BigEndian.PutUint16(record[1:3], r.Version)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(r.Payload)))
	copy(record[5:], r.Payload)
	return record
}

// TLSMirrorConfig configures TLSMirror behavior
type TLSMirrorConfig struct {
	MirrorRecords      bool
	RandomizeRecordSize bool
	MinRecordSize      int
	MaxRecordSize      int
	PaddingEnabled     bool
	PaddingMin         int
	PaddingMax         int
}

// DefaultTLSMirrorConfig returns default TLSMirror configuration
func DefaultTLSMirrorConfig() *TLSMirrorConfig {
	return &TLSMirrorConfig{
		MirrorRecords:       true,
		RandomizeRecordSize: true,
		MinRecordSize:       1024,
		MaxRecordSize:       16384,
		PaddingEnabled:      true,
		PaddingMin:          0,
		PaddingMax:          256,
	}
}

// TLSMirrorSession manages a TLSMirror session
type TLSMirrorSession struct {
	SessionID   string
	CreatedAt   time.Time
	LastActive  time.Time
	RecordCount uint64
	ByteCount   uint64
}

// UpdateActivity updates the last active timestamp
func (s *TLSMirrorSession) UpdateActivity() {
	s.LastActive = time.Now()
	s.RecordCount++
}

// AddBytes adds to the byte count
func (s *TLSMirrorSession) AddBytes(n int) {
	s.ByteCount += uint64(n)
}

// IsExpired checks if the session has expired
func (s *TLSMirrorSession) IsExpired(timeout time.Duration) bool {
	return time.Since(s.LastActive) > timeout
}
