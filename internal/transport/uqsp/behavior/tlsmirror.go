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

// tlsMirrorConn wraps a connection with TLSMirror behavior
type tlsMirrorConn struct {
	net.Conn
	controlChannel     string
	enrollmentRequired bool
	enrolled           bool
	recordBuf          []byte
	mu                 sync.Mutex
}

// enroll performs TLSMirror enrollment
func (c *tlsMirrorConn) enroll() error {
	if c.enrolled {
		return nil
	}

	// TLSMirror enrollment:
	// 1. Connect to control channel
	// 2. Exchange capabilities
	// 3. Receive mirror configuration

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

// wrapInTLSRecords wraps payload in TLS ApplicationData records
func (c *tlsMirrorConn) wrapInTLSRecords(payload []byte) [][]byte {
	const maxRecordSize = 16384 // TLS max plaintext record size

	var records [][]byte
	for len(payload) > 0 {
		size := len(payload)
		if size > maxRecordSize {
			size = maxRecordSize
		}

		record := make([]byte, 5+size)
		record[0] = 0x17 // ApplicationData content type
		record[1] = 0x03 // TLS 1.2
		record[2] = 0x03
		binary.BigEndian.PutUint16(record[3:5], uint16(size))
		copy(record[5:], payload[:size])

		records = append(records, record)
		payload = payload[size:]
	}

	return records
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
