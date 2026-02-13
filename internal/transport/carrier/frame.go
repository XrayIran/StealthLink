package carrier

import (
	"encoding/binary"
	"fmt"
)

// StealthLink Frame Format
//
// This is the common frame format used across all five StealthLink modes (4a-4e).
// Each mode wraps this frame in mode-specific obfuscation:
//   - Mode 4a: HTTP/2 DATA frame
//   - Mode 4b: FakeTCP packet with TCP header
//   - Mode 4c: TLS Application Data record
//   - Mode 4d: QUIC STREAM frame
//   - Mode 4e: HTTP/2 DATA frame with ICMP mux header
//
// Frame Structure (16-byte header + variable padding + variable payload):
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Version    |     Type      |            Flags              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Connection ID                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Stream ID                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Padding Length        |         Payload Length        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Padding (variable)                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Payload (variable)                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Field Descriptions:
//
// Version (1 byte):
//   Protocol version number. Current version is 0x01.
//   Allows for future protocol evolution while maintaining backward compatibility.
//
// Type (1 byte):
//   Frame type indicator:
//     0x01 = DATA: Contains application payload data
//     0x02 = CONTROL: Contains control/signaling information
//     0x03 = COVER: Cover traffic (dummy data for traffic analysis resistance)
//
// Flags (2 bytes, big-endian):
//   Bit flags for frame properties:
//     0x0001 = RELIABLE: Frame requires reliable delivery
//     0x0002 = ENCRYPTED: Payload is encrypted
//     0x0004 = COMPRESSED: Payload is compressed
//     0x0008-0xFFFF: Reserved for future use
//
// Connection ID (4 bytes, big-endian):
//   Unique identifier for the connection.
//   Used to multiplex multiple logical connections over a single carrier.
//   Generated randomly at connection establishment.
//
// Stream ID (4 bytes, big-endian):
//   Unique identifier for the stream within the connection.
//   Used to multiplex multiple streams within a single connection.
//   Stream ID 0 is reserved for connection-level control frames.
//
// Padding Length (2 bytes, big-endian):
//   Length of the padding field in bytes (0-65535).
//   Padding is used for traffic analysis resistance and alignment.
//
// Payload Length (2 bytes, big-endian):
//   Length of the payload field in bytes (0-65535).
//   The actual application data or control information.
//
// Padding (variable):
//   Random padding bytes for traffic analysis resistance.
//   Length specified by Padding Length field.
//   Should be filled with cryptographically random data.
//
// Payload (variable):
//   The actual frame data (application payload or control information).
//   Length specified by Payload Length field.
//   May be encrypted and/or compressed based on Flags.

const (
	// FrameHeaderSize is the size of the StealthLink frame header in bytes.
	FrameHeaderSize = 16

	// FrameVersion is the current protocol version.
	FrameVersion = 0x01

	// Frame type constants
	FrameTypeData    = 0x01 // DATA frame
	FrameTypeControl = 0x02 // CONTROL frame
	FrameTypeCover   = 0x03 // COVER traffic frame

	// Frame flag constants
	FrameFlagReliable   = 0x0001 // Requires reliable delivery
	FrameFlagEncrypted  = 0x0002 // Payload is encrypted
	FrameFlagCompressed = 0x0004 // Payload is compressed

	// MaxFrameSize is the maximum total frame size (header + padding + payload).
	// This is based on typical MTU (1500) minus IP/UDP overhead.
	MaxFrameSize = 1400

	// MaxPaddingLength is the maximum padding length.
	MaxPaddingLength = 65535

	// MaxPayloadLength is the maximum payload length.
	MaxPayloadLength = 65535
)

// Frame represents a StealthLink protocol frame.
type Frame struct {
	Version      uint8  // Protocol version
	Type         uint8  // Frame type (DATA, CONTROL, COVER)
	Flags        uint16 // Frame flags
	ConnectionID uint32 // Connection identifier
	StreamID     uint32 // Stream identifier
	Padding      []byte // Padding data
	Payload      []byte // Payload data
}

// Marshal encodes the frame into wire format.
// Returns the encoded bytes or an error if the frame is invalid.
func (f *Frame) Marshal() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("invalid frame: %w", err)
	}

	paddingLen := len(f.Padding)
	payloadLen := len(f.Payload)
	totalLen := FrameHeaderSize + paddingLen + payloadLen

	buf := make([]byte, totalLen)

	// Encode header
	buf[0] = f.Version
	buf[1] = f.Type
	binary.BigEndian.PutUint16(buf[2:4], f.Flags)
	binary.BigEndian.PutUint32(buf[4:8], f.ConnectionID)
	binary.BigEndian.PutUint32(buf[8:12], f.StreamID)
	binary.BigEndian.PutUint16(buf[12:14], uint16(paddingLen))
	binary.BigEndian.PutUint16(buf[14:16], uint16(payloadLen))

	// Copy padding and payload
	copy(buf[FrameHeaderSize:], f.Padding)
	copy(buf[FrameHeaderSize+paddingLen:], f.Payload)

	return buf, nil
}

// Unmarshal decodes a frame from wire format.
// Returns an error if the data is invalid or truncated.
func (f *Frame) Unmarshal(data []byte) error {
	if len(data) < FrameHeaderSize {
		return fmt.Errorf("frame too short: got %d bytes, need at least %d", len(data), FrameHeaderSize)
	}

	// Decode header
	f.Version = data[0]
	f.Type = data[1]
	f.Flags = binary.BigEndian.Uint16(data[2:4])
	f.ConnectionID = binary.BigEndian.Uint32(data[4:8])
	f.StreamID = binary.BigEndian.Uint32(data[8:12])
	paddingLen := binary.BigEndian.Uint16(data[12:14])
	payloadLen := binary.BigEndian.Uint16(data[14:16])

	// Validate lengths
	expectedLen := FrameHeaderSize + int(paddingLen) + int(payloadLen)
	if len(data) < expectedLen {
		return fmt.Errorf("frame truncated: got %d bytes, expected %d", len(data), expectedLen)
	}

	// Extract padding and payload
	paddingStart := FrameHeaderSize
	paddingEnd := paddingStart + int(paddingLen)
	payloadStart := paddingEnd
	payloadEnd := payloadStart + int(payloadLen)

	f.Padding = data[paddingStart:paddingEnd]
	f.Payload = data[payloadStart:payloadEnd]

	return f.Validate()
}

// Validate checks if the frame is valid.
func (f *Frame) Validate() error {
	if f.Version != FrameVersion {
		return fmt.Errorf("unsupported version: %d", f.Version)
	}

	if f.Type != FrameTypeData && f.Type != FrameTypeControl && f.Type != FrameTypeCover {
		return fmt.Errorf("invalid frame type: %d", f.Type)
	}

	if len(f.Padding) > MaxPaddingLength {
		return fmt.Errorf("padding too long: %d bytes (max %d)", len(f.Padding), MaxPaddingLength)
	}

	if len(f.Payload) > MaxPayloadLength {
		return fmt.Errorf("payload too long: %d bytes (max %d)", len(f.Payload), MaxPayloadLength)
	}

	totalSize := FrameHeaderSize + len(f.Padding) + len(f.Payload)
	if totalSize > MaxFrameSize {
		return fmt.Errorf("frame too large: %d bytes (max %d)", totalSize, MaxFrameSize)
	}

	return nil
}

// Size returns the total size of the frame in bytes (header + padding + payload).
func (f *Frame) Size() int {
	return FrameHeaderSize + len(f.Padding) + len(f.Payload)
}

// HasFlag checks if a specific flag is set.
func (f *Frame) HasFlag(flag uint16) bool {
	return (f.Flags & flag) != 0
}

// SetFlag sets a specific flag.
func (f *Frame) SetFlag(flag uint16) {
	f.Flags |= flag
}

// ClearFlag clears a specific flag.
func (f *Frame) ClearFlag(flag uint16) {
	f.Flags &^= flag
}
