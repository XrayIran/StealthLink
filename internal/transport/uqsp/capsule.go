package uqsp

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Capsule represents a CONNECT-UDP/IP capsule
type Capsule struct {
	// Type is the capsule type
	Type CapsuleType

	// ContextID is the context identifier (for context-associated capsules)
	ContextID uint64

	// Data is the capsule payload
	Data []byte
}

// Encode encodes the capsule to bytes
func (c *Capsule) Encode() []byte {
	// Variable-length integer encoding for type and length
	typeBytes := encodeVarInt(uint64(c.Type))
	lengthBytes := encodeVarInt(uint64(len(c.Data)))

	buf := make([]byte, len(typeBytes)+len(lengthBytes)+len(c.Data))
	offset := 0

	copy(buf[offset:], typeBytes)
	offset += len(typeBytes)

	copy(buf[offset:], lengthBytes)
	offset += len(lengthBytes)

	copy(buf[offset:], c.Data)

	return buf
}

// Decode decodes the capsule from bytes
func (c *Capsule) Decode(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("capsule data too short")
	}

	offset := 0

	// Decode type
	capsuleType, n, err := decodeVarInt(data[offset:])
	if err != nil {
		return fmt.Errorf("decode capsule type: %w", err)
	}
	c.Type = CapsuleType(capsuleType)
	offset += n

	// Decode length
	length, n, err := decodeVarInt(data[offset:])
	if err != nil {
		return fmt.Errorf("decode capsule length: %w", err)
	}
	offset += n

	// Extract data
	if uint64(len(data)-offset) < length {
		return fmt.Errorf("capsule data truncated")
	}
	c.Data = data[offset : offset+int(length)]

	return nil
}

// DecodeWithContext decodes the capsule with context ID prefix
func (c *Capsule) DecodeWithContext(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("capsule data too short for context")
	}

	c.ContextID = binary.BigEndian.Uint64(data[0:8])
	return c.Decode(data[8:])
}

// EncodeWithContext encodes the capsule with context ID prefix
func (c *Capsule) EncodeWithContext() []byte {
	capsuleData := c.Encode()
	buf := make([]byte, 8+len(capsuleData))
	binary.BigEndian.PutUint64(buf[0:8], c.ContextID)
	copy(buf[8:], capsuleData)
	return buf
}

// CapsuleReader reads capsules from a stream
type CapsuleReader struct {
	reader io.Reader
}

// NewCapsuleReader creates a new capsule reader
func NewCapsuleReader(r io.Reader) *CapsuleReader {
	return &CapsuleReader{reader: r}
}

// ReadCapsule reads a capsule
func (r *CapsuleReader) ReadCapsule() (*Capsule, error) {
	// Read type
	typeBuf := make([]byte, 8)
	if _, err := io.ReadFull(r.reader, typeBuf[:1]); err != nil {
		return nil, err
	}

	// Determine how many more bytes for type
	typeLen := varIntLen(typeBuf[0])
	if typeLen > 1 {
		if _, err := io.ReadFull(r.reader, typeBuf[1:typeLen]); err != nil {
			return nil, err
		}
	}

	capsuleType, _, err := decodeVarInt(typeBuf[:typeLen])
	if err != nil {
		return nil, err
	}

	// Read length
	lenBuf := make([]byte, 8)
	if _, err := io.ReadFull(r.reader, lenBuf[:1]); err != nil {
		return nil, err
	}

	lenLen := varIntLen(lenBuf[0])
	if lenLen > 1 {
		if _, err := io.ReadFull(r.reader, lenBuf[1:lenLen]); err != nil {
			return nil, err
		}
	}

	length, _, err := decodeVarInt(lenBuf[:lenLen])
	if err != nil {
		return nil, err
	}

	// Read data
	data := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r.reader, data); err != nil {
			return nil, err
		}
	}

	return &Capsule{
		Type: CapsuleType(capsuleType),
		Data: data,
	}, nil
}

// CapsuleWriter writes capsules to a stream
type CapsuleWriter struct {
	writer io.Writer
}

// NewCapsuleWriter creates a new capsule writer
func NewCapsuleWriter(w io.Writer) *CapsuleWriter {
	return &CapsuleWriter{writer: w}
}

// WriteCapsule writes a capsule
func (w *CapsuleWriter) WriteCapsule(capsule *Capsule) error {
	data := capsule.Encode()
	_, err := w.writer.Write(data)
	return err
}

// DatagramCapsule represents a UDP datagram capsule (RFC 9298)
type DatagramCapsule struct {
	// ContextID identifies the UDP context
	ContextID uint64

	// Payload is the UDP payload
	Payload []byte
}

// Encode encodes the datagram capsule
func (d *DatagramCapsule) Encode() []byte {
	// Format: Context ID (varint) + Payload
	contextBytes := encodeVarInt(d.ContextID)
	buf := make([]byte, len(contextBytes)+len(d.Payload))
	copy(buf, contextBytes)
	copy(buf[len(contextBytes):], d.Payload)
	return buf
}

// Decode decodes the datagram capsule
func (d *DatagramCapsule) Decode(data []byte) error {
	contextID, n, err := decodeVarInt(data)
	if err != nil {
		return err
	}
	d.ContextID = contextID
	d.Payload = data[n:]
	return nil
}

// AddressAssignCapsule represents an address assignment capsule
type AddressAssignCapsule struct {
	// RequestID identifies the address request
	RequestID uint64

	// IPAddresses are the assigned IP addresses
	IPAddresses []net.IP
}

// Encode encodes the address assign capsule
func (a *AddressAssignCapsule) Encode() []byte {
	// Format: Request ID (varint) + [IP addresses]
	reqIDBytes := encodeVarInt(a.RequestID)

	// Calculate total size
	totalSize := len(reqIDBytes)
	for _, ip := range a.IPAddresses {
		// 1 byte for prefix length + 4 or 16 bytes for IP
		totalSize += 1 + len(ip)
	}

	buf := make([]byte, totalSize)
	offset := 0

	copy(buf[offset:], reqIDBytes)
	offset += len(reqIDBytes)

	for _, ip := range a.IPAddresses {
		buf[offset] = byte(len(ip) * 8) // Prefix length in bits
		offset++
		copy(buf[offset:], ip)
		offset += len(ip)
	}

	return buf
}

// Decode decodes the address assign capsule
func (a *AddressAssignCapsule) Decode(data []byte) error {
	requestID, n, err := decodeVarInt(data)
	if err != nil {
		return err
	}
	a.RequestID = requestID

	offset := n
	a.IPAddresses = nil

	for offset < len(data) {
		if offset >= len(data) {
			break
		}
		prefixLen := int(data[offset])
		offset++

		ipLen := prefixLen / 8
		if offset+ipLen > len(data) {
			return fmt.Errorf("truncated IP address")
		}

		ip := make(net.IP, ipLen)
		copy(ip, data[offset:offset+ipLen])
		offset += ipLen

		a.IPAddresses = append(a.IPAddresses, ip)
	}

	return nil
}

// AddressRequestCapsule represents an address request capsule
type AddressRequestCapsule struct {
	// RequestID identifies this request
	RequestID uint64
}

// Encode encodes the address request capsule
func (a *AddressRequestCapsule) Encode() []byte {
	return encodeVarInt(a.RequestID)
}

// Decode decodes the address request capsule
func (a *AddressRequestCapsule) Decode(data []byte) error {
	requestID, _, err := decodeVarInt(data)
	if err != nil {
		return err
	}
	a.RequestID = requestID
	return nil
}

// RouteAdvertisementCapsule represents a route advertisement capsule
type RouteAdvertisementCapsule struct {
	// Routes are the advertised routes
	Routes []IPRoute
}

// IPRoute represents an IP route
type IPRoute struct {
	// IPPrefix is the IP prefix
	IPPrefix net.IPNet
}

// Encode encodes the route advertisement capsule
func (r *RouteAdvertisementCapsule) Encode() []byte {
	// Calculate total size
	totalSize := 0
	for _, route := range r.Routes {
		totalSize += 1 + len(route.IPPrefix.IP) // prefix len + IP
	}

	buf := make([]byte, totalSize)
	offset := 0

	for _, route := range r.Routes {
		// Calculate prefix length
		ones, _ := route.IPPrefix.Mask.Size()
		buf[offset] = byte(ones)
		offset++

		ipLen := len(route.IPPrefix.IP)
		copy(buf[offset:], route.IPPrefix.IP)
		offset += ipLen
	}

	return buf
}

// Decode decodes the route advertisement capsule
func (r *RouteAdvertisementCapsule) Decode(data []byte) error {
	offset := 0
	r.Routes = nil

	for offset < len(data) {
		if offset >= len(data) {
			break
		}
		prefixLen := int(data[offset])
		offset++

		// Determine IP length from prefix length
		var ipLen int
		if prefixLen <= 32 {
			ipLen = 4 // IPv4
		} else {
			ipLen = 16 // IPv6
		}

		if offset+ipLen > len(data) {
			return fmt.Errorf("truncated route")
		}

		ip := make(net.IP, ipLen)
		copy(ip, data[offset:offset+ipLen])
		offset += ipLen

		// Create mask
		mask := net.CIDRMask(prefixLen, ipLen*8)

		r.Routes = append(r.Routes, IPRoute{
			IPPrefix: net.IPNet{IP: ip, Mask: mask},
		})
	}

	return nil
}

// JunkCapsule represents a junk/padding capsule for AWG-style obfuscation
type JunkCapsule struct {
	// JunkData is the padding data
	JunkData []byte
}

// Encode encodes the junk capsule
func (j *JunkCapsule) Encode() []byte {
	return j.JunkData
}

// Decode decodes the junk capsule
func (j *JunkCapsule) Decode(data []byte) error {
	j.JunkData = data
	return nil
}

// Helper functions for variable-length integer encoding

func encodeVarInt(v uint64) []byte {
	if v < 64 {
		return []byte{byte(v)}
	}
	if v < 16384 {
		return []byte{byte(0x40 | (v >> 8)), byte(v)}
	}
	if v < 1073741824 {
		return []byte{
			byte(0x80 | (v >> 24)),
			byte(v >> 16),
			byte(v >> 8),
			byte(v),
		}
	}
	return []byte{
		byte(0xc0 | (v >> 56)),
		byte(v >> 48),
		byte(v >> 40),
		byte(v >> 32),
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
}

func decodeVarInt(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty data")
	}

	first := data[0]
	prefix := first >> 6
	length := 1 << prefix

	if len(data) < length {
		return 0, 0, fmt.Errorf("insufficient data for varint")
	}

	var value uint64
	switch length {
	case 1:
		value = uint64(first & 0x3f)
	case 2:
		value = uint64(first&0x3f)<<8 | uint64(data[1])
	case 4:
		value = uint64(first&0x3f)<<24 | uint64(data[1])<<16 | uint64(data[2])<<8 | uint64(data[3])
	case 8:
		value = uint64(first&0x3f)<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])
	}

	return value, length, nil
}

func varIntLen(first byte) int {
	prefix := first >> 6
	return 1 << prefix
}
