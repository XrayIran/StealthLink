// Package sniff implements protocol sniffing for traffic analysis.
// QUIC sniffing with JA3 fingerprinting based on sing-box.
package sniff

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

// QUICHeader represents a parsed QUIC header.
type QUICHeader struct {
	Version    uint32
	DCID       []byte
	SCID       []byte
	Token      []byte
	Length     int
	PacketType byte
}

// JA3Fingerprint holds JA3 fingerprint data.
type JA3Fingerprint struct {
	Version     string
	CipherSuites []string
	Extensions  []string
	EllipticCurves []string
	ECPointFormats []string
	JA3String   string
	JA3Hash     string
}

// ParseQUIC parses a QUIC packet and extracts information.
func ParseQUIC(data []byte) (*QUICHeader, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("packet too short")
	}

	// Check for QUIC long header (first bit must be 1)
	if data[0]&0x80 == 0 {
		return nil, fmt.Errorf("not a QUIC long header packet")
	}

	header := &QUICHeader{}
	offset := 0

	// Header form and fixed bit
	header.PacketType = (data[offset] >> 4) & 0x03
	offset++

	// Version (4 bytes)
	if len(data) < offset+4 {
		return nil, fmt.Errorf("incomplete version")
	}
	header.Version = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// DCIL (Destination Connection ID Length)
	if len(data) < offset+1 {
		return nil, fmt.Errorf("incomplete DCID length")
	}
	dcidLen := int(data[offset])
	offset++

	// DCID
	if len(data) < offset+dcidLen {
		return nil, fmt.Errorf("incomplete DCID")
	}
	header.DCID = data[offset : offset+dcidLen]
	offset += dcidLen

	// SCIL (Source Connection ID Length)
	if len(data) < offset+1 {
		return nil, fmt.Errorf("incomplete SCID length")
	}
	scidLen := int(data[offset])
	offset++

	// SCID
	if len(data) < offset+scidLen {
		return nil, fmt.Errorf("incomplete SCID")
	}
	header.SCID = data[offset : offset+scidLen]
	offset += scidLen

	// For Initial packets, parse token and length
	if header.PacketType == 0 {
		// Token Length (varint)
		tokenLen, bytesRead := readVarInt(data[offset:])
		offset += bytesRead

		// Token
		if len(data) < offset+int(tokenLen) {
			return nil, fmt.Errorf("incomplete token")
		}
		header.Token = data[offset : offset+int(tokenLen)]
		offset += int(tokenLen)

		// Length (varint)
		length, bytesRead := readVarInt(data[offset:])
		offset += bytesRead
		header.Length = int(length)
	}

	return header, nil
}

// readVarInt reads a QUIC variable-length integer.
func readVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	first := data[0]
	prefix := (first & 0xC0) >> 6
	length := 1 << prefix

	if len(data) < length {
		return 0, 0
	}

	var result uint64
	result = uint64(first & (0xFF >> (2 + prefix)))
	for i := 1; i < length; i++ {
		result = (result << 8) | uint64(data[i])
	}

	return result, length
}

// ExtractSNI extracts SNI from QUIC Initial packet.
func ExtractSNI(data []byte) (string, error) {
	header, err := ParseQUIC(data)
	if err != nil {
		return "", err
	}

	// Only parse Initial packets
	if header.PacketType != 0 {
		return "", fmt.Errorf("not an Initial packet")
	}

	// Find the start of the encrypted payload
	// This requires decryption with the version-specific salt
	// For now, return empty
	return "", fmt.Errorf("SNI extraction requires decryption")
}

// CalculateJA3 calculates JA3 fingerprint from TLS Client Hello.
func CalculateJA3(clientHello []byte) (*JA3Fingerprint, error) {
	fp := &JA3Fingerprint{}

	// Parse Client Hello
	if len(clientHello) < 43 {
		return nil, fmt.Errorf("Client Hello too short")
	}

	offset := 0

	// Skip record layer (5 bytes) if present
	if clientHello[0] == 0x16 {
		offset += 5
	}

	// Handshake type (1 byte) + length (3 bytes)
	offset += 4

	// Client Version (2 bytes)
	version := binary.BigEndian.Uint16(clientHello[offset:])
	fp.Version = fmt.Sprintf("%d", version)
	offset += 2

	// Random (32 bytes)
	offset += 32

	// Session ID Length
	sessionIDLen := int(clientHello[offset])
	offset++
	offset += sessionIDLen

	// Cipher Suites
	if len(clientHello) < offset+2 {
		return nil, fmt.Errorf("incomplete cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(clientHello[offset:]))
	offset += 2

	if len(clientHello) < offset+cipherSuitesLen {
		return nil, fmt.Errorf("incomplete cipher suites")
	}
	for i := 0; i < cipherSuitesLen; i += 2 {
		cs := binary.BigEndian.Uint16(clientHello[offset+i:])
		fp.CipherSuites = append(fp.CipherSuites, fmt.Sprintf("%d", cs))
	}
	offset += cipherSuitesLen

	// Compression Methods
	if len(clientHello) < offset+1 {
		return nil, fmt.Errorf("incomplete compression methods length")
	}
	compMethodsLen := int(clientHello[offset])
	offset++
	offset += compMethodsLen

	// Extensions
	if len(clientHello) < offset+2 {
		return nil, fmt.Errorf("incomplete extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(clientHello[offset:]))
	offset += 2

	extEnd := offset + extensionsLen
	for offset < extEnd && offset+4 <= len(clientHello) {
		extType := binary.BigEndian.Uint16(clientHello[offset:])
		extLen := binary.BigEndian.Uint16(clientHello[offset+2:])
		offset += 4

		fp.Extensions = append(fp.Extensions, fmt.Sprintf("%d", extType))

		// Parse specific extensions
		switch extType {
		case 10: // supported_groups
			if offset+2 <= len(clientHello) {
				groupsLen := binary.BigEndian.Uint16(clientHello[offset:])
				for i := 2; i < int(groupsLen)+2 && i+2 <= int(extLen); i += 2 {
					group := binary.BigEndian.Uint16(clientHello[offset+i:])
					fp.EllipticCurves = append(fp.EllipticCurves, fmt.Sprintf("%d", group))
				}
			}
		case 11: // ec_point_formats
			if offset+1 <= len(clientHello) {
				formatsLen := clientHello[offset]
				for i := 1; i < int(formatsLen)+1 && i < int(extLen); i++ {
					format := clientHello[offset+i]
					fp.ECPointFormats = append(fp.ECPointFormats, fmt.Sprintf("%d", format))
				}
			}
		case 0: // server_name
			// SNI extension
		}

		offset += int(extLen)
	}

	// Build JA3 string
	fp.JA3String = buildJA3String(fp)
	hash := sha256.Sum256([]byte(fp.JA3String))
	fp.JA3Hash = hex.EncodeToString(hash[:])[:32]

	return fp, nil
}

// buildJA3String builds the JA3 string.
func buildJA3String(fp *JA3Fingerprint) string {
	// Format: Version,Ciphers,Extensions,EllipticCurves,ECPointFormats
	result := fp.Version + ","
	result += joinInts(fp.CipherSuites, "-") + ","
	result += joinInts(fp.Extensions, "-") + ","
	result += joinInts(fp.EllipticCurves, "-") + ","
	result += joinInts(fp.ECPointFormats, "-")
	return result
}

func joinInts(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

// Sniffer provides protocol sniffing capabilities.
type Sniffer struct {
	// Protocol detectors
	httpDetector func([]byte) (string, bool)
	tlsDetector  func([]byte) (string, bool)
	quicDetector func([]byte) (string, bool)
}

// NewSniffer creates a new protocol sniffer.
func NewSniffer() *Sniffer {
	return &Sniffer{
		httpDetector: detectHTTP,
		tlsDetector:  detectTLS,
		quicDetector: detectQUIC,
	}
}

// Sniff sniffs the protocol and returns information.
func (s *Sniffer) Sniff(data []byte) (string, map[string]interface{}) {
	// Try QUIC first (UDP)
	if host, ok := s.quicDetector(data); ok {
		return "quic", map[string]interface{}{
			"host": host,
		}
	}

	// Try TLS
	if host, ok := s.tlsDetector(data); ok {
		return "tls", map[string]interface{}{
			"host": host,
		}
	}

	// Try HTTP
	if host, ok := s.httpDetector(data); ok {
		return "http", map[string]interface{}{
			"host": host,
		}
	}

	return "unknown", nil
}

func detectHTTP(data []byte) (string, bool) {
	// Check for HTTP methods
	methods := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("PATCH "),
	}

	for _, method := range methods {
		if bytes.HasPrefix(data, method) {
			// Try to extract Host header
			host := extractHTTPHost(data)
			return host, true
		}
	}

	return "", false
}

func extractHTTPHost(data []byte) string {
	// Find Host header
	hostPrefix := []byte("\r\nHost: ")
	idx := bytes.Index(data, hostPrefix)
	if idx == -1 {
		return ""
	}

	start := idx + len(hostPrefix)
	end := bytes.Index(data[start:], []byte("\r\n"))
	if end == -1 {
		return ""
	}

	return string(data[start : start+end])
}

func detectTLS(data []byte) (string, bool) {
	// Check for TLS handshake
	if len(data) < 5 || data[0] != 0x16 {
		return "", false
	}

	// Parse Client Hello to extract SNI
	sni := extractSNIFromClientHello(data)
	return sni, sni != ""
}

func extractSNIFromClientHello(data []byte) string {
	if len(data) < 43 {
		return ""
	}

	offset := 5 // Skip record header

	// Handshake type + length
	offset += 4

	// Version
	offset += 2

	// Random
	offset += 32

	// Session ID
	sessionIDLen := int(data[offset])
	offset++
	offset += sessionIDLen

	// Cipher Suites
	if len(data) < offset+2 {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2 + cipherSuitesLen

	// Compression Methods
	if len(data) < offset+1 {
		return ""
	}
	compMethodsLen := int(data[offset])
	offset++
	offset += compMethodsLen

	// Extensions
	if len(data) < offset+2 {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	extEnd := offset + extensionsLen

	for offset+4 <= extEnd && offset+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[offset:])
		extLen := binary.BigEndian.Uint16(data[offset+2:])

		if extType == 0 { // SNI extension
			return parseSNIExtension(data[offset+4 : offset+4+int(extLen)])
		}

		offset += 4 + int(extLen)
	}

	return ""
}

func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// SNI list length (validate it fits in remaining data)
	_ = binary.BigEndian.Uint16(data)
	offset := 2

	// Host name type
	hostNameType := data[offset]
	offset++

	if hostNameType != 0 {
		return ""
	}

	// Host name length
	hostNameLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if int(hostNameLen) > len(data)-offset {
		return ""
	}

	return string(data[offset : offset+int(hostNameLen)])
}

func detectQUIC(data []byte) (string, bool) {
	// Check for QUIC long header
	if len(data) < 5 || data[0]&0x80 == 0 {
		return "", false
	}

	// Parse QUIC header
	header, err := ParseQUIC(data)
	if err != nil {
		return "", false
	}

	// Return DCID as identifier
	return hex.EncodeToString(header.DCID), true
}

// DestinationOverride provides destination override based on sniffed protocol.
type DestinationOverride struct {
	Protocol string
	Host     string
	Port     int
	IP       net.IP
}

// SniffedConnection wraps a connection with sniffed protocol info.
type SniffedConnection struct {
	net.Conn
	Protocol string
	Host     string
	Override *DestinationOverride
}
