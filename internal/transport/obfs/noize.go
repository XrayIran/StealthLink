package obfs

import (
	"encoding/base32"
	"fmt"
	"net"
	"stealthlink/internal/transport/kcpbase"
	"strings"

	"github.com/miekg/dns"
)

// NoizeObfuscator implements protocol mimicry obfuscation.
// It makes traffic look like other protocols (HTTP, TLS, DNS, etc.)
type NoizeObfuscator struct {
	mimicType string
	params    map[string]string
}

// NewNoizeObfuscator creates a new Noize obfuscator
func NewNoizeObfuscator(params map[string]string) (Obfuscator, error) {
	mimicType := params["mimic_type"]
	if mimicType == "" {
		mimicType = "tls"
	}

	return &NoizeObfuscator{
		mimicType: mimicType,
		params:    params,
	}, nil
}

// WrapConn wraps a connection with Noize obfuscation
func (n *NoizeObfuscator) WrapConn(conn net.Conn) (net.Conn, error) {
	return &noizeConn{
		Conn:      conn,
		mimicType: n.mimicType,
		params:    n.params,
	}, nil
}

// WrapPacketConn wraps a packet connection with Noize obfuscation
func (n *NoizeObfuscator) WrapPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	return &noizePacketConn{
		PacketConn: conn,
		mimicType:  n.mimicType,
		params:     n.params,
	}, nil
}

// GenerateJunk generates junk data that looks like the mimicked protocol
func (n *NoizeObfuscator) GenerateJunk() []byte {
	switch n.mimicType {
	case "tls":
		return n.generateTLSJunk()
	case "http":
		return n.generateHTTPJunk()
	case "dns":
		return n.generateDNSJunk()
	default:
		return nil
	}
}

// Type returns TypeNoize
func (n *NoizeObfuscator) Type() Type {
	return TypeNoize
}

// Ensure NoizeObfuscator implements Obfuscator
var _ Obfuscator = (*NoizeObfuscator)(nil)

func (n *NoizeObfuscator) generateTLSJunk() []byte {
	// Generate a fake TLS record
	// Content type (1) + Version (2) + Length (2) + Data
	length := 64 + int(kcpbase.FastRandom.Int64n(192)) // 64-256 bytes
	record := make([]byte, 5+length)
	record[0] = 0x17 // Application Data
	record[1] = 0x03 // TLS 1.2
	record[2] = 0x03
	record[3] = byte(length >> 8)
	record[4] = byte(length)
	kcpbase.FastRandom.Read(record[5:])
	return record
}

func (n *NoizeObfuscator) generateHTTPJunk() []byte {
	// Generate a fake HTTP request/response fragment
	templates := [][]byte{
		[]byte("GET /"),
		[]byte("POST /"),
		[]byte("HTTP/1.1 200 OK\r\n"),
		[]byte("Content-Length: "),
		[]byte("Content-Type: "),
	}
	return templates[kcpbase.FastRandom.Int64n(int64(len(templates)))]
}

func (n *NoizeObfuscator) generateDNSJunk() []byte {
	// Generate a fake DNS query header
	// Transaction ID (2) + Flags (2) + Questions (2) + Answer RRs (2) + Authority RRs (2) + Additional RRs (2)
	header := make([]byte, 12)
	kcpbase.FastRandom.Read(header)
	// Set QR=0 (query) and opcode=0
	header[2] = 0x00
	header[3] = 0x00
	// Set QDCOUNT=1
	header[4] = 0x00
	header[5] = 0x01
	return header
}

// noizeConn wraps a net.Conn with protocol mimicry
type noizeConn struct {
	net.Conn
	mimicType string
	params    map[string]string
}

// Read reads data, stripping any mimicry headers
func (c *noizeConn) Read(p []byte) (int, error) {
	// Read actual data (skipping mimicry wrapper)
	return c.Conn.Read(p)
}

// Write writes data with mimicry wrapper
func (c *noizeConn) Write(p []byte) (int, error) {
	// Add mimicry wrapper based on type
	var wrapper []byte
	switch c.mimicType {
	case "tls":
		wrapper = c.wrapTLS(p)
	case "http":
		wrapper = c.wrapHTTP(p)
	case "dns":
		wrapper = c.wrapDNS(p)
	default:
		wrapper = p
	}

	_, err := c.Conn.Write(wrapper)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *noizeConn) wrapTLS(data []byte) []byte {
	// Wrap data in TLS Application Data record
	length := len(data)
	record := make([]byte, 5+length)
	record[0] = 0x17 // Application Data
	record[1] = 0x03 // TLS 1.2
	record[2] = 0x03
	record[3] = byte(length >> 8)
	record[4] = byte(length)
	copy(record[5:], data)
	return record
}

func (c *noizeConn) wrapHTTP(data []byte) []byte {
	// Wrap data in HTTP chunked encoding
	chunk := fmt.Sprintf("%x\r\n", len(data))
	result := make([]byte, 0, len(chunk)+len(data)+2)
	result = append(result, []byte(chunk)...)
	result = append(result, data...)
	result = append(result, []byte("\r\n")...)
	return result
}

func (c *noizeConn) wrapDNS(data []byte) []byte {
	domain := c.params["dns_domain"]
	if domain == "" {
		domain = "stealthlink.local."
	}
	packet := encodeDNSQueryPayload(data, domain)
	if len(packet) == 0 {
		return data
	}
	return packet
}

// noizePacketConn wraps a net.PacketConn with protocol mimicry
type noizePacketConn struct {
	net.PacketConn
	mimicType string
	params    map[string]string
}

// ReadFrom reads a packet, stripping mimicry wrapper
func (c *noizePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, len(p)+256)
	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	// Strip wrapper based on type
	var data []byte
	switch c.mimicType {
	case "dns":
		data = c.unwrapDNS(buf[:n])
	default:
		data = buf[:n]
	}

	return copy(p, data), addr, nil
}

// WriteTo writes a packet with mimicry wrapper
func (c *noizePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Add wrapper based on type
	var wrapper []byte
	switch c.mimicType {
	case "dns":
		wrapper = c.wrapDNSPacket(p)
	default:
		wrapper = p
	}

	_, err = c.PacketConn.WriteTo(wrapper, addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *noizePacketConn) unwrapDNS(data []byte) []byte {
	decoded := decodeDNSQueryPayload(data)
	if len(decoded) == 0 {
		return data
	}
	return decoded
}

func (c *noizePacketConn) wrapDNSPacket(data []byte) []byte {
	domain := c.params["dns_domain"]
	if domain == "" {
		domain = "stealthlink.local."
	}
	packet := encodeDNSQueryPayload(data, domain)
	if len(packet) == 0 {
		return data
	}
	return packet
}

func encodeDNSQueryPayload(data []byte, domain string) []byte {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	enc = strings.ToLower(enc)
	if len(enc) == 0 {
		enc = "a"
	}

	var labels []string
	for len(enc) > 63 {
		labels = append(labels, enc[:63])
		enc = enc[63:]
	}
	labels = append(labels, enc)
	qname := strings.Join(labels, ".")
	if domain != "" {
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}
		qname += "." + domain
	}

	msg := new(dns.Msg)
	msg.Id = uint16(kcpbase.FastRandom.Int64n(1 << 16))
	msg.RecursionDesired = true
	msg.Question = []dns.Question{
		{
			Name:   dns.Fqdn(qname),
			Qtype:  dns.TypeTXT,
			Qclass: dns.ClassINET,
		},
	}

	packet, err := msg.Pack()
	if err != nil {
		return nil
	}
	return packet
}

func decodeDNSQueryPayload(data []byte) []byte {
	var msg dns.Msg
	if err := msg.Unpack(data); err != nil {
		return nil
	}
	if len(msg.Question) == 0 {
		return nil
	}
	name := strings.TrimSuffix(msg.Question[0].Name, ".")
	if name == "" {
		return nil
	}
	parts := strings.Split(name, ".")
	if len(parts) == 0 {
		return nil
	}
	// Keep only base32-compatible labels from the front.
	var payloadLabels []string
	for _, part := range parts {
		ok := true
		for i := 0; i < len(part); i++ {
			ch := part[i]
			if (ch < 'a' || ch > 'z') && (ch < '2' || ch > '7') {
				ok = false
				break
			}
		}
		if !ok {
			break
		}
		payloadLabels = append(payloadLabels, part)
	}
	if len(payloadLabels) == 0 {
		return nil
	}

	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.Join(payloadLabels, "")))
	if err != nil {
		return nil
	}
	return decoded
}
