// Package masque implements MASQUE protocol primitives.
//
// It includes capsule encoding utilities used by the transport layer plus a
// standalone CONNECT-{UDP,IP} tunnel mode for local deployments and tests.
// Based on RFC 9298 (CONNECT-UDP) and draft-ietf-masque-connect-ip.
package masque

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config holds MASQUE configuration.
type Config struct {
	// Server endpoint
	ServerAddr string

	// Target to tunnel to (for client)
	Target string

	// Tunnel type: "udp", "tcp", or "ip"
	TunnelType string

	// Authentication
	AuthToken string

	// Custom headers
	Headers map[string]string
}

const (
	headerMasqueProto  = "X-Masque-Protocol"
	headerMasqueTarget = "X-Masque-Target"
)

// Client implements a standalone MASQUE client.
type Client struct {
	config *Config
	conn   net.Conn
}

// NewClient creates a standalone MASQUE client.
func NewClient(config *Config) (*Client, error) {
	return &Client{config: config}, nil
}

// Connect establishes a MASQUE tunnel to the target.
func (c *Client) Connect(ctx context.Context) (net.Conn, error) {
	if c.config == nil {
		return nil, fmt.Errorf("missing MASQUE config")
	}

	tunnelType := strings.ToLower(strings.TrimSpace(c.config.TunnelType))
	if tunnelType == "" {
		tunnelType = "udp"
	}

	target := c.config.Target
	if target == "" {
		target = c.config.ServerAddr
	}

	// If no explicit MASQUE server is configured, fall back to direct dial.
	if strings.TrimSpace(c.config.ServerAddr) == "" {
		d := net.Dialer{}
		network := "tcp"
		if tunnelType == "udp" {
			network = "udp"
		}
		conn, err := d.DialContext(ctx, network, target)
		if err != nil {
			return nil, err
		}
		c.conn = conn
		return conn, nil
	}

	return c.connectViaMASQUE(ctx, target, tunnelType)
}

func (c *Client) connectViaMASQUE(ctx context.Context, target, tunnelType string) (net.Conn, error) {
	d := net.Dialer{}
	baseConn, err := d.DialContext(ctx, "tcp", c.config.ServerAddr)
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Path: "/masque"},
		Host:   c.config.ServerAddr,
		Header: make(http.Header),
	}
	req.Header.Set(headerMasqueProto, "connect-"+tunnelType)
	req.Header.Set(headerMasqueTarget, target)
	req.Header.Set("Capsule-Protocol", "?1")
	if strings.TrimSpace(c.config.AuthToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.config.AuthToken))
	}
	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}

	if err := req.Write(baseConn); err != nil {
		_ = baseConn.Close()
		return nil, err
	}

	br := bufio.NewReader(baseConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = baseConn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = baseConn.Close()
		return nil, fmt.Errorf("masque connect failed: %s", resp.Status)
	}

	buffered := &bufferedConn{Conn: baseConn, br: br}
	if tunnelType == "tcp" || tunnelType == "ip" {
		c.conn = buffered
		return buffered, nil
	}

	framed := &datagramStreamConn{Conn: buffered}
	c.conn = framed
	return framed, nil
}

// Close closes the MASQUE client.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Capsule represents a MASQUE capsule.
type Capsule struct {
	Type    uint64
	Length  uint64
	Payload []byte
}

// Encode encodes a capsule to bytes.
func (c *Capsule) Encode() []byte {
	typeBytes := encodeVarInt(c.Type)
	lenBytes := encodeVarInt(c.Length)

	result := make([]byte, 0, len(typeBytes)+len(lenBytes)+int(c.Length))
	result = append(result, typeBytes...)
	result = append(result, lenBytes...)
	result = append(result, c.Payload...)

	return result
}

// DecodeCapsule decodes a capsule from bytes.
func DecodeCapsule(data []byte) (*Capsule, int, error) {
	if len(data) < 2 {
		return nil, 0, fmt.Errorf("data too short")
	}

	offset := 0

	capsuleType, bytesRead := decodeVarInt(data[offset:])
	offset += bytesRead

	length, bytesRead := decodeVarInt(data[offset:])
	offset += bytesRead

	if len(data) < offset+int(length) {
		return nil, 0, fmt.Errorf("incomplete capsule")
	}

	payload := data[offset : offset+int(length)]
	offset += int(length)

	return &Capsule{
		Type:    capsuleType,
		Length:  length,
		Payload: payload,
	}, offset, nil
}

// encodeVarInt encodes a uint64 as a variable-length integer (QUIC-style).
func encodeVarInt(v uint64) []byte {
	if v < 64 {
		return []byte{byte(v)}
	} else if v < 16384 {
		return []byte{byte(0x40 | (v >> 8)), byte(v)}
	} else if v < 1073741824 {
		return []byte{byte(0x80 | (v >> 24)), byte(v >> 16), byte(v >> 8), byte(v)}
	} else {
		return []byte{byte(0xc0 | (v >> 56)), byte(v >> 48), byte(v >> 40), byte(v >> 32),
			byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
}

// decodeVarInt decodes a variable-length integer.
func decodeVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	first := data[0]
	prefix := (first & 0xc0) >> 6
	length := 1 << prefix

	if len(data) < length {
		return 0, 0
	}

	var result uint64
	result = uint64(first & (0xff >> (2 + prefix)))
	for i := 1; i < length; i++ {
		result = (result << 8) | uint64(data[i])
	}

	return result, length
}

// Capsule types per RFC 9298.
const (
	CapsuleTypeDatagram           = 0x00
	CapsuleTypeAddressAssign      = 0x01
	CapsuleTypeAddressRequest     = 0x02
	CapsuleTypeRouteAdvertisement = 0x03
	CapsuleTypeRouteRequest       = 0x04
	CapsuleTypeClose              = 0x05
)

// UDPCapsule represents a UDP datagram capsule.
type UDPCapsule struct {
	Type            uint64
	ContextID       uint64
	IPVersion       uint8
	PartialChecksum uint16
	Payload         []byte
}

// Encode encodes a UDP capsule.
func (u *UDPCapsule) Encode() []byte {
	var buf []byte

	buf = append(buf, encodeVarInt(u.ContextID)...)

	if u.IPVersion != 0 {
		buf = append(buf, u.IPVersion)
		buf = binary.BigEndian.AppendUint16(buf, u.PartialChecksum)
	}

	buf = append(buf, u.Payload...)

	return buf
}

// ProxyRequest creates an HTTP CONNECT-UDP request URL.
func ProxyRequest(target *url.URL, authToken string) (*url.URL, error) {
	if target == nil {
		return nil, fmt.Errorf("target URL is required")
	}
	if target.Host == "" {
		return nil, fmt.Errorf("target host is required")
	}

	scheme := strings.ToLower(strings.TrimSpace(target.Scheme))
	path := "/.well-known/masque/udp"
	switch scheme {
	case "ip", "connect-ip":
		path = "/.well-known/masque/ip"
	case "udp", "connect-udp", "https", "http", "":
		// default CONNECT-UDP endpoint
	default:
		return nil, fmt.Errorf("unsupported target scheme %q", target.Scheme)
	}

	proxyURL := &url.URL{
		Scheme: "https",
		Host:   target.Host,
		Path:   path,
	}

	q := proxyURL.Query()
	q.Set("target", target.Host)
	if target.Path != "" && target.Path != "/" {
		q.Set("target_path", target.Path)
	}
	if target.RawQuery != "" {
		q.Set("target_query", target.RawQuery)
	}
	if strings.TrimSpace(authToken) != "" {
		q.Set("access_token", strings.TrimSpace(authToken))
	}
	proxyURL.RawQuery = q.Encode()
	return proxyURL, nil
}

// Server implements a standalone MASQUE server.
type Server struct {
	config *Config
	ln     net.Listener
	mu     sync.Mutex
	closed bool
}

// Tunnel represents an active MASQUE tunnel.
type Tunnel struct {
	ID        string
	Type      string
	Target    string
	CreatedAt time.Time
}

// NewServer creates a standalone MASQUE server.
func NewServer(config *Config) (*Server, error) {
	return &Server{config: config}, nil
}

// Listen starts the standalone MASQUE server.
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.closed = false
	s.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			continue
		}
		go s.handleConn(conn)
	}
}

// Close closes the MASQUE server.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}

	if s.config != nil && strings.TrimSpace(s.config.AuthToken) != "" {
		want := "Bearer " + strings.TrimSpace(s.config.AuthToken)
		if req.Header.Get("Authorization") != want {
			_, _ = io.WriteString(conn, "HTTP/1.1 401 Unauthorized\r\n\r\n")
			return
		}
	}

	proto := strings.ToLower(strings.TrimSpace(req.Header.Get(headerMasqueProto)))
	target := strings.TrimSpace(req.Header.Get(headerMasqueTarget))
	if target == "" {
		target = strings.TrimSpace(req.URL.Opaque)
	}
	if target == "" && s.config != nil {
		target = strings.TrimSpace(s.config.Target)
	}
	if target == "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}

	switch proto {
	case "connect-udp":
		s.handleConnectUDP(conn, br, target)
	case "connect-ip":
		// Standalone CONNECT-IP is modeled as full stream forwarding.
		s.handleConnectTCP(conn, br, target)
	default:
		s.handleConnectTCP(conn, br, target)
	}
}

func (s *Server) handleConnectTCP(client net.Conn, br *bufio.Reader, target string) {
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	joinBidirectional(client, br, upstream)
}

func (s *Server) handleConnectUDP(client net.Conn, br *bufio.Reader, target string) {
	upstream, err := net.Dial("udp", target)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	joinDatagramFramed(client, br, upstream)
}

func joinBidirectional(client net.Conn, br *bufio.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		_ = upstream.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
		done <- struct{}{}
	}()
	<-done
}

func joinDatagramFramed(client net.Conn, br *bufio.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			frame, err := readDatagramFrame(br)
			if err != nil {
				return
			}
			if _, err := upstream.Write(frame); err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64*1024)
		for {
			n, err := upstream.Read(buf)
			if err != nil {
				return
			}
			if err := writeDatagramFrame(client, buf[:n]); err != nil {
				return
			}
		}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
}

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.br.Read(p)
}

type datagramStreamConn struct {
	net.Conn
	readBuf []byte
}

func (c *datagramStreamConn) Write(p []byte) (int, error) {
	if len(p) > 0xFFFF {
		return 0, fmt.Errorf("datagram too large: %d", len(p))
	}
	if err := writeDatagramFrame(c.Conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *datagramStreamConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	frame, err := readDatagramFrame(c.Conn)
	if err != nil {
		return 0, err
	}
	n := copy(p, frame)
	if n < len(frame) {
		c.readBuf = append(c.readBuf[:0], frame[n:]...)
	}
	return n, nil
}

func readDatagramFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeDatagramFrame(w io.Writer, payload []byte) error {
	if len(payload) > 0xFFFF {
		return errors.New("frame exceeds uint16")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}
