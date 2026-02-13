package behavior

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"stealthlink/internal/config"
)

type ViolatedTCPMode string

const (
	ViolatedTCPModeMalformed   ViolatedTCPMode = "malformed"
	ViolatedTCPModeNoHandshake ViolatedTCPMode = "no_handshake"
	ViolatedTCPModeRandomFlags ViolatedTCPMode = "random_flags"
	ViolatedTCPModeBrokenSeq   ViolatedTCPMode = "broken_seq"
)

type ViolatedTCPConfig struct {
	Enabled           bool            `yaml:"enabled"`
	Mode              ViolatedTCPMode `yaml:"mode"`
	SeqRandomness     int             `yaml:"seq_randomness"`
	FlagCycling       bool            `yaml:"flag_cycling"`
	WindowJitter      int             `yaml:"window_jitter"`
	OptionRandom      bool            `yaml:"option_random"`
	FakeHTTPEnabled   bool            `yaml:"fake_http_enabled"`
	FakeHTTPHost      string          `yaml:"fake_http_host"`
	FakeHTTPUserAgent string          `yaml:"fake_http_user_agent"`
}

type ViolatedTCPOverlay struct {
	EnabledField bool
	Mode         ViolatedTCPMode
	Config       ViolatedTCPConfig

	mu       sync.Mutex
	conn     net.Conn
	closed   bool
	writeSeq uint32
	readSeq  uint32
}

func NewViolatedTCPOverlay(cfg config.ViolatedTCPBehaviorConfig) *ViolatedTCPOverlay {
	mode := ViolatedTCPMode(cfg.Mode)
	if mode == "" {
		mode = ViolatedTCPModeMalformed
	}
	return &ViolatedTCPOverlay{
		EnabledField: cfg.Enabled,
		Mode:         mode,
		Config: ViolatedTCPConfig{
			Enabled:           cfg.Enabled,
			Mode:              mode,
			SeqRandomness:     cfg.SeqRandomness,
			FlagCycling:       cfg.FlagCycling,
			WindowJitter:      cfg.WindowJitter,
			OptionRandom:      cfg.OptionRandom,
			FakeHTTPEnabled:   cfg.FakeHTTPEnabled,
			FakeHTTPHost:      cfg.FakeHTTPHost,
			FakeHTTPUserAgent: cfg.FakeHTTPUserAgent,
		},
		writeSeq: randomUint32(),
		readSeq:  randomUint32(),
	}
}

func (o *ViolatedTCPOverlay) Name() string {
	return "violated_tcp"
}

func (o *ViolatedTCPOverlay) Enabled() bool {
	return o.EnabledField
}

func (o *ViolatedTCPOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}

	wrapper := &violatedTCPConn{
		Conn:     conn,
		overlay:  o,
		writeSeq: o.writeSeq,
		readSeq:  o.readSeq,
		stopCh:   make(chan struct{}),
	}

	o.mu.Lock()
	o.conn = wrapper
	o.mu.Unlock()

	return wrapper, nil
}

type violatedTCPConn struct {
	net.Conn
	overlay     *ViolatedTCPOverlay
	writeSeq    uint32
	readSeq     uint32
	stopCh      chan struct{}
	mu          sync.Mutex
	readMu      sync.Mutex
	writeMu     sync.Mutex
	closed      bool
	readBuf     []byte
	prefaceSent bool
}

const (
	violatedTCPHeaderSize   = 20
	violatedTCPLengthSize   = 2
	violatedTCPMarker       = 0xFA
	violatedTCPKindData     = 0x00
	violatedTCPKindFakeHTTP = 0x01
)

func (c *violatedTCPConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	for {
		header := make([]byte, violatedTCPHeaderSize+violatedTCPLengthSize)
		if _, err := io.ReadFull(c.Conn, header); err != nil {
			return 0, err
		}

		payloadLen := int(binary.BigEndian.Uint16(header[violatedTCPHeaderSize : violatedTCPHeaderSize+violatedTCPLengthSize]))
		if payloadLen == 0 {
			continue
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(c.Conn, payload); err != nil {
			return 0, err
		}

		kind := byte(violatedTCPKindData)
		if header[0] == violatedTCPMarker {
			kind = header[1]
		}

		c.mu.Lock()
		c.readSeq += uint32(payloadLen)
		c.mu.Unlock()
		if kind == violatedTCPKindFakeHTTP || looksLikeHTTPPreface(payload) {
			continue
		}

		n := copy(p, payload)
		if n < len(payload) {
			c.readBuf = append(c.readBuf[:0], payload[n:]...)
		}
		return n, nil
	}
}

func (c *violatedTCPConn) Write(p []byte) (int, error) {
	if len(p) > 0xFFFF {
		return 0, fmt.Errorf("violated_tcp payload too large: %d", len(p))
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, fmt.Errorf("connection closed")
	}
	c.mu.Unlock()

	if c.overlay.Config.FakeHTTPEnabled && !c.prefaceSent {
		host := strings.TrimSpace(c.overlay.Config.FakeHTTPHost)
		if host == "" {
			host = "cdn.cloudflare.com"
		}
		ua := strings.TrimSpace(c.overlay.Config.FakeHTTPUserAgent)
		if ua == "" {
			ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		}
		preface := buildFakeHTTPRequest(host, ua)
		if err := c.sendFramedPayload(preface, violatedTCPKindFakeHTTP); err != nil {
			return 0, err
		}
		c.prefaceSent = true
	}

	if err := c.sendFramedPayload(p, violatedTCPKindData); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *violatedTCPConn) sendFramedPayload(payload []byte, kind byte) error {
	pseudo := c.encodeFrame(payload)
	frame := make([]byte, violatedTCPHeaderSize+violatedTCPLengthSize+len(payload))
	copy(frame[:violatedTCPHeaderSize], pseudo[:violatedTCPHeaderSize])
	frame[0] = violatedTCPMarker
	frame[1] = kind
	binary.BigEndian.PutUint16(frame[violatedTCPHeaderSize:violatedTCPHeaderSize+violatedTCPLengthSize], uint16(len(payload)))
	copy(frame[violatedTCPHeaderSize+violatedTCPLengthSize:], pseudo[violatedTCPHeaderSize:])
	_, err := c.Conn.Write(frame)
	return err
}

func (c *violatedTCPConn) encodeFrame(payload []byte) []byte {
	switch c.overlay.Mode {
	case ViolatedTCPModeMalformed:
		return c.encodeMalformed(payload)
	case ViolatedTCPModeNoHandshake:
		return c.encodeNoHandshake(payload)
	case ViolatedTCPModeRandomFlags:
		return c.encodeRandomFlags(payload)
	case ViolatedTCPModeBrokenSeq:
		return c.encodeBrokenSeq(payload)
	default:
		return c.encodeMalformed(payload)
	}
}

func (c *violatedTCPConn) encodeMalformed(payload []byte) []byte {
	header := make([]byte, 20)

	header[12] = 0x40 | 0x08

	seq := c.writeSeq
	if c.overlay.Config.SeqRandomness > 0 {
		seq += randomUint32() % uint32(c.overlay.Config.SeqRandomness)
	}
	binary.BigEndian.PutUint32(header[4:8], seq)

	ack := c.readSeq
	binary.BigEndian.PutUint32(header[8:12], ack)

	window := uint16(65535)
	if c.overlay.Config.WindowJitter > 0 {
		window = uint16(65535 - randomUint32()%uint32(c.overlay.Config.WindowJitter))
	}
	binary.BigEndian.PutUint16(header[14:16], window)

	if c.overlay.Config.FlagCycling {
		flags := []byte{0x10, 0x18, 0x08, 0x02}
		header[13] = flags[randomUint32()%4]
	} else {
		header[13] = 0x18
	}

	c.writeSeq += uint32(len(payload))

	frame := make([]byte, len(header)+len(payload))
	copy(frame, header)
	copy(frame[len(header):], payload)

	return frame
}

func (c *violatedTCPConn) encodeNoHandshake(payload []byte) []byte {
	header := make([]byte, 20)

	binary.BigEndian.PutUint32(header[4:8], c.writeSeq)
	binary.BigEndian.PutUint32(header[8:12], 0)
	header[12] = 0x50
	header[13] = 0x18
	binary.BigEndian.PutUint16(header[14:16], 65535)

	c.writeSeq += uint32(len(payload))

	frame := make([]byte, len(header)+len(payload))
	copy(frame, header)
	copy(frame[len(header):], payload)

	return frame
}

func (c *violatedTCPConn) encodeRandomFlags(payload []byte) []byte {
	header := make([]byte, 20)

	binary.BigEndian.PutUint32(header[4:8], c.writeSeq)
	binary.BigEndian.PutUint32(header[8:12], c.readSeq)

	allFlags := []byte{
		0x02,
		0x12,
		0x10,
		0x18,
		0x04,
		0x14,
		0x01,
	}
	header[13] = allFlags[randomUint32()%uint32(len(allFlags))]
	header[12] = 0x50

	binary.BigEndian.PutUint16(header[14:16], uint16(32768+randomUint32()%32768))

	c.writeSeq += uint32(len(payload))

	frame := make([]byte, len(header)+len(payload))
	copy(frame, header)
	copy(frame[len(header):], payload)

	return frame
}

func (c *violatedTCPConn) encodeBrokenSeq(payload []byte) []byte {
	header := make([]byte, 20)

	c.writeSeq += randomUint32() % 10000
	binary.BigEndian.PutUint32(header[4:8], c.writeSeq)
	binary.BigEndian.PutUint32(header[8:12], c.readSeq+randomUint32()%100)
	header[12] = 0x50
	header[13] = 0x18
	binary.BigEndian.PutUint16(header[14:16], 65535)

	c.writeSeq += uint32(len(payload))

	frame := make([]byte, len(header)+len(payload))
	copy(frame, header)
	copy(frame[len(header):], payload)

	return frame
}

func (c *violatedTCPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	close(c.stopCh)

	return c.Conn.Close()
}

func randomUint32() uint32 {
	b := make([]byte, 4)
	rand.Read(b)
	return binary.BigEndian.Uint32(b)
}

func buildFakeHTTPRequest(host, userAgent string) []byte {
	req := "GET / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + userAgent + "\r\n" +
		"Accept: */*\r\n" +
		"\r\n"
	return []byte(req)
}

func looksLikeHTTPPreface(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	s := strings.ToUpper(string(payload[:4]))
	return s == "GET " || s == "POST" || s == "HEAD"
}
