package behavior

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"stealthlink/internal/config"
)

const (
	anyTLSMagic0  = byte(0x41) // 'A'
	anyTLSMagic1  = byte(0x54) // 'T'
	anyTLSVersion = byte(0x01)
	anyTLSHdrLen  = 16
	anyTLSTagLen  = 8
)

// AnyTLSOverlay adds authenticated framing with randomized padding to reduce
// transport fingerprintability behind TLS-like carriers.
type AnyTLSOverlay struct {
	EnabledField bool
	Password     string
	PaddingMin   int
	PaddingMax   int
}

func NewAnyTLSOverlay(cfg config.AnyTLSBehaviorConfig) *AnyTLSOverlay {
	return &AnyTLSOverlay{
		EnabledField: cfg.Enabled,
		Password:     cfg.Password,
		PaddingMin:   cfg.PaddingMin,
		PaddingMax:   cfg.PaddingMax,
	}
}

func (o *AnyTLSOverlay) Name() string { return "anytls" }

func (o *AnyTLSOverlay) Enabled() bool { return o.EnabledField }

func (o *AnyTLSOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}
	if o.Password == "" {
		return nil, fmt.Errorf("anytls password is required")
	}
	minPad := o.PaddingMin
	maxPad := o.PaddingMax
	if minPad < 0 {
		minPad = 0
	}
	if maxPad < minPad {
		maxPad = minPad
	}
	return &anyTLSConn{
		Conn:       conn,
		macKey:     []byte(o.Password),
		paddingMin: minPad,
		paddingMax: maxPad,
	}, nil
}

type anyTLSConn struct {
	net.Conn

	macKey     []byte
	paddingMin int
	paddingMax int

	readMu  sync.Mutex
	writeMu sync.Mutex
	readBuf []byte
}

func (c *anyTLSConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	header := make([]byte, anyTLSHdrLen)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}
	if header[0] != anyTLSMagic0 || header[1] != anyTLSMagic1 || header[2] != anyTLSVersion {
		return 0, fmt.Errorf("invalid anytls frame header")
	}

	payloadLen := int(binary.BigEndian.Uint16(header[4:6]))
	padLen := int(binary.BigEndian.Uint16(header[6:8]))
	if payloadLen < 0 || padLen < 0 || payloadLen+padLen > 65535 {
		return 0, fmt.Errorf("invalid anytls lengths")
	}

	expectedTag := header[8 : 8+anyTLSTagLen]
	body := make([]byte, payloadLen+padLen)
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return 0, err
	}

	mac := hmac.New(sha256.New, c.macKey)
	mac.Write(header[:8])
	mac.Write(body)
	sum := mac.Sum(nil)
	if subtle.ConstantTimeCompare(expectedTag, sum[:anyTLSTagLen]) != 1 {
		return 0, fmt.Errorf("anytls frame authentication failed")
	}

	payload := body[:payloadLen]
	n := copy(p, payload)
	if n < len(payload) {
		c.readBuf = append(c.readBuf[:0], payload[n:]...)
	}
	return n, nil
}

func (c *anyTLSConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 65535 {
			chunk = chunk[:65535]
		}
		padLen, err := c.randPadding()
		if err != nil {
			return total, err
		}
		padding := make([]byte, padLen)
		if padLen > 0 {
			if _, err := rand.Read(padding); err != nil {
				return total, err
			}
		}

		header := make([]byte, anyTLSHdrLen)
		header[0] = anyTLSMagic0
		header[1] = anyTLSMagic1
		header[2] = anyTLSVersion
		header[3] = 0 // reserved flags
		binary.BigEndian.PutUint16(header[4:6], uint16(len(chunk)))
		binary.BigEndian.PutUint16(header[6:8], uint16(padLen))

		mac := hmac.New(sha256.New, c.macKey)
		mac.Write(header[:8])
		mac.Write(chunk)
		mac.Write(padding)
		sum := mac.Sum(nil)
		copy(header[8:8+anyTLSTagLen], sum[:anyTLSTagLen])

		if _, err := c.Conn.Write(header); err != nil {
			return total, err
		}
		if _, err := c.Conn.Write(chunk); err != nil {
			return total, err
		}
		if padLen > 0 {
			if _, err := c.Conn.Write(padding); err != nil {
				return total, err
			}
		}

		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *anyTLSConn) randPadding() (int, error) {
	if c.paddingMax <= c.paddingMin {
		return c.paddingMin, nil
	}
	span := c.paddingMax - c.paddingMin + 1
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return c.paddingMin + int(binary.BigEndian.Uint16(b[:]))%span, nil
}
