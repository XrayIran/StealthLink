package behavior

import (
	"crypto/rand"
	"net"
	"sync"
	"time"
)

// GFWResistTLSOverlay applies TLS-level evasions inspired by anti-DPI projects.
// It performs ClientHello record splitting and optional jittered writes.
type GFWResistTLSOverlay struct {
	EnabledField       bool
	SplitClientHelloAt int
	MinJitter          time.Duration
	MaxJitter          time.Duration
}

func NewGFWResistTLSOverlay() *GFWResistTLSOverlay {
	return &GFWResistTLSOverlay{
		EnabledField:       true,
		SplitClientHelloAt: 32,
		MinJitter:          0,
		MaxJitter:          7 * time.Millisecond,
	}
}

func (o *GFWResistTLSOverlay) Name() string  { return "gfwresist_tls" }
func (o *GFWResistTLSOverlay) Enabled() bool { return o.EnabledField }

func (o *GFWResistTLSOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}
	return &gfwTLSConn{
		Conn:               conn,
		splitClientHelloAt: o.SplitClientHelloAt,
		minJitter:          o.MinJitter,
		maxJitter:          o.MaxJitter,
	}, nil
}

type gfwTLSConn struct {
	net.Conn
	mu                 sync.Mutex
	firstWriteDone     bool
	splitClientHelloAt int
	minJitter          time.Duration
	maxJitter          time.Duration
}

func (c *gfwTLSConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.firstWriteDone {
		c.firstWriteDone = true
		if looksLikeTLSClientHello(p) && c.splitClientHelloAt > 0 && len(p) > c.splitClientHelloAt {
			n1, err := c.Conn.Write(p[:c.splitClientHelloAt])
			if err != nil {
				return n1, err
			}
			sleepRandomRange(c.minJitter, c.maxJitter)
			n2, err := c.Conn.Write(p[c.splitClientHelloAt:])
			return n1 + n2, err
		}
	}

	sleepRandomRange(c.minJitter, c.maxJitter)
	return c.Conn.Write(p)
}

func looksLikeTLSClientHello(p []byte) bool {
	if len(p) < 6 {
		return false
	}
	// TLS record type Handshake (0x16), handshake type ClientHello (0x01).
	return p[0] == 0x16 && p[5] == 0x01
}

func sleepRandomRange(min, max time.Duration) {
	if max <= min || max <= 0 {
		if min > 0 {
			time.Sleep(min)
		}
		return
	}
	delta := max - min
	ns := secureRandUint64(uint64(delta))
	time.Sleep(min + time.Duration(ns))
}

func secureRandUint64(max uint64) uint64 {
	if max == 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// fallback deterministic-ish clock jitter
		return uint64(time.Now().UnixNano()) % max
	}
	v := uint64(0)
	for _, x := range b[:] {
		v = (v << 8) | uint64(x)
	}
	return v % max
}

var _ net.Conn = (*gfwTLSConn)(nil)
