package behavior

import (
	"net"
	"sync"
	"time"
)

// GFWResistTCPOverlay applies TCP-level stream desynchronization patterns.
// It chunks writes with jitter to reduce DPI signature stability.
type GFWResistTCPOverlay struct {
	EnabledField bool
	ChunkMin     int
	ChunkMax     int
	InterChunk   time.Duration
}

func NewGFWResistTCPOverlay() *GFWResistTCPOverlay {
	return &GFWResistTCPOverlay{
		EnabledField: true,
		ChunkMin:     32,
		ChunkMax:     256,
		InterChunk:   2 * time.Millisecond,
	}
}

func (o *GFWResistTCPOverlay) Name() string  { return "gfwresist_tcp" }
func (o *GFWResistTCPOverlay) Enabled() bool { return o.EnabledField }

func (o *GFWResistTCPOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}
	if o.ChunkMin <= 0 {
		o.ChunkMin = 32
	}
	if o.ChunkMax < o.ChunkMin {
		o.ChunkMax = o.ChunkMin
	}
	return &gfwTCPConn{
		Conn:       conn,
		chunkMin:   o.ChunkMin,
		chunkMax:   o.ChunkMax,
		interChunk: o.InterChunk,
	}, nil
}

type gfwTCPConn struct {
	net.Conn
	mu         sync.Mutex
	chunkMin   int
	chunkMax   int
	interChunk time.Duration
}

func (c *gfwTCPConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	total := 0
	for total < len(p) {
		chunk := c.chunkMin
		if c.chunkMax > c.chunkMin {
			chunk += int(secureRandUint64(uint64(c.chunkMax - c.chunkMin + 1)))
		}
		if total+chunk > len(p) {
			chunk = len(p) - total
		}
		n, err := c.Conn.Write(p[total : total+chunk])
		total += n
		if err != nil {
			return total, err
		}
		if c.interChunk > 0 && total < len(p) {
			time.Sleep(c.interChunk)
		}
	}
	return total, nil
}

var _ net.Conn = (*gfwTCPConn)(nil)
