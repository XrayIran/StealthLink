package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const packetGuardHeaderLen = 12 // 4 bytes magic + 8 bytes cookie

type PacketGuardConfig struct {
	Enabled bool
	Magic   string
	Window  time.Duration
	Skew    int
	Key     string
}

type guardCookies struct {
	win     uint64
	cookies [][8]byte
}

// PacketGuardConn prepends an authenticated header to each packet and drops
// packets without a valid header before higher-level processing.
// It also detects and splits GRO/LRO-coalesced packets.
type PacketGuardConn struct {
	net.PacketConn

	magic         [4]byte
	windowSeconds int64
	skew          int

	key [32]byte

	state   atomic.Value
	bufPool sync.Pool

	// Coalesced packet queue for GRO/LRO split
	pending     []coalescedPart
	pendingLock sync.Mutex

	// Counters
	CoalescedFrames atomic.Int64
	CoalescedParts  atomic.Int64
	OversizeDrops   atomic.Int64
}

type coalescedPart struct {
	data []byte
	addr net.Addr
}

func NewPacketGuardConn(pc net.PacketConn, cfg PacketGuardConfig) net.PacketConn {
	if pc == nil || !cfg.Enabled {
		return pc
	}
	if len(cfg.Magic) != 4 || cfg.Window <= 0 || cfg.Skew < 0 {
		return pc
	}
	if cfg.Key == "" {
		return pc
	}

	g := &PacketGuardConn{
		PacketConn:    pc,
		windowSeconds: int64(cfg.Window.Seconds()),
		skew:          cfg.Skew,
		bufPool: sync.Pool{
			New: func() any { return make([]byte, 0, 2048) },
		},
	}
	copy(g.magic[:], cfg.Magic)

	dk := pbkdf2.Key([]byte(cfg.Key), []byte("stealthlink_guard"), 100_000, 32, sha256.New)
	copy(g.key[:], dk)

	g.getCookies()
	return g
}

func (g *PacketGuardConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Drain any previously split coalesced parts first.
	g.pendingLock.Lock()
	if len(g.pending) > 0 {
		part := g.pending[0]
		g.pending = g.pending[1:]
		g.pendingLock.Unlock()
		n = copy(p, part.data)
		return n, part.addr, nil
	}
	g.pendingLock.Unlock()

	for {
		n, addr, err = g.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}
		if n < packetGuardHeaderLen {
			continue
		}
		if !hmac.Equal(p[0:4], g.magic[:]) {
			continue
		}
		cookies := g.getCookies()
		ok := false
		for i := range cookies.cookies {
			if hmac.Equal(p[4:12], cookies.cookies[i][:]) {
				ok = true
				break
			}
		}
		if !ok {
			continue
		}

		payload := p[:n]

		// Detect GRO/LRO coalesced packets: scan for additional guard headers.
		if next := g.findNextGuard(payload, packetGuardHeaderLen, cookies); next != -1 {
			g.CoalescedFrames.Add(1)
			parts := g.splitCoalesced(payload, cookies)
			if len(parts) > 0 {
				g.CoalescedParts.Add(int64(len(parts)))
				// Return the first part, queue the rest.
				first := parts[0]
				if len(parts) > 1 {
					g.pendingLock.Lock()
					for _, part := range parts[1:] {
						g.pending = append(g.pending, coalescedPart{data: part, addr: addr})
					}
					g.pendingLock.Unlock()
				}
				n = copy(p, first)
				return n, addr, nil
			}
		}

		// Single packet path
		copy(p, p[packetGuardHeaderLen:n])
		return n - packetGuardHeaderLen, addr, nil
	}
}

// findNextGuard scans payload for the next valid guard header starting from offset start.
func (g *PacketGuardConn) findNextGuard(payload []byte, start int, cookies *guardCookies) int {
	if len(payload) < packetGuardHeaderLen || start >= len(payload) {
		return -1
	}
	for i := start; i+packetGuardHeaderLen <= len(payload); i++ {
		if !hmac.Equal(payload[i:i+4], g.magic[:]) {
			continue
		}
		for k := range cookies.cookies {
			if hmac.Equal(payload[i+4:i+12], cookies.cookies[k][:]) {
				return i
			}
		}
	}
	return -1
}

// splitCoalesced splits a coalesced packet into individual payloads (stripped of guard headers).
func (g *PacketGuardConn) splitCoalesced(payload []byte, cookies *guardCookies) [][]byte {
	var parts [][]byte
	for pos := 0; pos+packetGuardHeaderLen <= len(payload); {
		if !hmac.Equal(payload[pos:pos+4], g.magic[:]) {
			pos++
			continue
		}
		ok := false
		for k := range cookies.cookies {
			if hmac.Equal(payload[pos+4:pos+12], cookies.cookies[k][:]) {
				ok = true
				break
			}
		}
		if !ok {
			pos++
			continue
		}
		start := pos + packetGuardHeaderLen
		next := g.findNextGuard(payload, start, cookies)
		end := len(payload)
		if next != -1 {
			end = next
		}
		if end > start {
			part := make([]byte, end-start)
			copy(part, payload[start:end])
			parts = append(parts, part)
		}
		if next == -1 {
			break
		}
		pos = next
	}
	return parts
}

func (g *PacketGuardConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	cookies := g.getCookies()

	buf := g.bufPool.Get().([]byte)
	need := packetGuardHeaderLen + len(p)
	if cap(buf) < need {
		buf = make([]byte, 0, need)
	}
	buf = buf[:need]

	copy(buf[0:4], g.magic[:])
	copy(buf[4:12], cookies.cookies[0][:])
	copy(buf[packetGuardHeaderLen:], p)

	_, err = g.PacketConn.WriteTo(buf, addr)
	buf = buf[:0]
	g.bufPool.Put(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (g *PacketGuardConn) getCookies() *guardCookies {
	nowWin := uint64(time.Now().Unix() / g.windowSeconds)
	if v := g.state.Load(); v != nil {
		c := v.(*guardCookies)
		if c.win == nowWin {
			return c
		}
	}

	out := &guardCookies{
		win:     nowWin,
		cookies: make([][8]byte, g.skew+1),
	}
	for i := 0; i <= g.skew; i++ {
		out.cookies[i] = g.cookie(nowWin - uint64(i))
	}
	g.state.Store(out)
	return out
}

func (g *PacketGuardConn) cookie(win uint64) [8]byte {
	var winb [8]byte
	binary.BigEndian.PutUint64(winb[:], win)

	mac := hmac.New(sha256.New, g.key[:])
	mac.Write(g.magic[:])
	mac.Write(winb[:])
	sum := mac.Sum(nil)

	var out [8]byte
	copy(out[:], sum[:8])
	return out
}
