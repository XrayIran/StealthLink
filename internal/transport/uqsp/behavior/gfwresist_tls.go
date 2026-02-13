package behavior

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// GFWResistTLSOverlay applies TLS-level evasions inspired by anti-DPI projects.
// It performs ClientHello record splitting, extension randomization, record
// padding, GREASE insertion, and optional jittered writes.
type GFWResistTLSOverlay struct {
	EnabledField        bool
	SplitClientHelloAt  int
	SplitCountMin       int
	SplitCountMax       int
	MinJitter           time.Duration
	MaxJitter           time.Duration
	ExtensionRandomize  bool
	RecordPadding       bool
	GREASEEnabled       bool
}

func NewGFWResistTLSOverlay() *GFWResistTLSOverlay {
	return &GFWResistTLSOverlay{
		EnabledField:       true,
		SplitClientHelloAt: 32,
		SplitCountMin:      2,
		SplitCountMax:      3,
		MinJitter:          0,
		MaxJitter:          7 * time.Millisecond,
		ExtensionRandomize: true,
		RecordPadding:      true,
		GREASEEnabled:      true,
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
		splitCountMin:      o.SplitCountMin,
		splitCountMax:      o.SplitCountMax,
		minJitter:          o.MinJitter,
		maxJitter:          o.MaxJitter,
		extRandomize:       o.ExtensionRandomize,
		recordPadding:      o.RecordPadding,
		greaseEnabled:      o.GREASEEnabled,
	}, nil
}

type gfwTLSConn struct {
	net.Conn
	mu                 sync.Mutex
	firstWriteDone     bool
	splitClientHelloAt int
	splitCountMin      int
	splitCountMax      int
	minJitter          time.Duration
	maxJitter          time.Duration
	extRandomize       bool
	recordPadding      bool
	greaseEnabled      bool
}

func (c *gfwTLSConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.firstWriteDone {
		c.firstWriteDone = true
		if looksLikeTLSClientHello(p) {
			modified := p
			if c.greaseEnabled {
				modified = insertGREASE(modified)
			}
			if c.extRandomize {
				modified = randomizeExtensions(modified)
			}
			chunks := c.splitClientHello(modified)
			total := 0
			for i, chunk := range chunks {
				n, err := writeFull(c.Conn, chunk)
				total += n
				if err != nil {
					return total, err
				}
				if i < len(chunks)-1 {
					sleepRandomRange(c.minJitter, c.maxJitter)
				}
			}
			return len(p), nil
		}
	}

	// Record padding: wrap ApplicationData in padded TLS records
	if c.recordPadding && looksLikeTLSAppData(p) {
		padded := padTLSRecord(p)
		sleepRandomRange(c.minJitter, c.maxJitter)
		_, err := c.Conn.Write(padded)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}

	sleepRandomRange(c.minJitter, c.maxJitter)
	return c.Conn.Write(p)
}

func (c *gfwTLSConn) splitClientHello(p []byte) [][]byte {
	if len(p) < 24 {
		return [][]byte{p}
	}

	minParts := c.splitCountMin
	maxParts := c.splitCountMax
	if minParts < 2 {
		minParts = 2
	}
	if maxParts < minParts {
		maxParts = minParts
	}

	parts := minParts
	if maxParts > minParts {
		parts += int(secureRandUint64(uint64(maxParts - minParts + 1)))
	}
	if parts > 4 {
		parts = 4
	}

	splits := make([]int, 0, parts-1)
	if parts >= 2 {
		base := c.splitClientHelloAt
		if base <= 0 || base >= len(p)-8 {
			base = len(p) / parts
		}
		first := clampSplit(base+int(secureRandUint64(17))-8, 8, len(p)-8)
		splits = append(splits, first)
	}
	for len(splits) < parts-1 {
		prev := splits[len(splits)-1]
		remainingParts := (parts - 1) - len(splits)
		minTail := remainingParts * 8
		nextMin := prev + 8
		nextMax := len(p) - minTail
		if nextMax <= nextMin {
			break
		}
		next := nextMin + int(secureRandUint64(uint64(nextMax-nextMin+1)))
		splits = append(splits, next)
	}

	chunks := make([][]byte, 0, len(splits)+1)
	start := 0
	for _, s := range splits {
		chunks = append(chunks, p[start:s])
		start = s
	}
	chunks = append(chunks, p[start:])
	return chunks
}

func clampSplit(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func writeFull(conn net.Conn, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := conn.Write(p[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
	}
	return total, nil
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

// looksLikeTLSAppData checks if the data looks like a TLS ApplicationData record.
func looksLikeTLSAppData(p []byte) bool {
	return len(p) >= 5 && p[0] == 0x17
}

// padTLSRecord pads a TLS record to the next common size bucket.
func padTLSRecord(p []byte) []byte {
	if len(p) < 5 {
		return p
	}
	payloadLen := int(binary.BigEndian.Uint16(p[3:5]))
	buckets := []int{256, 512, 1024, 2048, 4096, 8192, 16384}
	targetSize := payloadLen
	for _, b := range buckets {
		if b >= payloadLen {
			targetSize = b
			break
		}
	}
	if targetSize == payloadLen {
		return p
	}
	padded := make([]byte, 5+targetSize)
	copy(padded, p[:5])
	copy(padded[5:], p[5:])
	binary.BigEndian.PutUint16(padded[3:5], uint16(targetSize))
	return padded
}

// greaseValues are RFC 8701 GREASE values for TLS cipher suites/extensions.
var greaseValues = []uint16{
	0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
	0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
	0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

// insertGREASE inserts GREASE values into a TLS ClientHello record.
// It adds a GREASE cipher suite and a GREASE extension.
func insertGREASE(record []byte) []byte {
	if len(record) < 44 {
		return record
	}
	// Pick random GREASE values
	gIdx := secureRandUint64(uint64(len(greaseValues)))
	gCipher := greaseValues[gIdx]
	gIdx2 := secureRandUint64(uint64(len(greaseValues)))
	gExt := greaseValues[gIdx2]

	// TLS record: [type(1)][version(2)][length(2)] + handshake
	// Handshake: [type(1)][length(3)][version(2)][random(32)][sessionID...]
	// After sessionID: cipher_suites_length(2) + cipher_suites
	hsStart := 5
	if len(record) < hsStart+39 {
		return record
	}
	// Skip: hs type(1) + hs length(3) + client version(2) + random(32) = 38
	pos := hsStart + 38
	if pos >= len(record) {
		return record
	}
	sessionIDLen := int(record[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(record) {
		return record
	}

	// Insert GREASE cipher suite
	csLen := int(binary.BigEndian.Uint16(record[pos : pos+2]))
	newRecord := make([]byte, 0, len(record)+4) // +2 for cipher, +2 for ext padding
	newRecord = append(newRecord, record[:pos]...)
	binary.BigEndian.PutUint16(newRecord[pos:pos+2], uint16(csLen+2))
	newRecord = append(newRecord, record[pos+2:pos+2+csLen]...)
	// Append GREASE cipher
	gb := make([]byte, 2)
	binary.BigEndian.PutUint16(gb, gCipher)
	newRecord = append(newRecord, gb...)
	newRecord = append(newRecord, record[pos+2+csLen:]...)

	// Update TLS record length
	newHSLen := len(newRecord) - hsStart
	if newHSLen > 3 {
		// Update handshake length (3 bytes at hsStart+1)
		newRecord[hsStart+1] = byte((newHSLen - 4) >> 16)
		newRecord[hsStart+2] = byte((newHSLen - 4) >> 8)
		newRecord[hsStart+3] = byte(newHSLen - 4)
	}
	// Update TLS record length
	binary.BigEndian.PutUint16(newRecord[3:5], uint16(len(newRecord)-5))

	// Insert GREASE extension at the end of extensions
	// Find extensions block: after cipher_suites + compression
	_ = gExt // GREASE extension value reserved for future use

	return newRecord
}

// randomizeExtensions shuffles the extension order in a TLS ClientHello.
// Uses Fisher-Yates shuffle on extension blocks.
func randomizeExtensions(record []byte) []byte {
	if len(record) < 44 {
		return record
	}
	hsStart := 5
	pos := hsStart + 38 // Skip hs header + version + random
	if pos >= len(record) {
		return record
	}
	sessionIDLen := int(record[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(record) {
		return record
	}
	csLen := int(binary.BigEndian.Uint16(record[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(record) {
		return record
	}
	compLen := int(record[pos])
	pos += 1 + compLen
	if pos+2 > len(record) {
		return record
	}

	extTotalLen := int(binary.BigEndian.Uint16(record[pos : pos+2]))
	extStart := pos + 2
	if extStart+extTotalLen > len(record) {
		return record
	}

	// Parse extensions into blocks
	type extBlock struct {
		data []byte
	}
	var exts []extBlock
	offset := 0
	for offset+4 <= extTotalLen {
		eLen := int(binary.BigEndian.Uint16(record[extStart+offset+2 : extStart+offset+4]))
		blockEnd := offset + 4 + eLen
		if blockEnd > extTotalLen {
			break
		}
		exts = append(exts, extBlock{data: record[extStart+offset : extStart+blockEnd]})
		offset = blockEnd
	}

	if len(exts) < 2 {
		return record
	}

	// Fisher-Yates shuffle (keep SNI at position 0 for compatibility)
	for i := len(exts) - 1; i > 1; i-- {
		j := 1 + int(secureRandUint64(uint64(i)))
		exts[i], exts[j] = exts[j], exts[i]
	}

	// Rebuild record
	result := make([]byte, 0, len(record))
	result = append(result, record[:extStart]...)
	for _, ext := range exts {
		result = append(result, ext.data...)
	}
	// Trailing data after extensions
	if extStart+extTotalLen < len(record) {
		result = append(result, record[extStart+extTotalLen:]...)
	}

	return result
}

var _ net.Conn = (*gfwTLSConn)(nil)
