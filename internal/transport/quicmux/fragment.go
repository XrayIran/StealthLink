// Package quicmux provides QUIC multiplexing with UDP fragmentation support.
// This file implements UDP fragmentation ported from Hysteria.
package quicmux

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Fragmenter splits large UDP packets into smaller fragments
type Fragmenter struct {
	maxDatagramSize uint16
	fragID          uint32
	mu              sync.Mutex
}

// Fragment represents a single fragment of a UDP message
type Fragment struct {
	// Original packet ID
	PacketID uint16

	// Fragment ID (0-indexed within this packet)
	FragID uint8

	// Total number of fragments
	FragCount uint8

	// Fragment payload data
	Data []byte
}

// NewFragmenter creates a new UDP fragmenter
func NewFragmenter(maxDatagramSize uint16) *Fragmenter {
	if maxDatagramSize < 512 {
		maxDatagramSize = 512 // Minimum safe size
	}

	return &Fragmenter{
		maxDatagramSize: maxDatagramSize,
		fragID:          0,
	}
}

// SetMaxDatagramSize updates the maximum datagram size
func (f *Fragmenter) SetMaxDatagramSize(size uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if size >= 512 {
		f.maxDatagramSize = size
	}
}

// Fragment splits a UDP payload into fragments
// Returns nil if the payload fits within maxDatagramSize
func (f *Fragmenter) Fragment(packetID uint16, payload []byte) []*Fragment {
	f.mu.Lock()
	maxSize := f.maxDatagramSize
	f.mu.Unlock()

	// Calculate header overhead (8 bytes for fragment header)
	headerSize := 8
	maxPayloadSize := int(maxSize) - headerSize

	if len(payload) <= maxPayloadSize {
		// No fragmentation needed
		return []*Fragment{
			{
				PacketID:  packetID,
				FragID:    0,
				FragCount: 1,
				Data:      payload,
			},
		}
	}

	// Calculate number of fragments needed
	fragCount := (len(payload) + maxPayloadSize - 1) / maxPayloadSize
	if fragCount > 255 {
		// Too many fragments, truncate
		fragCount = 255
		maxPayloadSize = (len(payload) + 254) / 255
	}

	frags := make([]*Fragment, fragCount)
	offset := 0

	for i := 0; i < fragCount; i++ {
		end := offset + maxPayloadSize
		if end > len(payload) {
			end = len(payload)
		}

		frags[i] = &Fragment{
			PacketID:  packetID,
			FragID:    uint8(i),
			FragCount: uint8(fragCount),
			Data:      payload[offset:end],
		}

		offset = end
	}

	return frags
}

// Marshal serializes a fragment to bytes
func (f *Fragment) Marshal() []byte {
	buf := make([]byte, 8+len(f.Data))

	// Header format:
	// 2 bytes: Packet ID
	// 1 byte:  Fragment ID
	// 1 byte:  Fragment Count
	// 2 bytes: Data Length
	// 2 bytes: Reserved
	// N bytes: Data

	binary.BigEndian.PutUint16(buf[0:2], f.PacketID)
	buf[2] = f.FragID
	buf[3] = f.FragCount
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(f.Data)))
	// buf[6:8] reserved
	copy(buf[8:], f.Data)

	return buf
}

// UnmarshalFragment deserializes a fragment from bytes
func UnmarshalFragment(data []byte) (*Fragment, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("fragment too short: %d bytes", len(data))
	}

	dataLen := binary.BigEndian.Uint16(data[4:6])
	if len(data) < 8+int(dataLen) {
		return nil, fmt.Errorf("fragment truncated: expected %d bytes, got %d", 8+dataLen, len(data))
	}

	return &Fragment{
		PacketID:  binary.BigEndian.Uint16(data[0:2]),
		FragID:    data[2],
		FragCount: data[3],
		Data:      data[8 : 8+dataLen],
	}, nil
}

// IsComplete returns true if this is a complete (non-fragmented) packet
func (f *Fragment) IsComplete() bool {
	return f.FragCount <= 1
}

// Defragger handles reassembly of fragmented UDP packets
type Defragger struct {
	mu sync.Mutex

	// Current packet being reassembled
	packetID uint16
	frags    []*Fragment
	count    uint8
	size     int

	// Timeout for partial packets
	timeout time.Duration
	lastUpdate time.Time
}

// NewDefragger creates a new UDP defragmenter
func NewDefragger() *Defragger {
	return &Defragger{
		timeout:    5 * time.Second,
		lastUpdate: time.Now(),
	}
}

// SetTimeout sets the reassembly timeout
func (d *Defragger) SetTimeout(timeout time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.timeout = timeout
}

// Feed feeds a fragment into the defragmenter
// Returns the reassembled packet if all fragments received, nil otherwise
func (d *Defragger) Feed(frag *Fragment) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check for timeout
	if time.Since(d.lastUpdate) > d.timeout {
		d.reset()
	}
	d.lastUpdate = time.Now()

	// Non-fragmented packet
	if frag.IsComplete() {
		return frag.Data, nil
	}

	// Validate fragment
	if frag.FragID >= frag.FragCount {
		return nil, fmt.Errorf("invalid fragment ID: %d >= %d", frag.FragID, frag.FragCount)
	}

	// Check if this is a new packet
	if frag.PacketID != d.packetID || frag.FragCount != uint8(len(d.frags)) {
		d.resetPacket(frag.PacketID, frag.FragCount)
	}

	// Store fragment if not already received
	if d.frags[frag.FragID] == nil {
		d.frags[frag.FragID] = frag
		d.count++
		d.size += len(frag.Data)

		// Check if complete
		if int(d.count) == len(d.frags) {
			return d.assemble(), nil
		}
	}

	return nil, nil // Waiting for more fragments
}

func (d *Defragger) reset() {
	d.packetID = 0
	d.frags = nil
	d.count = 0
	d.size = 0
}

func (d *Defragger) resetPacket(packetID uint16, fragCount uint8) {
	d.packetID = packetID
	d.frags = make([]*Fragment, fragCount)
	d.count = 0
	d.size = 0
}

func (d *Defragger) assemble() []byte {
	data := make([]byte, d.size)
	offset := 0

	for _, frag := range d.frags {
		if frag == nil {
			continue // Should not happen if count is correct
		}
		offset += copy(data[offset:], frag.Data)
	}

	// Reset for next packet
	d.reset()

	return data
}

// IsComplete returns true if all fragments have been received
func (d *Defragger) IsComplete() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return int(d.count) == len(d.frags) && d.count > 0
}

// FragmentStats holds fragmentation statistics
type FragmentStats struct {
	PacketsFragmented uint64
	PacketsReassembled uint64
	FragmentsSent     uint64
	FragmentsReceived uint64
	DefragTimeouts    uint64
	DefragErrors      uint64
}

// StatsCollector collects fragmentation statistics
type StatsCollector struct {
	mu     sync.RWMutex
	stats  FragmentStats
}

// NewStatsCollector creates a new stats collector
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{}
}

// RecordFragmented records a fragmented packet
func (s *StatsCollector) RecordFragmented(fragCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.PacketsFragmented++
	s.stats.FragmentsSent += uint64(fragCount)
}

// RecordReassembled records a reassembled packet
func (s *StatsCollector) RecordReassembled(fragCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.PacketsReassembled++
	s.stats.FragmentsReceived += uint64(fragCount)
}

// RecordTimeout records a defragmentation timeout
func (s *StatsCollector) RecordTimeout() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.DefragTimeouts++
}

// RecordError records a defragmentation error
func (s *StatsCollector) RecordError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.DefragErrors++
}

// GetStats returns current statistics
func (s *StatsCollector) GetStats() FragmentStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}
