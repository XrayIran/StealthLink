package udprelay

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Packet types
const (
	PacketTypeData        uint8 = iota // Application data
	PacketTypeFragment                  // Fragment of larger data
	PacketTypeACK                       // Acknowledgment
	PacketTypeHandshake                 // Session establishment
	PacketTypeHandshakeAck              // Handshake acknowledgment
	PacketTypePing                      // Keepalive ping
	PacketTypePong                      // Keepalive pong
	PacketTypeClose                     // Session close
)

// Packet header size (bytes)
const PacketHeaderSize = 20

// PacketHeader represents the header of a UDP relay packet
type PacketHeader struct {
	SessionID SessionID // 8 bytes
	Type      uint8     // 1 byte
	Flags     uint8     // 1 byte
	SeqNum    uint32    // 4 bytes
	AckNum    uint32    // 4 bytes
	Length    uint16    // 2 bytes (payload length)
}

// Encode serializes the header
func (h *PacketHeader) Encode() []byte {
	buf := make([]byte, PacketHeaderSize)
	binary.BigEndian.PutUint64(buf[0:8], uint64(h.SessionID))
	buf[8] = h.Type
	buf[9] = h.Flags
	binary.BigEndian.PutUint32(buf[10:14], h.SeqNum)
	binary.BigEndian.PutUint32(buf[14:18], h.AckNum)
	binary.BigEndian.PutUint16(buf[18:20], h.Length)
	return buf
}

// DecodePacketHeader decodes a packet header
func DecodePacketHeader(data []byte) (*PacketHeader, error) {
	if len(data) < PacketHeaderSize {
		return nil, fmt.Errorf("data too short for header: %d < %d", len(data), PacketHeaderSize)
	}
	return &PacketHeader{
		SessionID: SessionID(binary.BigEndian.Uint64(data[0:8])),
		Type:      data[8],
		Flags:     data[9],
		SeqNum:    binary.BigEndian.Uint32(data[10:14]),
		AckNum:    binary.BigEndian.Uint32(data[14:18]),
		Length:    binary.BigEndian.Uint16(data[18:20]),
	}, nil
}

// Packet represents a complete packet with header and payload
type Packet struct {
	Header  PacketHeader
	Payload []byte
}

// Encode serializes the complete packet
func (p *Packet) Encode() []byte {
	p.Header.Length = uint16(len(p.Payload))
	header := p.Header.Encode()
	return append(header, p.Payload...)
}

// DecodePacket decodes a complete packet
func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < PacketHeaderSize {
		return nil, fmt.Errorf("data too short: %d < %d", len(data), PacketHeaderSize)
	}
	header, err := DecodePacketHeader(data)
	if err != nil {
		return nil, err
	}
	payloadLen := int(header.Length)
	if len(data) < PacketHeaderSize+payloadLen {
		return nil, fmt.Errorf("incomplete packet: have %d, need %d", len(data), PacketHeaderSize+payloadLen)
	}
	return &Packet{
		Header:  *header,
		Payload: data[PacketHeaderSize : PacketHeaderSize+payloadLen],
	}, nil
}

// Fragment header size
const FragmentHeaderSize = 12

// FragmentHeader represents fragmentation metadata
type FragmentHeader struct {
	FragID     uint16 // Fragment group ID
	FragIndex  uint16 // Index within group (0-based)
	FragTotal  uint16 // Total fragments in group
	FragOffset uint32 // Byte offset in original data
}

// Encode encodes the fragment header followed by data
func (fh *FragmentHeader) Encode(data []byte) []byte {
	buf := make([]byte, FragmentHeaderSize+len(data))
	binary.BigEndian.PutUint16(buf[0:2], fh.FragID)
	binary.BigEndian.PutUint16(buf[2:4], fh.FragIndex)
	binary.BigEndian.PutUint16(buf[4:6], fh.FragTotal)
	binary.BigEndian.PutUint32(buf[6:10], fh.FragOffset)
	// 2 bytes reserved
	copy(buf[FragmentHeaderSize:], data)
	return buf
}

// DecodeFragment decodes fragment header and returns it with data
func DecodeFragment(data []byte) (*FragmentHeader, []byte, error) {
	if len(data) < FragmentHeaderSize {
		return nil, nil, fmt.Errorf("fragment too short: %d < %d", len(data), FragmentHeaderSize)
	}
	fh := &FragmentHeader{
		FragID:     binary.BigEndian.Uint16(data[0:2]),
		FragIndex:  binary.BigEndian.Uint16(data[2:4]),
		FragTotal:  binary.BigEndian.Uint16(data[4:6]),
		FragOffset: binary.BigEndian.Uint32(data[6:10]),
	}
	return fh, data[FragmentHeaderSize:], nil
}

// Reassembler handles reassembly of fragmented packets
type Reassembler struct {
	fragments map[uint16]*fragmentGroup
	mu        sync.RWMutex
	timeout   time.Duration
}

type fragmentGroup struct {
	fragID    uint16
	total     uint16
	received  uint16
	fragments map[uint16][]byte
	timestamp time.Time
}

// NewReassembler creates a new reassembler
func NewReassembler(timeout time.Duration) *Reassembler {
	r := &Reassembler{
		fragments: make(map[uint16]*fragmentGroup),
		timeout:   timeout,
	}
	go r.gcLoop()
	return r
}

// AddFragment adds a fragment and returns true if complete
func (r *Reassembler) AddFragment(fh *FragmentHeader, data []byte) (bool, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	group, exists := r.fragments[fh.FragID]
	if !exists {
		group = &fragmentGroup{
			fragID:    fh.FragID,
			total:     fh.FragTotal,
			fragments: make(map[uint16][]byte),
			timestamp: time.Now(),
		}
		r.fragments[fh.FragID] = group
	}

	// Store fragment
	if _, exists := group.fragments[fh.FragIndex]; !exists {
		group.fragments[fh.FragIndex] = data
		group.received++
	}

	// Check if complete
	if group.received == group.total {
		// Reassemble
		reassembled := r.reassemble(group)
		delete(r.fragments, fh.FragID)
		return true, reassembled
	}

	return false, nil
}

// reassemble combines fragments into original data
func (r *Reassembler) reassemble(group *fragmentGroup) []byte {
	// Calculate total size
	var totalSize uint32
	for i := uint16(0); i < group.total; i++ {
		if frag, ok := group.fragments[i]; ok {
			totalSize += uint32(len(frag))
		}
	}

	result := make([]byte, totalSize)
	for i := uint16(0); i < group.total; i++ {
		if frag, ok := group.fragments[i]; ok {
			// Use offset if available, otherwise calculate
			// In practice we'd use the offset from fragment header
			copy(result[uint32(i)*uint32(len(frag)):], frag)
		}
	}

	return result
}

// gcLoop removes expired fragment groups
func (r *Reassembler) gcLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		r.mu.Lock()
		cutoff := time.Now().Add(-r.timeout)
		for id, group := range r.fragments {
			if group.timestamp.Before(cutoff) {
				delete(r.fragments, id)
			}
		}
		r.mu.Unlock()
	}
}

// SlidingWindow implements a sliding window for reliable delivery
type SlidingWindow struct {
	size        int
	sendBase    uint32
	sendNext    uint32
	recvExpected uint32
	mu          sync.RWMutex
	pending     map[uint32]*PendingPacket
}

// PendingPacket represents a packet awaiting acknowledgment
type PendingPacket struct {
	SeqNum    uint32
	Data      []byte
	Timestamp time.Time
	Retries   int
}

// NewSlidingWindow creates a new sliding window
func NewSlidingWindow(size int) *SlidingWindow {
	return &SlidingWindow{
		size:    size,
		pending: make(map[uint32]*PendingPacket),
	}
}

// NextSendSeq returns the next sequence number for sending
func (w *SlidingWindow) NextSendSeq() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	seq := w.sendNext
	w.sendNext++
	return seq
}

// IsExpected checks if a sequence number is within the receive window
func (w *SlidingWindow) IsExpected(seq uint32) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	// Simplified: accept any sequence >= expected
	return seq >= w.recvExpected
}

// ExpectedSeq returns the expected receive sequence number
func (w *SlidingWindow) ExpectedSeq() uint32 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.recvExpected
}

// AdvanceRecv advances the receive window
func (w *SlidingWindow) AdvanceRecv(seq uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if seq >= w.recvExpected {
		w.recvExpected = seq + 1
	}
}

// Ack acknowledges packets up to seq
func (w *SlidingWindow) Ack(seq uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for s := range w.pending {
		if s <= seq {
			delete(w.pending, s)
		}
	}
	if seq > w.sendBase {
		w.sendBase = seq
	}
}

// AddPending adds a packet to pending
func (w *SlidingWindow) AddPending(seq uint32, data []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending[seq] = &PendingPacket{
		SeqNum:    seq,
		Data:      data,
		Timestamp: time.Now(),
	}
}

// GetPending returns pending packets needing retransmit
func (w *SlidingWindow) GetPending(timeout time.Duration) []*PendingPacket {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var result []*PendingPacket
	cutoff := time.Now().Add(-timeout)
	for _, pkt := range w.pending {
		if pkt.Timestamp.Before(cutoff) {
			result = append(result, pkt)
		}
	}
	return result
}

// PendingCount returns number of pending packets
func (w *SlidingWindow) PendingCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.pending)
}

// CurrentSize returns the current window size
func (w *SlidingWindow) CurrentSize() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.size
}

// RTTEstimator estimates round-trip time
type RTTEstimator struct {
	rtt     int64 // nanoseconds
	rttVar  int64 // nanoseconds
	rttMin  int64
	rttMax  int64
	samples int
	mu      sync.RWMutex
}

// NewRTTEstimator creates a new RTT estimator
func NewRTTEstimator() *RTTEstimator {
	return &RTTEstimator{
		rtt:    100 * int64(time.Millisecond),
		rttVar: 50 * int64(time.Millisecond),
		rttMin: 1 << 63 - 1,
	}
}

// Update updates the RTT estimate with a new sample
func (e *RTTEstimator) Update(rtt time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rttNs := rtt.Nanoseconds()
	e.samples++

	// Update min/max
	if rttNs < e.rttMin {
		e.rttMin = rttNs
	}
	if rttNs > e.rttMax {
		e.rttMax = rttNs
	}

	// Jacobson's algorithm
	if e.samples == 1 {
		e.rtt = rttNs
		e.rttVar = rttNs / 2
	} else {
		diff := rttNs - e.rtt
		if diff < 0 {
			diff = -diff
		}
		e.rttVar = (3*e.rttVar + diff) / 4
		e.rtt = (7*e.rtt + rttNs) / 8
	}
}

// RTT returns the current RTT estimate
func (e *RTTEstimator) RTT() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return time.Duration(e.rtt)
}

// RTO returns the retransmission timeout
func (e *RTTEstimator) RTO() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	// RTO = RTT + 4 * RTTVAR
	rto := e.rtt + 4*e.rttVar
	if rto < 1*int64(time.Millisecond) {
		rto = 1 * int64(time.Millisecond)
	}
	if rto > 60*int64(time.Second) {
		rto = 60 * int64(time.Second)
	}
	return time.Duration(rto)
}

// RTTVar returns the RTT variance
func (e *RTTEstimator) RTTVar() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return time.Duration(e.rttVar)
}
