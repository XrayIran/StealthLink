package uqsp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
)

// DatagramFragment represents a fragment of a larger datagram
type DatagramFragment struct {
	// SessionID identifies the UDP session
	SessionID uint32

	// FragmentID identifies this fragment (unique per original datagram)
	FragmentID uint16

	// FragmentIndex is the index of this fragment (0-based)
	FragmentIndex uint8

	// TotalFragments is the total number of fragments
	TotalFragments uint8

	// Data is the fragment payload
	Data []byte
}

const (
	// MaxFragmentSize is the maximum size of a fragment payload
	MaxFragmentSize = 1200

	// FragmentHeaderSize is the size of the fragment header
	FragmentHeaderSize = 12
)

// Encode encodes the fragment to bytes
func (f *DatagramFragment) Encode() []byte {
	buf := make([]byte, FragmentHeaderSize+len(f.Data))
	binary.BigEndian.PutUint32(buf[0:4], f.SessionID)
	binary.BigEndian.PutUint16(buf[4:6], f.FragmentID)
	buf[6] = f.FragmentIndex
	buf[7] = f.TotalFragments
	// Reserved bytes 8-11 for future use
	binary.BigEndian.PutUint32(buf[8:12], 0)
	copy(buf[FragmentHeaderSize:], f.Data)
	return buf
}

// Decode decodes the fragment from bytes
func (f *DatagramFragment) Decode(data []byte) error {
	if len(data) < FragmentHeaderSize {
		return fmt.Errorf("fragment data too short: %d bytes", len(data))
	}
	f.SessionID = binary.BigEndian.Uint32(data[0:4])
	f.FragmentID = binary.BigEndian.Uint16(data[4:6])
	f.FragmentIndex = data[6]
	f.TotalFragments = data[7]
	// Skip reserved bytes 8-11
	f.Data = data[FragmentHeaderSize:]
	return nil
}

// DatagramReassembler reassembles fragmented datagrams
type DatagramReassembler struct {
	// fragments maps sessionID+fragmentID to reassembly buckets
	fragments map[uint64]*datagramReassemblyBucket
	mu        sync.Mutex

	timeout      time.Duration
	maxBytes     int
	currentBytes int
}

// NewDatagramReassembler creates a new datagram reassembler
func NewDatagramReassembler() *DatagramReassembler {
	return NewDatagramReassemblerWithConfig(30*time.Second, 4<<20)
}

// NewDatagramReassemblerWithConfig creates a new datagram reassembler with
// explicit timeout and memory cap.
func NewDatagramReassemblerWithConfig(timeout time.Duration, maxBytes int) *DatagramReassembler {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if maxBytes <= 0 {
		maxBytes = 4 << 20 // 4 MiB aggregate fragment memory cap
	}
	return &DatagramReassembler{
		fragments: make(map[uint64]*datagramReassemblyBucket),
		timeout:   timeout,
		maxBytes:  maxBytes,
	}
}

// AddFragment adds a fragment and attempts reassembly
func (r *DatagramReassembler) AddFragment(fragment *DatagramFragment) ([]byte, error) {
	if fragment == nil {
		return nil, fmt.Errorf("nil fragment")
	}
	if fragment.TotalFragments == 0 {
		return nil, fmt.Errorf("invalid total fragments: 0")
	}
	if fragment.FragmentIndex >= fragment.TotalFragments {
		return nil, fmt.Errorf("invalid fragment index %d for total %d", fragment.FragmentIndex, fragment.TotalFragments)
	}

	key := r.makeKey(fragment.SessionID, fragment.FragmentID)
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupExpiredLocked(now)

	bucket, ok := r.fragments[key]
	if !ok {
		bucket = &datagramReassemblyBucket{
			total:     fragment.TotalFragments,
			fragments: make(map[uint8][]byte, fragment.TotalFragments),
			updatedAt: now,
		}
		r.fragments[key] = bucket
	}
	if bucket.total != fragment.TotalFragments {
		return nil, fmt.Errorf("fragment total mismatch: got %d want %d", fragment.TotalFragments, bucket.total)
	}

	if _, exists := bucket.fragments[fragment.FragmentIndex]; !exists {
		cp := make([]byte, len(fragment.Data))
		copy(cp, fragment.Data)

		if err := r.reserveBytesLocked(len(cp)); err != nil {
			return nil, err
		}

		bucket.fragments[fragment.FragmentIndex] = cp
		bucket.received++
		bucket.bytes += len(cp)
		r.currentBytes += len(cp)
	}
	bucket.updatedAt = now

	// Check if complete.
	if bucket.received >= bucket.total {
		return r.reassembleLocked(key)
	}

	return nil, nil // Not complete yet
}

func (r *DatagramReassembler) reserveBytesLocked(size int) error {
	if size < 0 {
		return fmt.Errorf("invalid fragment size %d", size)
	}
	if size > r.maxBytes {
		return fmt.Errorf("fragment size %d exceeds reassembly memory cap %d", size, r.maxBytes)
	}
	for r.currentBytes+size > r.maxBytes {
		if !r.evictOldestLocked() {
			return fmt.Errorf("reassembly memory cap exceeded")
		}
	}
	return nil
}

func (r *DatagramReassembler) evictOldestLocked() bool {
	var (
		oldestKey uint64
		oldestAt  time.Time
		found     bool
	)
	for key, bucket := range r.fragments {
		if !found || bucket.updatedAt.Before(oldestAt) {
			found = true
			oldestKey = key
			oldestAt = bucket.updatedAt
		}
	}
	if !found {
		return false
	}
	bucket := r.fragments[oldestKey]
	r.currentBytes -= bucket.bytes
	delete(r.fragments, oldestKey)
	metrics.IncUQSPReassemblyEviction()
	return true
}

func (r *DatagramReassembler) cleanupExpiredLocked(now time.Time) {
	for key, bucket := range r.fragments {
		if now.Sub(bucket.updatedAt) > r.timeout {
			r.currentBytes -= bucket.bytes
			delete(r.fragments, key)
			metrics.IncUQSPReassemblyEviction()
		}
	}
	if r.currentBytes < 0 {
		r.currentBytes = 0
	}
}

// reassembleLocked reassembles fragments into a complete datagram.
// Caller must hold r.mu.
func (r *DatagramReassembler) reassembleLocked(key uint64) ([]byte, error) {
	bucket, ok := r.fragments[key]
	if !ok {
		return nil, fmt.Errorf("reassembly bucket not found")
	}
	delete(r.fragments, key)
	r.currentBytes -= bucket.bytes
	if r.currentBytes < 0 {
		r.currentBytes = 0
	}

	if bucket.received < bucket.total {
		return nil, fmt.Errorf("incomplete fragments")
	}

	totalSize := 0
	for i := uint8(0); i < bucket.total; i++ {
		payload, ok := bucket.fragments[i]
		if !ok {
			return nil, fmt.Errorf("missing fragment %d", i)
		}
		totalSize += len(payload)
	}

	result := make([]byte, 0, totalSize)
	for i := uint8(0); i < bucket.total; i++ {
		result = append(result, bucket.fragments[i]...)
	}
	return result, nil
}

// makeKey creates a key from session ID and fragment ID
func (r *DatagramReassembler) makeKey(sessionID uint32, fragmentID uint16) uint64 {
	return (uint64(sessionID) << 16) | uint64(fragmentID)
}

type datagramReassemblyBucket struct {
	total     uint8
	received  uint8
	fragments map[uint8][]byte
	bytes     int
	updatedAt time.Time
}

// DatagramFragmenter fragments large datagrams.
// When PaddingMin/PaddingMax are set, random padding is appended to the
// original datagram *before* fragmentation so that all fragments carry
// the same padding policy and reassembly strips it cleanly.
type DatagramFragmenter struct {
	// nextFragmentID is the next fragment ID to use
	nextID uint16
	mu     sync.Mutex

	PaddingMin int
	PaddingMax int
}

// NewDatagramFragmenter creates a new datagram fragmenter
func NewDatagramFragmenter() *DatagramFragmenter {
	return &DatagramFragmenter{
		nextID: 1,
	}
}

// Fragment fragments a datagram into smaller pieces.
// If padding is configured, it is applied to the whole datagram before
// fragmentation so reassembly can strip it using the original length.
func (f *DatagramFragmenter) Fragment(sessionID uint32, data []byte) []*DatagramFragment {
	// Apply padding before fragmentation
	if f.PaddingMax > 0 && f.PaddingMax >= f.PaddingMin {
		padLen := f.PaddingMin
		delta := f.PaddingMax - f.PaddingMin
		if delta > 0 {
			var b [2]byte
			rand.Read(b[:])
			padLen += int(binary.BigEndian.Uint16(b[:])) % (delta + 1)
		}
		if padLen > 0 {
			// Prepend 2-byte original length header + data + padding
			padded := make([]byte, 2+len(data)+padLen)
			binary.BigEndian.PutUint16(padded[0:2], uint16(len(data)))
			copy(padded[2:], data)
			// Padding bytes remain zero
			data = padded
		}
	}
	if len(data) <= MaxFragmentSize {
		// No fragmentation needed
		return []*DatagramFragment{
			{
				SessionID:      sessionID,
				FragmentID:     f.getNextFragmentID(),
				FragmentIndex:  0,
				TotalFragments: 1,
				Data:           data,
			},
		}
	}

	// Calculate number of fragments
	totalFragments := (len(data) + MaxFragmentSize - 1) / MaxFragmentSize
	if totalFragments > 255 {
		// Too many fragments, truncate data
		totalFragments = 255
		data = data[:MaxFragmentSize*255]
	}

	fragments := make([]*DatagramFragment, totalFragments)
	fragmentID := f.getNextFragmentID()

	for i := 0; i < totalFragments; i++ {
		start := i * MaxFragmentSize
		end := start + MaxFragmentSize
		if end > len(data) {
			end = len(data)
		}

		fragments[i] = &DatagramFragment{
			SessionID:      sessionID,
			FragmentID:     fragmentID,
			FragmentIndex:  uint8(i),
			TotalFragments: uint8(totalFragments),
			Data:           data[start:end],
		}
	}

	return fragments
}

// getNextFragmentID returns the next fragment ID
func (f *DatagramFragmenter) getNextFragmentID() uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextID
	f.nextID++
	if f.nextID == 0 {
		f.nextID = 1 // Skip 0
	}
	return id
}

// UDPRelay handles UDP relay over UQSP
type UDPRelay struct {
	// sessionManager is the parent session manager
	sessionManager *SessionManager

	// fragmenter fragments outgoing datagrams
	fragmenter *DatagramFragmenter

	// reassembler reassembles incoming fragments
	reassembler *DatagramReassembler

	// localConn is the local UDP connection for relay
	localConn *net.UDPConn

	// relayAddr is the relay target address
	relayAddr *net.UDPAddr
}

// NewUDPRelay creates a new UDP relay
func NewUDPRelay(sm *SessionManager, localAddr string) (*UDPRelay, error) {
	addr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	return &UDPRelay{
		sessionManager: sm,
		fragmenter:     NewDatagramFragmenter(),
		reassembler:    NewDatagramReassembler(),
		localConn:      conn,
	}, nil
}

// Close closes the UDP relay
func (r *UDPRelay) Close() error {
	if r.localConn != nil {
		return r.localConn.Close()
	}
	return nil
}

// SendToPeer sends a UDP datagram to the peer via UQSP
func (r *UDPRelay) SendToPeer(sessionID uint32, data []byte) error {
	// Fragment if necessary
	fragments := r.fragmenter.Fragment(sessionID, data)

	// Send each fragment
	for _, frag := range fragments {
		if err := r.sessionManager.SendDatagram(sessionID, frag.Encode()); err != nil {
			return err
		}
	}

	return nil
}

// ReceiveFromPeer receives a UDP datagram from the peer via UQSP
func (r *UDPRelay) ReceiveFromPeer(sessionID uint32) ([]byte, *net.UDPAddr, error) {
	for i := 0; i < 1024; i++ {
		dg, err := r.sessionManager.ReceiveDatagram(sessionID)
		if err != nil {
			return nil, nil, err
		}

		// Try to decode as fragment.
		frag := &DatagramFragment{}
		if err := frag.Decode(dg.Data); err == nil {
			data, err := r.reassembler.AddFragment(frag)
			if err != nil {
				return nil, nil, err
			}
			if data == nil {
				continue
			}
			return data, dg.TargetAddr, nil
		}

		// Not a fragment, return as-is.
		return dg.Data, dg.TargetAddr, nil
	}
	return nil, nil, fmt.Errorf("datagram reassembly exceeded wait budget")
}

// LocalAddr returns the local UDP address
func (r *UDPRelay) LocalAddr() net.Addr {
	if r.localConn != nil {
		return r.localConn.LocalAddr()
	}
	return nil
}

// SetRelayAddr sets the relay target address
func (r *UDPRelay) SetRelayAddr(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	r.relayAddr = udpAddr
	return nil
}

// RelayAddr returns the relay target address
func (r *UDPRelay) RelayAddr() *net.UDPAddr {
	return r.relayAddr
}

// Hysteria UDP Support - QUIC Unreliable Datagrams

// HysteriaDatagram represents a Hysteria-style UDP datagram
// Format: [Packet ID (2)] [Fragment ID (1)] [Fragment Count (1)] [Session ID (4)] [Payload]
type HysteriaDatagram struct {
	PacketID      uint16
	FragmentID    uint8
	FragmentCount uint8
	SessionID     uint32
	Payload       []byte
}

// HysteriaHeaderSize is the size of the Hysteria datagram header
const HysteriaHeaderSize = 8

// Encode encodes the Hysteria datagram
func (h *HysteriaDatagram) Encode() []byte {
	buf := make([]byte, HysteriaHeaderSize+len(h.Payload))
	binary.BigEndian.PutUint16(buf[0:2], h.PacketID)
	buf[2] = h.FragmentID
	buf[3] = h.FragmentCount
	binary.BigEndian.PutUint32(buf[4:8], h.SessionID)
	copy(buf[8:], h.Payload)
	return buf
}

// Decode decodes the Hysteria datagram
func (h *HysteriaDatagram) Decode(data []byte) error {
	if len(data) < HysteriaHeaderSize {
		return fmt.Errorf("hysteria datagram too short")
	}
	h.PacketID = binary.BigEndian.Uint16(data[0:2])
	h.FragmentID = data[2]
	h.FragmentCount = data[3]
	h.SessionID = binary.BigEndian.Uint32(data[4:8])
	h.Payload = data[8:]
	return nil
}

// HysteriaUDPManager manages UDP forwarding via QUIC unreliable datagrams
type HysteriaUDPManager struct {
	// Sessions maps session IDs to UDP sessions
	sessions map[uint32]*HysteriaUDPSession
	sessMu   sync.RWMutex

	// Packet tracking for reassembly
	packets map[uint64]*hysteriaPacket
	pktMu   sync.RWMutex

	// Local UDP connections
	udpConns map[uint32]*net.UDPConn
	connMu   sync.RWMutex

	// done signals the cleanup goroutine to stop.
	done chan struct{}
}

// hysteriaPacket tracks fragments for reassembly
type hysteriaPacket struct {
	packetID  uint16
	sessionID uint32
	fragments map[uint8][]byte
	received  uint8
	total     uint8
	timestamp time.Time
}

// HysteriaUDPSession represents a UDP session
type HysteriaUDPSession struct {
	SessionID  uint32
	LocalAddr  *net.UDPAddr
	RemoteAddr *net.UDPAddr
	CreatedAt  time.Time
	lastActive atomic.Int64 // UnixNano; use LastActiveTime()/touch()
	bytesIn    atomic.Uint64
	bytesOut   atomic.Uint64
	fullCone   bool
}

// touch updates the last-active timestamp atomically.
func (s *HysteriaUDPSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

// LastActiveTime returns the last-active timestamp.
func (s *HysteriaUDPSession) LastActiveTime() time.Time {
	return time.Unix(0, s.lastActive.Load())
}

// NewHysteriaUDPManager creates a new Hysteria UDP manager with a background
// cleanup goroutine that evicts stale sessions and incomplete packets every 30s.
func NewHysteriaUDPManager() *HysteriaUDPManager {
	m := &HysteriaUDPManager{
		sessions: make(map[uint32]*HysteriaUDPSession),
		packets:  make(map[uint64]*hysteriaPacket),
		udpConns: make(map[uint32]*net.UDPConn),
		done:     make(chan struct{}),
	}
	go m.cleanupLoop()
	return m
}

// cleanupLoop periodically evicts stale sessions and packets.
func (h *HysteriaUDPManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.Cleanup(2 * time.Minute)
		case <-h.done:
			return
		}
	}
}

// Stop shuts down the background cleanup goroutine.
func (h *HysteriaUDPManager) Stop() {
	select {
	case <-h.done:
	default:
		close(h.done)
	}
}

// CreateSession creates a new UDP session
func (h *HysteriaUDPManager) CreateSession(sessionID uint32, remoteAddr string) (*HysteriaUDPSession, error) {
	sess := &HysteriaUDPSession{
		SessionID: sessionID,
		CreatedAt: time.Now(),
		fullCone:  true,
	}
	sess.touch()

	if remoteAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", remoteAddr)
		if err != nil {
			return nil, err
		}
		sess.RemoteAddr = addr
	}

	h.sessMu.Lock()
	h.sessions[sessionID] = sess
	h.sessMu.Unlock()

	return sess, nil
}

// GetSession retrieves a session
func (h *HysteriaUDPManager) GetSession(sessionID uint32) (*HysteriaUDPSession, bool) {
	h.sessMu.RLock()
	defer h.sessMu.RUnlock()
	sess, ok := h.sessions[sessionID]
	return sess, ok
}

// RemoveSession removes a session and cleans up its orphaned packets.
func (h *HysteriaUDPManager) RemoveSession(sessionID uint32) {
	h.sessMu.Lock()
	delete(h.sessions, sessionID)
	h.sessMu.Unlock()

	h.connMu.Lock()
	if conn, ok := h.udpConns[sessionID]; ok {
		conn.Close()
		delete(h.udpConns, sessionID)
	}
	h.connMu.Unlock()

	// Purge incomplete packets belonging to this session.
	h.pktMu.Lock()
	for key, pkt := range h.packets {
		if pkt.sessionID == sessionID {
			delete(h.packets, key)
		}
	}
	h.pktMu.Unlock()
}

// SendDatagram sends a UDP datagram via Hysteria format
func (h *HysteriaUDPManager) SendDatagram(sessionID uint32, payload []byte) (*HysteriaDatagram, error) {
	// Single fragment for now (fragmentation handled at QUIC level)
	dg := &HysteriaDatagram{
		PacketID:      uint16(time.Now().UnixNano() & 0xFFFF),
		FragmentID:    0,
		FragmentCount: 1,
		SessionID:     sessionID,
		Payload:       payload,
	}

	sess, ok := h.GetSession(sessionID)
	if ok {
		sess.bytesOut.Add(uint64(len(payload)))
		sess.touch()
	}

	return dg, nil
}

// ReceiveDatagram processes a received Hysteria datagram
func (h *HysteriaUDPManager) ReceiveDatagram(dg *HysteriaDatagram) ([]byte, error) {
	// Update session activity
	sess, ok := h.GetSession(dg.SessionID)
	if ok {
		sess.bytesIn.Add(uint64(len(dg.Payload)))
		sess.touch()
	}

	// If single fragment, return immediately
	if dg.FragmentCount == 1 {
		return dg.Payload, nil
	}

	// Multi-fragment packet - reassemble
	return h.reassemblePacket(dg)
}

// reassemblePacket reassembles fragmented packets
func (h *HysteriaUDPManager) reassemblePacket(dg *HysteriaDatagram) ([]byte, error) {
	if dg.FragmentCount == 0 {
		return nil, fmt.Errorf("invalid fragment count 0")
	}
	if dg.FragmentID >= dg.FragmentCount {
		return nil, fmt.Errorf("invalid fragment id %d/%d", dg.FragmentID, dg.FragmentCount)
	}

	key := (uint64(dg.SessionID) << 16) | uint64(dg.PacketID)

	h.pktMu.Lock()
	defer h.pktMu.Unlock()
	h.cleanupPacketsLocked(30 * time.Second)

	// Get or create packet tracker
	pkt, ok := h.packets[key]
	if !ok {
		pkt = &hysteriaPacket{
			packetID:  dg.PacketID,
			sessionID: dg.SessionID,
			fragments: make(map[uint8][]byte),
			total:     dg.FragmentCount,
			timestamp: time.Now(),
		}
		h.packets[key] = pkt
	} else if pkt.total != dg.FragmentCount {
		return nil, fmt.Errorf("fragment count mismatch for packet %d", dg.PacketID)
	}

	// Add fragment
	if _, exists := pkt.fragments[dg.FragmentID]; !exists {
		pkt.fragments[dg.FragmentID] = dg.Payload
		pkt.received++
	}

	// Check if complete
	if pkt.received >= pkt.total {
		// Reassemble
		var result []byte
		for i := uint8(0); i < pkt.total; i++ {
			part, ok := pkt.fragments[i]
			if !ok {
				return nil, nil
			}
			result = append(result, part...)
		}
		delete(h.packets, key)
		return result, nil
	}

	return nil, nil
}

func (h *HysteriaUDPManager) cleanupPacketsLocked(timeout time.Duration) {
	now := time.Now()
	for key, pkt := range h.packets {
		if now.Sub(pkt.timestamp) > timeout {
			delete(h.packets, key)
		}
	}
}

// Cleanup removes expired sessions and packets
func (h *HysteriaUDPManager) Cleanup(timeout time.Duration) {
	now := time.Now()

	// Collect expired session IDs under read lock, then remove.
	var expired []uint32
	h.sessMu.RLock()
	for id, sess := range h.sessions {
		if now.Sub(sess.LastActiveTime()) > timeout {
			expired = append(expired, id)
		}
	}
	h.sessMu.RUnlock()

	for _, id := range expired {
		h.RemoveSession(id)
	}

	// Clean packets
	h.pktMu.Lock()
	for key, pkt := range h.packets {
		if now.Sub(pkt.timestamp) > timeout {
			delete(h.packets, key)
		}
	}
	h.pktMu.Unlock()
}

// FullConeNAT returns whether full cone NAT is supported
func (h *HysteriaUDPManager) FullConeNAT(sessionID uint32) bool {
	sess, ok := h.GetSession(sessionID)
	if !ok {
		return false
	}
	return sess.fullCone
}

// EnableFullCone enables full cone NAT for a session
func (h *HysteriaUDPManager) EnableFullCone(sessionID uint32) {
	h.sessMu.Lock()
	defer h.sessMu.Unlock()
	if sess, ok := h.sessions[sessionID]; ok {
		sess.fullCone = true
	}
}

// Datagram represents a received datagram with its target address
type Datagram struct {
	Data       []byte
	TargetAddr *net.UDPAddr
}
