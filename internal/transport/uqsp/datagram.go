package uqsp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
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
	// fragments maps sessionID+fragmentID to fragments
	fragments map[uint64][]*DatagramFragment
	mu        sync.Mutex

	// timeout for incomplete reassemblies
	timeout int64
}

// NewDatagramReassembler creates a new datagram reassembler
func NewDatagramReassembler() *DatagramReassembler {
	return &DatagramReassembler{
		fragments: make(map[uint64][]*DatagramFragment),
		timeout:   30, // 30 seconds
	}
}

// AddFragment adds a fragment and attempts reassembly
func (r *DatagramReassembler) AddFragment(fragment *DatagramFragment) ([]byte, error) {
	key := r.makeKey(fragment.SessionID, fragment.FragmentID)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Initialize fragment list if needed
	if r.fragments[key] == nil {
		r.fragments[key] = make([]*DatagramFragment, 0, fragment.TotalFragments)
	}

	// Add fragment
	r.fragments[key] = append(r.fragments[key], fragment)

	// Check if we have all fragments
	if uint8(len(r.fragments[key])) >= fragment.TotalFragments {
		return r.reassemble(key, fragment.TotalFragments)
	}

	return nil, nil // Not complete yet
}

// reassemble reassembles fragments into a complete datagram
func (r *DatagramReassembler) reassemble(key uint64, total uint8) ([]byte, error) {
	fragments := r.fragments[key]
	delete(r.fragments, key)

	if uint8(len(fragments)) < total {
		return nil, fmt.Errorf("incomplete fragments")
	}

	// Sort fragments by index and calculate total size
	totalSize := 0
	sorted := make([]*DatagramFragment, total)
	for _, f := range fragments {
		if f.FragmentIndex >= total {
			return nil, fmt.Errorf("invalid fragment index")
		}
		sorted[f.FragmentIndex] = f
		totalSize += len(f.Data)
	}

	// Check for missing fragments
	for i := uint8(0); i < total; i++ {
		if sorted[i] == nil {
			return nil, fmt.Errorf("missing fragment %d", i)
		}
	}

	// Reassemble
	result := make([]byte, 0, totalSize)
	for _, f := range sorted {
		result = append(result, f.Data...)
	}

	return result, nil
}

// makeKey creates a key from session ID and fragment ID
func (r *DatagramReassembler) makeKey(sessionID uint32, fragmentID uint16) uint64 {
	return (uint64(sessionID) << 16) | uint64(fragmentID)
}

// DatagramFragmenter fragments large datagrams
type DatagramFragmenter struct {
	// nextFragmentID is the next fragment ID to use
	nextID uint16
	mu     sync.Mutex
}

// NewDatagramFragmenter creates a new datagram fragmenter
func NewDatagramFragmenter() *DatagramFragmenter {
	return &DatagramFragmenter{
		nextID: 1,
	}
}

// Fragment fragments a datagram into smaller pieces
func (f *DatagramFragmenter) Fragment(sessionID uint32, data []byte) []*DatagramFragment {
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
	dg, err := r.sessionManager.ReceiveDatagram(sessionID)
	if err != nil {
		return nil, nil, err
	}

	// Try to decode as fragment
	frag := &DatagramFragment{}
	if err := frag.Decode(dg.Data); err == nil {
		// It's a fragment, try to reassemble
		data, err := r.reassembler.AddFragment(frag)
		if err != nil {
			return nil, nil, err
		}
		if data == nil {
			// Not complete yet, wait for more fragments
			return r.ReceiveFromPeer(sessionID)
		}
		return data, dg.TargetAddr, nil
	}

	// Not a fragment, return as-is
	return dg.Data, dg.TargetAddr, nil
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
	SessionID   uint32
	LocalAddr   *net.UDPAddr
	RemoteAddr  *net.UDPAddr
	CreatedAt   time.Time
	LastActive  time.Time
	bytesIn     uint64
	bytesOut    uint64
	fullCone    bool
}

// NewHysteriaUDPManager creates a new Hysteria UDP manager
func NewHysteriaUDPManager() *HysteriaUDPManager {
	return &HysteriaUDPManager{
		sessions: make(map[uint32]*HysteriaUDPSession),
		packets:  make(map[uint64]*hysteriaPacket),
		udpConns: make(map[uint32]*net.UDPConn),
	}
}

// CreateSession creates a new UDP session
func (h *HysteriaUDPManager) CreateSession(sessionID uint32, remoteAddr string) (*HysteriaUDPSession, error) {
	sess := &HysteriaUDPSession{
		SessionID:  sessionID,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		fullCone:   true,
	}

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

// RemoveSession removes a session
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
		sess.bytesOut += uint64(len(payload))
		sess.LastActive = time.Now()
	}

	return dg, nil
}

// ReceiveDatagram processes a received Hysteria datagram
func (h *HysteriaUDPManager) ReceiveDatagram(dg *HysteriaDatagram) ([]byte, error) {
	// Update session activity
	sess, ok := h.GetSession(dg.SessionID)
	if ok {
		sess.bytesIn += uint64(len(dg.Payload))
		sess.LastActive = time.Now()
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
	key := (uint64(dg.SessionID) << 16) | uint64(dg.PacketID)

	h.pktMu.Lock()
	defer h.pktMu.Unlock()

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
	}

	// Add fragment
	if dg.FragmentID < dg.FragmentCount {
		pkt.fragments[dg.FragmentID] = dg.Payload
		pkt.received++
	}

	// Check if complete
	if pkt.received >= pkt.total {
		// Reassemble
		var result []byte
		for i := uint8(0); i < pkt.total; i++ {
			result = append(result, pkt.fragments[i]...)
		}
		delete(h.packets, key)
		return result, nil
	}

	return nil, fmt.Errorf("packet incomplete")
}

// Cleanup removes expired sessions and packets
func (h *HysteriaUDPManager) Cleanup(timeout time.Duration) {
	now := time.Now()

	// Clean sessions
	h.sessMu.Lock()
	for id, sess := range h.sessions {
		if now.Sub(sess.LastActive) > timeout {
			delete(h.sessions, id)
		}
	}
	h.sessMu.Unlock()

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
