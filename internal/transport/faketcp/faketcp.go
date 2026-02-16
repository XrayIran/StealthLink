// Package faketcp implements a NAT-friendly fake TCP over UDP.
// It simulates a full TCP state machine in userspace while using
// UDP as the underlying transport, making it appear like normal
// TCP flows to middleboxes while remaining userspace controlled.
package faketcp

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"stealthlink/internal/metrics"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/batch"
	"stealthlink/internal/transport/kcpbase"

	"github.com/xtaci/smux"
)

// Packet types for fake TCP.
const (
	PacketTypeSYN       = 0x01
	PacketTypeSYNACK    = 0x02
	PacketTypeACK       = 0x03
	PacketTypeData      = 0x04
	PacketTypeFIN       = 0x05
	PacketTypeRST       = 0x06
	PacketTypeKeepalive = 0x07
)

type sessionCrypto struct {
	enabled bool
	send    *AEADEncryptor
	recv    *AEADEncryptor
}

func buildSessionCrypto(cfg *Config, isClient bool) (*sessionCrypto, error) {
	if cfg.CryptoKey == "" || cfg.AEADMode == "off" || cfg.AEADMode == "" {
		return &sessionCrypto{enabled: false}, nil
	}

	keyLen := 32
	if cfg.AEADMode == "aesgcm" {
		keyLen = 16
	}

	kd := NewKeyDerivation(cfg.CryptoKey)
	keys, err := kd.DeriveDirectionalKeys(keyLen)
	if err != nil {
		return nil, err
	}

	var sendKey, recvKey []byte
	if isClient {
		sendKey = keys.ClientToServer
		recvKey = keys.ServerToClient
	} else {
		sendKey = keys.ServerToClient
		recvKey = keys.ClientToServer
	}

	send, err := NewAEADEncryptor(cfg.AEADMode, sendKey)
	if err != nil {
		return nil, fmt.Errorf("create send AEAD: %w", err)
	}

	recv, err := NewAEADEncryptor(cfg.AEADMode, recvKey)
	if err != nil {
		return nil, fmt.Errorf("create recv AEAD: %w", err)
	}

	return &sessionCrypto{
		enabled: true,
		send:    send,
		recv:    recv,
	}, nil
}

func (s *fakeSession) encryptPacket(pkt *packet) {
	if s.crypto == nil || !s.crypto.enabled || s.crypto.send == nil {
		return
	}
	pkt.Payload = s.crypto.send.Seal(pkt.Payload, pkt)
	direction := "s2c"
	if s.isClient {
		direction = "c2s"
	}
	metrics.AddFakeTCPEncryptedBytes(int64(len(pkt.Payload)), direction)
}

func (s *fakeSession) decryptPacket(pkt *packet) error {
	if s.crypto == nil || !s.crypto.enabled || s.crypto.recv == nil || len(pkt.Payload) == 0 {
		return nil
	}
	plaintext, err := s.crypto.recv.Open(pkt.Payload, pkt)
	if err != nil {
		return err
	}
	pkt.Payload = plaintext
	return nil
}

func (s *fakeSession) effectiveMTU() int {
	mtu := s.config.MTU
	if mtu <= 0 {
		mtu = 1400
	}
	// Subtract FakeTCP header (24) and AEAD tag (16)
	mtu -= HeaderSize
	if s.crypto != nil && s.crypto.enabled {
		mtu -= 16
	}
	return mtu
}

// Header size for fake TCP packets.
const HeaderSize = 24

// TCPFingerprintProfile defines TCP option mimicry for DPI evasion.
type TCPFingerprintProfile struct {
	Name        string
	MSS         uint16
	WindowScale uint8
	SACKPermit  uint8
}

var (
	FPProfileLinuxDefault   = TCPFingerprintProfile{Name: "linux", MSS: 1460, WindowScale: 7, SACKPermit: 1}
	FPProfileWindowsDefault = TCPFingerprintProfile{Name: "windows", MSS: 1440, WindowScale: 8, SACKPermit: 1}
)

func LookupFingerprintProfile(name string) TCPFingerprintProfile {
	switch name {
	case "windows":
		return FPProfileWindowsDefault
	default:
		return FPProfileLinuxDefault
	}
}

func resolveFingerprintProfile(cfg *Config) TCPFingerprintProfile {
	return cfg.FingerprintProfile
}

// Config holds fake TCP configuration.
type Config struct {
	MTU                int                    // Maximum transmission unit
	WindowSize         int                    // TCP window size
	RTO                time.Duration          // Retransmission timeout
	Keepalive          time.Duration          // Keepalive interval
	KeepaliveIdle      time.Duration          // Idle time before keepalive
	FingerprintProfile TCPFingerprintProfile  // TCP option mimicry profile
	CryptoKey          string                 // Shared secret for directional key derivation
	AEADMode           string                 // off, chacha20poly1305, aesgcm
	FakeHTTPPreface    *FakeHTTPPrefaceConfig // Optional fake HTTP preface framing
	Batch              batch.BatchConfig      // Batch I/O configuration
}

// FakeHTTPPrefaceConfig configures fake HTTP preface injected on first send/recv
type FakeHTTPPrefaceConfig struct {
	Enabled   bool   // Whether to inject fake HTTP preface
	Host      string // Host header value
	UserAgent string // User-Agent header value
	Path      string // Request path
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		MTU:           1400,
		WindowSize:    65535,
		RTO:           200 * time.Millisecond,
		Keepalive:     30 * time.Second,
		KeepaliveIdle: 60 * time.Second,
	}
}

// Dialer implements transport.Dialer for fake TCP.
type Dialer struct {
	Config *Config
	Smux   *smux.Config
	Guard  string
}

// Listener implements transport.Listener for fake TCP.
type Listener struct {
	conn      *net.UDPConn
	config    *Config
	smux      *smux.Config
	guard     string
	sessions  sync.Map // map[string]*fakeSession
	acceptCh  chan *fakeSession
	closeCh   chan struct{}
	closeOnce sync.Once

	batchMgr *batch.BatchIOManager // Batch I/O manager for UDP operations
}

// NewDialer creates a new fake TCP dialer.
func NewDialer(cfg *Config, smuxCfg *smux.Config, guard string) *Dialer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if smuxCfg == nil {
		smuxCfg = smux.DefaultConfig()
	}
	return &Dialer{
		Config: cfg,
		Smux:   smuxCfg,
		Guard:  guard,
	}
}

// Listen creates a fake TCP listener.
func Listen(addr string, cfg *Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if smuxCfg == nil {
		smuxCfg = smux.DefaultConfig()
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	l := &Listener{
		conn:     conn,
		config:   cfg,
		smux:     smuxCfg,
		guard:    guard,
		acceptCh: make(chan *fakeSession, 128),
		closeCh:  make(chan struct{}),
	}

	// Initialize batch manager
	l.batchMgr = batch.NewBatchIOManager(cfg.Batch)

	// Start the accept loop
	go l.acceptLoop()

	return l, nil
}

func (l *Listener) RecvBatch(buffers [][]byte) (int, []net.Addr, error) {
	return l.batchMgr.RecvBatch(l.conn, buffers)
}

// acceptLoop handles incoming packets.
func (l *Listener) acceptLoop() {
	batchSize := l.batchMgr.BatchSize()
	buffers := make([][]byte, batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, 65536)
	}

	for {
		// Use RecvBatch for efficient multi-packet receive
		nBatch, addrs, err := l.RecvBatch(buffers)
		if err != nil {
			select {
			case <-l.closeCh:
				return
			default:
			}
			continue
		}

		for i := 0; i < nBatch; i++ {
			buf := buffers[i]
			n := len(buf)
			addr := addrs[i].(*net.UDPAddr)

			if n < HeaderSize {
				continue // Too small
			}

			// Parse header
			pkt := parsePacket(buf)
			if pkt == nil {
				continue
			}

			// Find session
			sessionKey := addr.String()
			var session *fakeSession
			if val, ok := l.sessions.Load(sessionKey); ok {
				session = val.(*fakeSession)
			} else if pkt.Type == PacketTypeSYN {
				// New connection
				session = l.newSession(addr)
			}

			if session != nil {
				// Decrypt if necessary
				if err := session.decryptPacket(pkt); err != nil {
					continue // Auth failure, discard
				}
				session.handlePacket(pkt)
			}
		}

		// Prepare buffers for next batch
		for i := range buffers {
			if cap(buffers[i]) < 65536 {
				buffers[i] = make([]byte, 65536)
			} else {
				buffers[i] = buffers[i][:cap(buffers[i])]
			}
		}
	}
}

// newSession creates a new fake TCP session.
func (l *Listener) newSession(addr *net.UDPAddr) *fakeSession {
	cryptoCtx, err := buildSessionCrypto(l.config, false)
	if err != nil {
		return nil
	}
	s := &fakeSession{
		listener:  l,
		conn:      nil,
		remote:    addr,
		state:     StateListen,
		window:    newWindow(l.config.WindowSize),
		config:    l.config,
		fpProfile: l.config.FingerprintProfile,
		crypto:    cryptoCtx,
		readCh:    make(chan *packet, 256),
		writeCh:   make(chan []byte, 256),
		closeCh:   make(chan struct{}),
		readyCh:   make(chan struct{}, 1),
		batchMgr:  l.batchMgr,
		sndNxt:    uint32(kcpbase.FastRandom.Int64n(1 << 32)),
	}
	l.sessions.Store(addr.String(), s)
	return s
}

// Accept accepts a new fake TCP connection.
func (l *Listener) Accept() (transport.Session, error) {
	select {
	case session := <-l.acceptCh:
		// Send guard token if configured
		if l.guard != "" {
			guard := make([]byte, len(l.guard))
			if _, err := io.ReadFull(session, guard); err != nil {
				_ = session.Close()
				return nil, fmt.Errorf("read guard: %w", err)
			}
			expected := []byte(l.guard)
			if len(guard) != len(expected) || subtle.ConstantTimeCompare(guard, expected) != 1 {
				_ = session.Close()
				return nil, fmt.Errorf("invalid guard token")
			}
		}

		smuxCfg := *l.smux
		smuxCfg.MaxFrameSize = session.effectiveMTU()
		smuxSession, err := smux.Server(session, &smuxCfg)
		if err != nil {
			_ = session.Close()
			return nil, fmt.Errorf("smux: %w", err)
		}

		return &sessionWrapper{
			session: session,
			smux:    smuxSession,
		}, nil
	case <-l.closeCh:
		return nil, fmt.Errorf("listener closed")
	}
}

// Close closes the listener.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeCh)
	})
	return l.conn.Close()
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// Dial connects to a fake TCP server.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP: %w", err)
	}

	// Create session
	cryptoCtx, err := buildSessionCrypto(d.Config, true)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("init session crypto: %w", err)
	}
	session := &fakeSession{
		conn:      conn,
		config:    d.Config,
		state:     StateClosed,
		window:    newWindow(d.Config.WindowSize),
		fpProfile: d.Config.FingerprintProfile,
		isClient:  true,
		crypto:    cryptoCtx,
		readCh:    make(chan *packet, 256),
		writeCh:   make(chan []byte, 256),
		closeCh:   make(chan struct{}),
		readyCh:   make(chan struct{}, 1),
		sndNxt:    uint32(kcpbase.FastRandom.Int64n(1 << 32)),
	}

	// Initialize batch manager
	session.batchMgr = batch.NewBatchIOManager(d.Config.Batch)

	// Perform handshake
	if err := session.connect(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	// Send guard token
	if d.Guard != "" {
		if _, err := session.Write([]byte(d.Guard)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("send guard: %w", err)
		}
	}

	// Start smux
	smuxCfg := *d.Smux
	smuxCfg.MaxFrameSize = session.effectiveMTU()
	smuxSession, err := smux.Client(session, &smuxCfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("smux: %w", err)
	}

	return &sessionWrapper{
		session: session,
		smux:    smuxSession,
	}, nil
}

// fakeSession represents a fake TCP session.
type fakeSession struct {
	listener  *Listener
	conn      *net.UDPConn
	remote    *net.UDPAddr
	state     State
	window    *window
	config    *Config
	fpProfile TCPFingerprintProfile
	isClient  bool
	crypto    *sessionCrypto

	// Sequence numbers
	sndUna uint32 // Send unacknowledged
	sndNxt uint32 // Send next
	rcvNxt uint32 // Receive next

	// Reorder buffer for out-of-order packets (cap 64)
	reorderBuf map[uint32]*packet

	// Channels
	readCh    chan *packet
	writeCh   chan []byte
	closeCh   chan struct{}
	readyCh   chan struct{}
	closeOnce sync.Once
	readBuf   []byte

	// Guards
	mu sync.RWMutex

	batchMgr *batch.BatchIOManager // Batch I/O manager for UDP operations
}

// connect performs the client-side handshake.
func (s *fakeSession) connect() error {
	s.mu.Lock()
	s.state = StateSynSent
	s.mu.Unlock()

	s.startClientReceiveLoop()

	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		s.mu.Lock()
		synSeq := s.sndNxt
		s.mu.Unlock()
		syn := &packet{
			Type: PacketTypeSYN,
			Seq:  synSeq,
		}
		if err := s.sendPacket(syn); err != nil {
			return err
		}
		s.mu.Lock()
		if s.sndNxt == synSeq {
			s.sndNxt = synSeq + 1
		}
		s.mu.Unlock()

		select {
		case <-s.readyCh:
			return nil
		case <-time.After(s.config.RTO):
		case <-s.closeCh:
			return fmt.Errorf("connection closed")
		}
	}

	return fmt.Errorf("handshake timeout after %d attempts", maxRetries)
}

func (s *fakeSession) SendBatch(msgs [][]byte) (int, error) {
	conn := s.conn
	if conn == nil && s.listener != nil {
		conn = s.listener.conn
	}
	if conn == nil {
		return 0, fmt.Errorf("nil connection")
	}
	return s.batchMgr.SendBatch(conn, msgs)
}

func (s *fakeSession) SendBatchAddr(msgs [][]byte, addrs []*net.UDPAddr) (int, error) {
	conn := s.conn
	if conn == nil && s.listener != nil {
		conn = s.listener.conn
	}
	if conn == nil {
		return 0, fmt.Errorf("nil connection")
	}
	return s.batchMgr.SendBatchAddr(conn, msgs, addrs)
}

func (s *fakeSession) RecvBatch(buffers [][]byte) (int, []net.Addr, error) {
	conn := s.conn
	if conn == nil && s.listener != nil {
		conn = s.listener.conn
	}
	if conn == nil {
		return 0, nil, fmt.Errorf("nil connection")
	}
	return s.batchMgr.RecvBatch(conn, buffers)
}

func (s *fakeSession) startClientReceiveLoop() {
	if s.conn == nil {
		return
	}
	go func() {
		batchSize := s.batchMgr.BatchSize()
		buffers := make([][]byte, batchSize)
		for i := range buffers {
			buffers[i] = make([]byte, 65536)
		}

		for {
			select {
			case <-s.closeCh:
				return
			default:
			}

			_ = s.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			// Use RecvBatch for efficient multi-packet receive
			nBatch, _, err := s.RecvBatch(buffers)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				s.handleRST(nil)
				return
			}

			for i := 0; i < nBatch; i++ {
				buf := buffers[i]
				n := len(buf)
				if n < HeaderSize {
					continue
				}
				pkt := parsePacket(buf)
				if pkt == nil {
					continue
				}
				if err := s.decryptPacket(pkt); err != nil {
					continue
				}
				s.handlePacket(pkt)
			}

			// Prepare buffers for next batch
			for i := range buffers {
				if cap(buffers[i]) < 65536 {
					buffers[i] = make([]byte, 65536)
				} else {
					buffers[i] = buffers[i][:cap(buffers[i])]
				}
			}
		}
	}()
}

// handlePacket processes an incoming packet.
func (s *fakeSession) handlePacket(pkt *packet) {
	switch pkt.Type {
	case PacketTypeSYN:
		s.handleSYN(pkt)
	case PacketTypeSYNACK:
		s.handleSYNACK(pkt)
	case PacketTypeACK:
		s.handleACK(pkt)
	case PacketTypeData:
		s.handleData(pkt)
	case PacketTypeFIN:
		s.handleFIN(pkt)
	case PacketTypeRST:
		s.handleRST(pkt)
	case PacketTypeKeepalive:
		// Just update activity timestamp
	}
}

func (s *fakeSession) handleSYN(pkt *packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateListen {
		return
	}

	// Initialize receive sequence
	s.rcvNxt = pkt.Seq + 1

	// Send SYN-ACK
	synack := &packet{
		Type: PacketTypeSYNACK,
		Seq:  s.sndNxt,
		Ack:  s.rcvNxt,
	}
	_ = s.sendPacket(synack)
	s.sndNxt++

	s.state = StateSynReceived
}

func (s *fakeSession) handleSYNACK(pkt *packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateSynSent {
		return
	}

	// Update sequence numbers
	s.sndUna = pkt.Ack
	s.rcvNxt = pkt.Seq + 1

	// Send ACK
	ack := &packet{
		Type: PacketTypeACK,
		Seq:  s.sndNxt,
		Ack:  s.rcvNxt,
	}
	_ = s.sendPacket(ack)

	s.state = StateEstablished
	select {
	case s.readyCh <- struct{}{}:
	default:
	}
}

func (s *fakeSession) handleACK(pkt *packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update send window
	if pkt.Ack > s.sndUna {
		s.sndUna = pkt.Ack
	}

	if s.state == StateSynReceived {
		s.state = StateEstablished
		select {
		case s.readyCh <- struct{}{}:
		default:
		}
		if s.listener != nil {
			select {
			case s.listener.acceptCh <- s:
			default:
			}
		}
	}
}

func (s *fakeSession) handleData(pkt *packet) {
	s.mu.Lock()

	if s.state != StateEstablished {
		s.mu.Unlock()
		return
	}

	// Check sequence number
	if pkt.Seq != s.rcvNxt {
		// Out of order - queue (cap 64)
		if s.reorderBuf == nil {
			s.reorderBuf = make(map[uint32]*packet)
		}
		if len(s.reorderBuf) < 64 {
			cp := &packet{Type: pkt.Type, Seq: pkt.Seq, Payload: make([]byte, len(pkt.Payload))}
			copy(cp.Payload, pkt.Payload)
			s.reorderBuf[pkt.Seq] = cp
		}
		s.mu.Unlock()
		return
	}

	// Deliver this packet and drain contiguous buffered packets
	var toDeliver []*packet

	s.rcvNxt += uint32(len(pkt.Payload))
	payload := make([]byte, len(pkt.Payload))
	copy(payload, pkt.Payload)
	toDeliver = append(toDeliver, &packet{Type: PacketTypeData, Payload: payload})

	// Drain contiguous reorder buffer entries
	for {
		if s.reorderBuf == nil {
			break
		}
		next, ok := s.reorderBuf[s.rcvNxt]
		if !ok {
			break
		}
		delete(s.reorderBuf, s.rcvNxt)
		s.rcvNxt += uint32(len(next.Payload))
		toDeliver = append(toDeliver, next)
	}

	// Send ACK
	ack := &packet{
		Type: PacketTypeACK,
		Seq:  s.sndNxt,
		Ack:  s.rcvNxt,
	}
	s.mu.Unlock()

	_ = s.sendPacket(ack)

	for _, dp := range toDeliver {
		select {
		case <-s.closeCh:
			return
		case s.readCh <- dp:
		}
	}
}

func (s *fakeSession) handleFIN(pkt *packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case StateEstablished:
		s.state = StateCloseWait
	case StateFinWait1:
		s.state = StateClosing
	case StateFinWait2:
		s.state = StateTimeWait
	}
}

func (s *fakeSession) handleRST(_ *packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = StateClosed
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
}

// sendPacket sends a packet.
func (s *fakeSession) sendPacket(pkt *packet) error {
	s.encryptPacket(pkt)
	data := encodePacket(pkt, s.fpProfile)

	// Use SendBatch for efficient multi-packet send
	if s.isClient {
		// Connected socket
		_, err := s.SendBatch([][]byte{data})
		return err
	}
	// Shared listener socket
	_, err := s.SendBatchAddr([][]byte{data}, []*net.UDPAddr{s.remote})
	return err
}

// Read implements net.Conn.
func (s *fakeSession) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	if len(s.readBuf) > 0 {
		n = copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()

	select {
	case <-s.closeCh:
		return 0, io.EOF
	case pkt := <-s.readCh:
		if pkt == nil || len(pkt.Payload) == 0 {
			return 0, nil
		}
		n = copy(p, pkt.Payload)
		if n < len(pkt.Payload) {
			s.mu.Lock()
			s.readBuf = append(s.readBuf[:0], pkt.Payload[n:]...)
			s.mu.Unlock()
		}
		return n, nil
	}
}

// Write implements net.Conn.
func (s *fakeSession) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	if s.state != StateEstablished {
		s.mu.Unlock()
		return 0, fmt.Errorf("connection not established")
	}

	// Send data packet
	payload := make([]byte, len(p))
	copy(payload, p)
	seq := s.sndNxt
	s.sndNxt += uint32(len(p))
	s.mu.Unlock()

	pkt := &packet{
		Type:    PacketTypeData,
		Seq:     seq,
		Payload: payload,
	}

	if err := s.sendPacket(pkt); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Close implements net.Conn.
func (s *fakeSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case StateEstablished:
		s.state = StateFinWait1
		fin := &packet{
			Type: PacketTypeFIN,
			Seq:  s.sndNxt,
		}
		_ = s.sendPacket(fin)
	case StateCloseWait:
		s.state = StateLastAck
		fin := &packet{
			Type: PacketTypeFIN,
			Seq:  s.sndNxt,
		}
		_ = s.sendPacket(fin)
	}

	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// LocalAddr implements net.Conn.
func (s *fakeSession) LocalAddr() net.Addr {
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return s.listener.conn.LocalAddr()
}

// RemoteAddr implements net.Conn.
func (s *fakeSession) RemoteAddr() net.Addr {
	if s.remote != nil {
		return s.remote
	}
	if s.conn != nil {
		return s.conn.RemoteAddr()
	}
	return nil
}

// SetDeadline implements net.Conn.
func (s *fakeSession) SetDeadline(t time.Time) error {
	if s.conn != nil {
		return s.conn.SetDeadline(t)
	}
	return nil
}

// SetReadDeadline implements net.Conn.
func (s *fakeSession) SetReadDeadline(t time.Time) error {
	if s.conn != nil {
		return s.conn.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline implements net.Conn.
func (s *fakeSession) SetWriteDeadline(t time.Time) error {
	if s.conn != nil {
		return s.conn.SetWriteDeadline(t)
	}
	return nil
}

// packet represents a fake TCP packet.
type packet struct {
	Type    uint8
	Flags   uint8
	Seq     uint32
	Ack     uint32
	Window  uint16
	Payload []byte
}

// parsePacket parses a packet from bytes.
func parsePacket(data []byte) *packet {
	if len(data) < HeaderSize {
		return nil
	}

	pkt := &packet{
		Type:   data[0],
		Flags:  data[1],
		Seq:    binary.BigEndian.Uint32(data[2:6]),
		Ack:    binary.BigEndian.Uint32(data[6:10]),
		Window: binary.BigEndian.Uint16(data[10:12]),
	}

	if len(data) > HeaderSize {
		pkt.Payload = data[HeaderSize:]
	}

	return pkt
}

// encodePacket encodes a packet to bytes.
func encodePacket(pkt *packet, fp TCPFingerprintProfile) []byte {
	data := make([]byte, HeaderSize+len(pkt.Payload))
	data[0] = pkt.Type
	data[1] = pkt.Flags
	binary.BigEndian.PutUint32(data[2:6], pkt.Seq)
	binary.BigEndian.PutUint32(data[6:10], pkt.Ack)
	binary.BigEndian.PutUint16(data[10:12], pkt.Window)

	// Encode TCP options for DPI evasion
	binary.BigEndian.PutUint16(data[12:14], fp.MSS)
	data[14] = fp.WindowScale
	data[15] = fp.SACKPermit
	// 16-23 reserved for future use

	copy(data[HeaderSize:], pkt.Payload)
	return data
}

// sessionWrapper wraps a fakeSession for transport.Session.
type sessionWrapper struct {
	session *fakeSession
	smux    *smux.Session
}

func (w *sessionWrapper) OpenStream() (net.Conn, error) {
	return w.smux.OpenStream()
}

func (w *sessionWrapper) AcceptStream() (net.Conn, error) {
	return w.smux.AcceptStream()
}

func (w *sessionWrapper) Close() error {
	if w.smux != nil {
		_ = w.smux.Close()
	}
	return w.session.Close()
}

func (w *sessionWrapper) LocalAddr() net.Addr  { return w.session.LocalAddr() }
func (w *sessionWrapper) RemoteAddr() net.Addr { return w.session.RemoteAddr() }

func defaultSendBatch(conn *net.UDPConn, msgs [][]byte, addrs []*net.UDPAddr) (int, error) {
	sent := 0
	for i, msg := range msgs {
		var err error
		if i < len(addrs) && addrs[i] != nil {
			_, err = conn.WriteToUDP(msg, addrs[i])
		} else {
			_, err = conn.Write(msg)
		}
		if err != nil {
			if sent > 0 {
				return sent, nil
			}
			return 0, err
		}
		sent++
	}
	return sent, nil
}

func defaultRecvBatch(conn *net.UDPConn, buffers [][]byte) (int, []net.Addr, error) {
	if len(buffers) == 0 {
		return 0, nil, nil
	}
	n, addr, err := conn.ReadFromUDP(buffers[0])
	if err != nil {
		return 0, nil, err
	}
	buffers[0] = buffers[0][:n]
	return 1, []net.Addr{addr}, nil
}
