package zrtt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"
	"stealthlink/internal/metrics"
)

const (
	ZeroRTTHeaderSize = 48
	SessionKeySize    = 32
	MaxEarlyData      = 4096
)

type ZeroRTTConfig struct {
	Enabled        bool
	MaxEarlyData   int
	SessionTimeout time.Duration
	SessionKey     string
}

type ZeroRTTSession struct {
	ID          []byte
	Key         []byte
	Created     time.Time
	RemoteAddr  net.Addr
	EarlyData   []byte
	PacketCount uint64
}

type ZeroRTTClient struct {
	config   ZeroRTTConfig
	sessions sync.Map
	conn     *net.UDPConn
	running  atomic.Bool
	mu       sync.Mutex
}

func NewZeroRTTClient(cfg ZeroRTTConfig) *ZeroRTTClient {
	if cfg.MaxEarlyData == 0 {
		cfg.MaxEarlyData = MaxEarlyData
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 24 * time.Hour
	}
	return &ZeroRTTClient{config: cfg}
}

func (c *ZeroRTTClient) Connect(ctx context.Context, addr string, earlyData []byte) (net.Conn, *ZeroRTTSession, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial udp: %w", err)
	}

	session := c.generateSession()
	session.RemoteAddr = udpAddr

	if len(earlyData) > c.config.MaxEarlyData {
		earlyData = earlyData[:c.config.MaxEarlyData]
	}
	session.EarlyData = earlyData

	handshake := c.buildZeroRTTHandshake(session, earlyData)
	if _, err := conn.Write(handshake); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send 0-rtt handshake: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 64)
	n, err := conn.Read(response)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read response: %w", err)
	}

	if err := c.validateResponse(session, response[:n]); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("validate response: %w", err)
	}

	c.sessions.Store(string(session.ID), session)
	metrics.IncTransportSession("zrtt")

	return &zeroRTTConn{
		Conn:    conn,
		session: session,
		client:  c,
	}, session, nil
}

func (c *ZeroRTTClient) generateSession() *ZeroRTTSession {
	id := make([]byte, 16)
	rand.Read(id)

	key := make([]byte, SessionKeySize)
	if c.config.SessionKey != "" {
		hkdf := hkdf.New(sha256.New, []byte(c.config.SessionKey), id, []byte("zrtt"))
		hkdf.Read(key)
	} else {
		rand.Read(key)
	}

	return &ZeroRTTSession{
		ID:      id,
		Key:     key,
		Created: time.Now(),
	}
}

func (c *ZeroRTTClient) buildZeroRTTHandshake(session *ZeroRTTSession, earlyData []byte) []byte {
	totalLen := ZeroRTTHeaderSize + len(earlyData)
	buf := make([]byte, totalLen)

	buf[0] = 0x5A
	buf[1] = 0x52
	buf[2] = 0x54
	buf[3] = 0x54

	copy(buf[4:20], session.ID)
	binary.BigEndian.PutUint32(buf[20:24], uint32(len(earlyData)))
	binary.BigEndian.PutUint64(buf[24:32], uint64(time.Now().UnixNano()))

	block, _ := aes.NewCipher(session.Key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	copy(buf[32:44], nonce)

	tag := sha256.Sum256(buf[:44])
	copy(buf[44:48], tag[:4])

	if len(earlyData) > 0 {
		encrypted := gcm.Seal(nil, nonce, earlyData, buf[:44])
		copy(buf[ZeroRTTHeaderSize:], encrypted)
	}

	return buf
}

func (c *ZeroRTTClient) validateResponse(session *ZeroRTTSession, response []byte) error {
	if len(response) < 16 {
		return fmt.Errorf("response too short")
	}

	if response[0] != 0x5A || response[1] != 0x52 || response[2] != 0x54 || response[3] != 0x54 {
		return fmt.Errorf("invalid response magic")
	}

	expectedTag := sha256.Sum256(append(session.ID, response[4:12]...))
	for i := 0; i < 4; i++ {
		if response[12+i] != expectedTag[i] {
			return fmt.Errorf("response tag mismatch")
		}
	}

	return nil
}

func (c *ZeroRTTClient) GetSession(id []byte) (*ZeroRTTSession, bool) {
	val, ok := c.sessions.Load(string(id))
	if !ok {
		return nil, false
	}
	return val.(*ZeroRTTSession), true
}

func (c *ZeroRTTClient) Close() error {
	c.running.Store(false)
	return nil
}

type ZeroRTTServer struct {
	config   ZeroRTTConfig
	conn     *net.UDPConn
	sessions sync.Map
	running  atomic.Bool
	mu       sync.Mutex
}

func NewZeroRTTServer(cfg ZeroRTTConfig) *ZeroRTTServer {
	if cfg.MaxEarlyData == 0 {
		cfg.MaxEarlyData = MaxEarlyData
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 24 * time.Hour
	}
	return &ZeroRTTServer{config: cfg}
}

func (s *ZeroRTTServer) Listen(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}

	s.conn = conn
	s.running.Store(true)

	go s.serve()
	return nil
}

func (s *ZeroRTTServer) serve() {
	buf := make([]byte, 65535)
	for s.running.Load() {
		n, remote, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		if n < ZeroRTTHeaderSize {
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		go s.handlePacket(pkt, remote)
	}
}

func (s *ZeroRTTServer) handlePacket(data []byte, remote *net.UDPAddr) {
	if data[0] != 0x5A || data[1] != 0x52 || data[2] != 0x54 || data[3] != 0x54 {
		return
	}

	sessionID := data[4:20]
	earlyDataLen := binary.BigEndian.Uint32(data[20:24])

	session := &ZeroRTTSession{
		ID:      sessionID,
		Key:     s.deriveSessionKey(sessionID),
		Created: time.Now(),
	}

	if s.config.SessionKey != "" {
		hkdf := hkdf.New(sha256.New, []byte(s.config.SessionKey), sessionID, []byte("zrtt"))
		hkdf.Read(session.Key)
	}

	var earlyData []byte
	if earlyDataLen > 0 && int(earlyDataLen) <= s.config.MaxEarlyData {
		block, _ := aes.NewCipher(session.Key)
		gcm, _ := cipher.NewGCM(block)
		nonce := data[32:44]
		decrypted, err := gcm.Open(nil, nonce, data[ZeroRTTHeaderSize:], data[:44])
		if err == nil {
			earlyData = decrypted
		}
	}
	session.EarlyData = earlyData

	s.sessions.Store(string(sessionID), session)

	response := make([]byte, 16)
	response[0] = 0x5A
	response[1] = 0x52
	response[2] = 0x54
	response[3] = 0x54
	rand.Read(response[4:12])

	tag := sha256.Sum256(append(sessionID, response[4:12]...))
	copy(response[12:16], tag[:4])

	s.conn.WriteToUDP(response, remote)
	metrics.IncTransportSession("zrtt_server")
}

func (s *ZeroRTTServer) deriveSessionKey(sessionID []byte) []byte {
	key := make([]byte, SessionKeySize)
	if s.config.SessionKey != "" {
		hkdf := hkdf.New(sha256.New, []byte(s.config.SessionKey), sessionID, []byte("zrtt"))
		hkdf.Read(key)
	} else {
		rand.Read(key)
	}
	return key
}

func (s *ZeroRTTServer) Close() error {
	s.running.Store(false)
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

type zeroRTTConn struct {
	net.Conn
	session  *ZeroRTTSession
	client   *ZeroRTTClient
	readBuf  []byte
	writeBuf []byte
	mu       sync.Mutex
	closed   bool
}

func (c *zeroRTTConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	if len(c.readBuf) > 0 {
		n = copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	buf := make([]byte, 4096)
	nRead, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}

	block, _ := aes.NewCipher(c.session.Key)
	gcm, _ := cipher.NewGCM(block)

	nonce := buf[:12]
	ciphertext := buf[12:nRead]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}

	n = copy(b, plaintext)
	if n < len(plaintext) {
		c.readBuf = append(c.readBuf[:0], plaintext[n:]...)
	}

	metrics.AddTrafficInbound(int64(n))
	return n, nil
}

func (c *zeroRTTConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	block, _ := aes.NewCipher(c.session.Key)
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	ciphertext := gcm.Seal(nil, nonce, b, nil)

	packet := make([]byte, 12+len(ciphertext))
	copy(packet[:12], nonce)
	copy(packet[12:], ciphertext)

	_, err = c.Conn.Write(packet)
	if err != nil {
		return 0, err
	}

	metrics.AddTrafficOutbound(int64(len(b)))
	return len(b), nil
}

func (c *zeroRTTConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	metrics.DecTransportSession("zrtt")
	return c.Conn.Close()
}

type FullConeNAT struct {
	localAddr *net.UDPAddr
	mappings  sync.Map
	mu        sync.RWMutex
}

func NewFullConeNAT() *FullConeNAT {
	return &FullConeNAT{}
}

func (n *FullConeNAT) GetMapping(localPort int, remote *net.UDPAddr) *net.UDPAddr {
	key := fmt.Sprintf("%d-%s", localPort, remote.String())
	if val, ok := n.mappings.Load(key); ok {
		return val.(*net.UDPAddr)
	}

	mapping := &net.UDPAddr{
		IP:   n.localAddr.IP,
		Port: localPort,
	}
	n.mappings.Store(key, mapping)
	return mapping
}

func (n *FullConeNAT) SetLocalAddr(addr *net.UDPAddr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.localAddr = addr
}

func (n *FullConeNAT) IsFullCone() bool {
	return true
}
