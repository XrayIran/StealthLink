// Package rawpacket provides unified raw socket-based transports requiring CAP_NET_RAW.
// It consolidates rawtcp, faketcp, and icmptun into a single configurable transport.
package rawpacket

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/faketcp"
	"stealthlink/internal/transport/icmptun"
	"stealthlink/internal/transport/rawtcp"

	"github.com/xtaci/smux"
)

// PacketType represents the raw packet transport type
type PacketType string

const (
	// TypeRawTCP uses raw TCP with pcap packet crafting
	TypeRawTCP PacketType = "rawtcp"
	// TypeFakeTCP uses userspace TCP state machine over UDP
	TypeFakeTCP PacketType = "faketcp"
	// TypeICMP uses ICMP tunneling
	TypeICMP PacketType = "icmp"
)

// TCPFlag represents TCP flags
type TCPFlag uint8

const (
	TCPFlagFIN TCPFlag = 0x01
	TCPFlagSYN TCPFlag = 0x02
	TCPFlagRST TCPFlag = 0x04
	TCPFlagPSH TCPFlag = 0x08
	TCPFlagACK TCPFlag = 0x10
	TCPFlagURG TCPFlag = 0x20
	TCPFlagECE TCPFlag = 0x40
	TCPFlagCWR TCPFlag = 0x80
)

// Config holds the unified raw packet configuration
type Config struct {
	// Type selects the raw packet transport type
	Type PacketType

	// Interface to bind to (empty for any)
	Interface string

	// Local address
	LocalAddr net.Addr

	// Remote address
	RemoteAddr net.Addr

	// TCP-specific settings
	TCPFlags TCPFlagConfig

	// ICMP-specific settings
	ICMP ICMPConfig

	// Common settings
	MTU int

	// Recovery settings
	Recovery RecoveryConfig
}

// TCPFlagConfig configures TCP flag behavior
type TCPFlagConfig struct {
	// Initial flags for handshake
	InitialFlags TCPFlag

	// Flag cycling for obfuscation
	CycleFlags    bool
	CycleSequence []TCPFlag

	// Window size
	WindowSize int

	// Options to include in TCP header
	Options []TCPOption
}

// TCPOption represents a TCP option
type TCPOption struct {
	Type   uint8
	Length uint8
	Data   []byte
}

// ICMPConfig configures ICMP tunneling
type ICMPConfig struct {
	// ICMP ID (for echo request/reply matching)
	ID uint16

	// Echo interval for keepalives
	EchoInterval time.Duration

	// Sequence number management
	SequenceStart uint16

	// Obfuscate payload
	Obfuscate bool

	// Obfuscation key
	ObfuscationKey string
}

// RecoveryConfig configures connection recovery
type RecoveryConfig struct {
	Enabled           bool
	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
	AntiReplayWindow  uint64
	AutoPortChange    bool
	StateMachine      bool
	MaxRetries        int
}

// DefaultConfig returns default raw packet configuration
func DefaultConfig() *Config {
	return &Config{
		Type:     TypeFakeTCP,
		MTU:      1400,
		TCPFlags: DefaultTCPFlagConfig(),
		ICMP:     DefaultICMPConfig(),
		Recovery: DefaultRecoveryConfig(),
	}
}

// DefaultTCPFlagConfig returns default TCP flag configuration
func DefaultTCPFlagConfig() TCPFlagConfig {
	return TCPFlagConfig{
		InitialFlags: TCPFlagSYN,
		CycleFlags:   false,
		WindowSize:   65535,
		Options: []TCPOption{
			{Type: 2, Length: 4, Data: []byte{0x05, 0xb4}}, // MSS 1460
			{Type: 4, Length: 2, Data: []byte{}},           // SACK permitted
			{Type: 8, Length: 10, Data: make([]byte, 8)},   // Timestamp
			{Type: 1, Length: 0, Data: []byte{}},           // NOP
			{Type: 3, Length: 3, Data: []byte{0x08}},       // Window scale
		},
	}
}

// DefaultICMPConfig returns default ICMP configuration
func DefaultICMPConfig() ICMPConfig {
	return ICMPConfig{
		ID:             0,
		EchoInterval:   5 * time.Second,
		SequenceStart:  1,
		Obfuscate:      true,
		ObfuscationKey: "",
	}
}

// DefaultRecoveryConfig returns default recovery configuration
func DefaultRecoveryConfig() RecoveryConfig {
	return RecoveryConfig{
		Enabled:           true,
		HeartbeatInterval: 10 * time.Second,
		HeartbeatTimeout:  30 * time.Second,
		AntiReplayWindow:  64,
		AutoPortChange:    true,
		StateMachine:      true,
		MaxRetries:        3,
	}
}

// Dialer creates raw packet connections
type Dialer struct {
	cfg  *Config
	smux *smux.Config
}

// NewDialer creates a new raw packet dialer
func NewDialer(cfg *Config, smuxCfg *smux.Config) *Dialer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Dialer{
		cfg:  cfg,
		smux: smuxCfg,
	}
}

// Dial connects to a raw packet server
func (d *Dialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	switch d.cfg.Type {
	case TypeRawTCP:
		return d.dialRawTCP(ctx, addr)
	case TypeFakeTCP:
		return d.dialFakeTCP(ctx, addr)
	case TypeICMP:
		return d.dialICMP(ctx, addr)
	default:
		return nil, fmt.Errorf("unknown packet type: %s", d.cfg.Type)
	}
}

func (d *Dialer) dialRawTCP(ctx context.Context, addr string) (net.Conn, error) {
	unified := &rawtcp.UnifiedConfig{
		Mode: rawtcp.RawModeTCP,
		TCP: config.RawTCPConfig{
			Interface: d.cfg.Interface,
		},
		KCP:  config.KCPConfig{},
		Smux: d.effectiveSmuxConfig(),
	}
	return d.dialViaUnified(ctx, addr, unified)
}

func (d *Dialer) dialFakeTCP(ctx context.Context, addr string) (net.Conn, error) {
	unified := &rawtcp.UnifiedConfig{
		Mode:    rawtcp.RawModeFakeTCP,
		FakeTCP: rawtcpFakeTCPConfigFrom(d.cfg),
		Smux:    d.effectiveSmuxConfig(),
	}
	return d.dialViaUnified(ctx, addr, unified)
}

func (d *Dialer) dialICMP(ctx context.Context, addr string) (net.Conn, error) {
	unified := &rawtcp.UnifiedConfig{
		Mode: rawtcp.RawModeICMP,
		ICMP: rawtcpICMPConfigFrom(d.cfg),
		Smux: d.effectiveSmuxConfig(),
	}
	return d.dialViaUnified(ctx, addr, unified)
}

func (d *Dialer) dialViaUnified(ctx context.Context, addr string, cfg *rawtcp.UnifiedConfig) (net.Conn, error) {
	sess, err := rawtcp.NewUnifiedDialer(cfg).Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	stream, err := sess.OpenStream()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	return &sessionStreamConn{Conn: stream, sess: sess}, nil
}

func (d *Dialer) effectiveSmuxConfig() *smux.Config {
	if d.smux != nil {
		return d.smux
	}
	return smux.DefaultConfig()
}

func rawtcpFakeTCPConfigFrom(cfg *Config) faketcp.Config {
	ft := faketcp.Config{}
	if cfg.MTU > 0 {
		ft.MTU = cfg.MTU
	}
	if cfg.TCPFlags.WindowSize > 0 {
		ft.WindowSize = cfg.TCPFlags.WindowSize
	}
	return ft
}

func rawtcpICMPConfigFrom(cfg *Config) icmptun.Config {
	ic := icmptun.Config{
		Obfuscate: cfg.ICMP.Obfuscate,
	}
	if cfg.MTU > 0 {
		ic.MTU = cfg.MTU
	}
	if cfg.ICMP.EchoInterval > 0 {
		ic.EchoInterval = cfg.ICMP.EchoInterval
	}
	return ic
}

// Listener listens for raw packet connections
type Listener struct {
	cfg      *Config
	smux     *smux.Config
	closed   bool
	listener *rawtcp.UnifiedListener
}

// Listen creates a raw packet listener
func Listen(addr string, cfg *Config, smuxCfg *smux.Config) (*Listener, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	unified := &rawtcp.UnifiedConfig{
		Smux: smuxCfg,
	}
	switch cfg.Type {
	case TypeRawTCP:
		unified.Mode = rawtcp.RawModeTCP
		unified.TCP.Interface = cfg.Interface
	case TypeFakeTCP:
		unified.Mode = rawtcp.RawModeFakeTCP
		unified.FakeTCP = rawtcpFakeTCPConfigFrom(cfg)
	case TypeICMP:
		unified.Mode = rawtcp.RawModeICMP
		unified.ICMP = rawtcpICMPConfigFrom(cfg)
	default:
		return nil, fmt.Errorf("unknown packet type: %s", cfg.Type)
	}

	inner, err := rawtcp.NewUnifiedListener(addr, unified)
	if err != nil {
		return nil, err
	}

	return &Listener{
		cfg:      cfg,
		smux:     smuxCfg,
		listener: inner,
	}, nil
}

// Accept accepts a raw packet connection
func (l *Listener) Accept() (net.Conn, error) {
	if l.closed {
		return nil, fmt.Errorf("listener closed")
	}
	if l.listener == nil {
		return nil, fmt.Errorf("listener not initialized")
	}

	sess, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}

	// Server side must accept the first client-opened stream from the session.
	stream, err := sess.AcceptStream()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}

	return &sessionStreamConn{Conn: stream, sess: sess}, nil
}

// Close closes the listener
func (l *Listener) Close() error {
	l.closed = true
	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

// Addr returns the listener address
func (l *Listener) Addr() net.Addr {
	if l.listener != nil {
		return l.listener.Addr()
	}
	return nil
}

type sessionStreamConn struct {
	net.Conn
	sess transport.Session
}

func (c *sessionStreamConn) Close() error {
	if c.Conn != nil {
		_ = c.Conn.Close()
	}
	if c.sess != nil {
		return c.sess.Close()
	}
	return nil
}

// PacketConn wraps a raw packet connection with additional features
type PacketConn struct {
	typ     PacketType
	conn    net.PacketConn
	config  *Config
	smux    *smux.Config
	state   *TCPStateMachine
	peer    net.Addr
	tcpSeq  uint32
	icmpSeq uint16
}

// NewPacketConn creates a new packet connection wrapper
func NewPacketConn(conn net.PacketConn, typ PacketType, config *Config) *PacketConn {
	if config == nil {
		config = DefaultConfig()
	}
	if config.MTU <= 0 {
		config.MTU = 1400
	}

	pc := &PacketConn{
		typ:     typ,
		conn:    conn,
		config:  config,
		tcpSeq:  uint32(time.Now().UnixNano()),
		icmpSeq: config.ICMP.SequenceStart,
	}

	if typ == TypeFakeTCP && config.Recovery.StateMachine {
		pc.state = NewTCPStateMachine()
	}

	return pc
}

// Read reads data from the connection
func (pc *PacketConn) Read(p []byte) (int, error) {
	// Read packet
	buf := make([]byte, pc.config.MTU)
	n, addr, err := pc.conn.ReadFrom(buf)
	if err != nil {
		return 0, err
	}

	// Process based on type
	switch pc.typ {
	case TypeRawTCP, TypeFakeTCP:
		return pc.processTCPPacket(buf[:n], addr, p)
	case TypeICMP:
		return pc.processICMPPacket(buf[:n], addr, p)
	default:
		return 0, fmt.Errorf("unknown packet type")
	}
}

// Write writes data to the connection
func (pc *PacketConn) Write(p []byte) (int, error) {
	switch pc.typ {
	case TypeRawTCP, TypeFakeTCP:
		return pc.writeTCPPacket(p)
	case TypeICMP:
		return pc.writeICMPPacket(p)
	default:
		return 0, fmt.Errorf("unknown packet type")
	}
}

func (pc *PacketConn) processTCPPacket(data []byte, addr net.Addr, out []byte) (int, error) {
	if len(data) < 20 {
		return 0, fmt.Errorf("TCP packet too short")
	}
	pc.peer = addr

	seq := binary.BigEndian.Uint32(data[4:8])
	ack := binary.BigEndian.Uint32(data[8:12])
	headerLen := int((data[12]>>4)&0x0F) * 4
	if headerLen < 20 || headerLen > len(data) {
		return 0, fmt.Errorf("invalid TCP header length")
	}

	flags := TCPFlag(data[13])
	if pc.state != nil {
		switch {
		case flags&TCPFlagSYN != 0 && flags&TCPFlagACK != 0:
			_ = pc.state.ProcessSYNACK(seq, ack, nil)
		case flags&TCPFlagSYN != 0:
			_ = pc.state.ProcessSYN(seq, nil)
		case flags&TCPFlagFIN != 0:
			_ = pc.state.ProcessFIN(seq)
		case flags&TCPFlagACK != 0:
			_ = pc.state.ProcessACK(ack)
		}
	}

	payload := data[headerLen:]
	if len(payload) == 0 {
		return 0, nil
	}
	n := copy(out, payload)
	if n < len(payload) {
		return n, nil
	}
	return n, nil
}

func (pc *PacketConn) processICMPPacket(data []byte, addr net.Addr, out []byte) (int, error) {
	if len(data) < 8 {
		return 0, fmt.Errorf("ICMP packet too short")
	}
	pc.peer = addr

	typ := data[0]
	if typ != icmptun.ICMPTypeEchoReply && typ != icmptun.ICMPTypeEchoRequest {
		return 0, nil
	}
	payload := make([]byte, len(data)-8)
	copy(payload, data[8:])
	if pc.config.ICMP.Obfuscate {
		xorPayload(payload, pc.icmpMask())
	}
	n := copy(out, payload)
	return n, nil
}

func (pc *PacketConn) writeTCPPacket(data []byte) (int, error) {
	addr := pc.config.RemoteAddr
	if addr == nil {
		addr = pc.peer
	}
	if addr == nil {
		return 0, fmt.Errorf("remote address not set")
	}

	srcPort := uint16(0)
	dstPort := uint16(0)
	if la, ok := pc.config.LocalAddr.(*net.TCPAddr); ok {
		srcPort = uint16(la.Port)
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		dstPort = uint16(a.Port)
	case *net.UDPAddr:
		dstPort = uint16(a.Port)
	}

	flags := byte(TCPFlagPSH | TCPFlagACK)
	seq := pc.tcpSeq
	ack := uint32(0)
	payload := data

	if pc.state != nil {
		if !pc.state.CanSendData() {
			if syn, err := pc.state.SendSYN(); err == nil {
				flags = byte(syn.Flags)
				seq = syn.Seq
				ack = syn.Ack
				payload = nil
			}
		} else if info, err := pc.state.SendData(data); err == nil {
			flags = byte(info.Flags)
			seq = info.Seq
			ack = info.Ack
			payload = info.Data
		}
	}

	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], srcPort)
	binary.BigEndian.PutUint16(header[2:4], dstPort)
	binary.BigEndian.PutUint32(header[4:8], seq)
	binary.BigEndian.PutUint32(header[8:12], ack)
	header[12] = 5 << 4 // data offset
	header[13] = flags
	window := uint16(pc.config.TCPFlags.WindowSize)
	if window == 0 {
		window = 65535
	}
	binary.BigEndian.PutUint16(header[14:16], window)
	packet := append(header, payload...)
	binary.BigEndian.PutUint16(packet[16:18], internetChecksum(packet))

	_, err := pc.conn.WriteTo(packet, addr)
	if err != nil {
		return 0, err
	}

	pc.tcpSeq = seq + uint32(len(payload))
	return len(data), nil
}

func (pc *PacketConn) writeICMPPacket(data []byte) (int, error) {
	addr := pc.config.RemoteAddr
	if addr == nil {
		addr = pc.peer
	}
	if addr == nil {
		return 0, fmt.Errorf("remote address not set")
	}

	payload := make([]byte, len(data))
	copy(payload, data)
	if pc.config.ICMP.Obfuscate {
		xorPayload(payload, pc.icmpMask())
	}

	packet := make([]byte, 8+len(payload))
	packet[0] = icmptun.ICMPTypeEchoRequest
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[4:6], pc.config.ICMP.ID)
	binary.BigEndian.PutUint16(packet[6:8], pc.icmpSeq)
	copy(packet[8:], payload)
	binary.BigEndian.PutUint16(packet[2:4], internetChecksum(packet))

	if _, err := pc.conn.WriteTo(packet, addr); err != nil {
		return 0, err
	}
	pc.icmpSeq++
	return len(data), nil
}

func (pc *PacketConn) icmpMask() []byte {
	if pc.config.ICMP.ObfuscationKey != "" {
		return []byte(pc.config.ICMP.ObfuscationKey)
	}
	mask := make([]byte, 2)
	binary.BigEndian.PutUint16(mask, pc.config.ICMP.ID)
	return mask
}

func xorPayload(buf, mask []byte) {
	if len(mask) == 0 {
		return
	}
	for i := range buf {
		buf[i] ^= mask[i%len(mask)]
	}
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Close closes the connection
func (pc *PacketConn) Close() error {
	return pc.conn.Close()
}

// LocalAddr returns the local address
func (pc *PacketConn) LocalAddr() net.Addr {
	return pc.conn.LocalAddr()
}

// RemoteAddr returns the remote address
func (pc *PacketConn) RemoteAddr() net.Addr {
	return pc.config.RemoteAddr
}

// SetDeadline sets the deadline
func (pc *PacketConn) SetDeadline(t time.Time) error {
	return pc.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (pc *PacketConn) SetReadDeadline(t time.Time) error {
	return pc.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (pc *PacketConn) SetWriteDeadline(t time.Time) error {
	return pc.conn.SetWriteDeadline(t)
}

// Ensure PacketConn implements net.Conn
var _ net.Conn = (*PacketConn)(nil)
