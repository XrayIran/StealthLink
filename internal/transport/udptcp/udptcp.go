// Package udptcp provides UDP-over-TCP fallback when UDP is blocked.
// It encapsulates UDP traffic in TCP connections with length-prefixed framing.
package udptcp

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Config holds UDP-over-TCP configuration.
type Config struct {
	BufferSize int           // Read/write buffer size
	Timeout    time.Duration // Read/write timeout
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		BufferSize: 65535,
		Timeout:    30 * time.Second,
	}
}

// Wrapper wraps a TCP connection to provide UDP-like semantics.
type Wrapper struct {
	conn       net.Conn
	bufferSize int
	timeout    time.Duration
	readBuf    []byte
	writeMu    sync.Mutex
	readMu     sync.Mutex
}

// Wrap wraps an existing TCP connection.
func Wrap(conn net.Conn, cfg *Config) *Wrapper {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Wrapper{
		conn:       conn,
		bufferSize: cfg.BufferSize,
		timeout:    cfg.Timeout,
		readBuf:    make([]byte, cfg.BufferSize),
	}
}

// Dial connects to a UDP-over-TCP server.
func Dial(addr string, cfg *Config) (*Wrapper, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	return Wrap(conn, cfg), nil
}

// Listen creates a UDP-over-TCP listener.
func Listen(addr string, cfg *Config) (net.Listener, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &listener{
		Listener: ln,
		config:   cfg,
	}, nil
}

// ReadFromUDP reads a UDP packet from the wrapped connection.
func (w *Wrapper) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()

	if w.timeout > 0 {
		w.conn.SetReadDeadline(time.Now().Add(w.timeout))
		defer w.conn.SetReadDeadline(time.Time{})
	}

	// Read length prefix
	var lengthBuf [4]byte
	if _, err := io.ReadFull(w.conn, lengthBuf[:]); err != nil {
		return 0, nil, err
	}

	length := binary.BigEndian.Uint32(lengthBuf[:])
	if length > uint32(w.bufferSize) {
		return 0, nil, fmt.Errorf("packet too large: %d", length)
	}

	// Read packet data
	if length > uint32(len(b)) {
		// Packet larger than buffer, read and discard excess
		if _, err := io.ReadFull(w.conn, b); err != nil {
			return 0, nil, err
		}
		// Discard remaining
		remaining := int(length) - len(b)
		io.CopyN(io.Discard, w.conn, int64(remaining))
		return len(b), nil, nil
	}

	if _, err := io.ReadFull(w.conn, b[:length]); err != nil {
		return 0, nil, err
	}

	// Return nil address since we don't have the original UDP address
	return int(length), nil, nil
}

// WriteToUDP writes a UDP packet to the wrapped connection.
func (w *Wrapper) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if w.timeout > 0 {
		w.conn.SetWriteDeadline(time.Now().Add(w.timeout))
		defer w.conn.SetWriteDeadline(time.Time{})
	}

	// Write length prefix
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(b)))

	if _, err := w.conn.Write(lengthBuf); err != nil {
		return 0, err
	}

	// Write packet data
	return w.conn.Write(b)
}

// Read implements net.Conn.
func (w *Wrapper) Read(b []byte) (int, error) {
	n, _, err := w.ReadFromUDP(b)
	return n, err
}

// Write implements net.Conn.
func (w *Wrapper) Write(b []byte) (int, error) {
	return w.WriteToUDP(b, nil)
}

// Close implements net.Conn.
func (w *Wrapper) Close() error {
	return w.conn.Close()
}

// LocalAddr implements net.Conn.
func (w *Wrapper) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

// RemoteAddr implements net.Conn.
func (w *Wrapper) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

// SetDeadline implements net.Conn.
func (w *Wrapper) SetDeadline(t time.Time) error {
	return w.conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (w *Wrapper) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (w *Wrapper) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

// Conn returns the underlying TCP connection.
func (w *Wrapper) Conn() net.Conn {
	return w.conn
}

// listener wraps a TCP listener to return UDP-over-TCP wrappers.
type listener struct {
	net.Listener
	config *Config
}

// Accept accepts a new connection and wraps it.
func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Wrap(conn, l.config), nil
}

// PacketConn wraps a UDP-over-TCP connection to implement net.PacketConn.
type PacketConn struct {
	*Wrapper
	localAddr *net.UDPAddr
}

// ReadFrom implements net.PacketConn.
func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return p.Wrapper.ReadFromUDP(b)
}

// WriteTo implements net.PacketConn.
func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("address must be *net.UDPAddr")
	}
	return p.Wrapper.WriteToUDP(b, udpAddr)
}

// LocalAddr implements net.PacketConn.
func (p *PacketConn) LocalAddr() net.Addr {
	if p.localAddr != nil {
		return p.localAddr
	}
	return p.Wrapper.LocalAddr()
}

// SetDeadline implements net.PacketConn.
func (p *PacketConn) SetDeadline(t time.Time) error {
	return p.Wrapper.SetDeadline(t)
}

// SetReadDeadline implements net.PacketConn.
func (p *PacketConn) SetReadDeadline(t time.Time) error {
	return p.Wrapper.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn.
func (p *PacketConn) SetWriteDeadline(t time.Time) error {
	return p.Wrapper.SetWriteDeadline(t)
}
