// Package multiport implements multi-port listening using iptables REDIRECT.
// Based on WaterWall's approach.
package multiport

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"stealthlink/internal/transport"
)

// Listener listens on a single port but handles connections
// that were redirected from multiple ports using iptables REDIRECT.
type Listener struct {
	ln         net.Listener
	sessions   chan transport.Session
	 handler    func(net.Conn) (transport.Session, error)
	closed     atomic.Bool
	wg         sync.WaitGroup
}

// Listen creates a new multi-port listener.
// The handler function should wrap the connection in a transport.Session.
func Listen(addr string, handler func(net.Conn) (transport.Session, error)) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		ln:       ln,
		sessions: make(chan transport.Session, 16),
		handler:  handler,
	}

	go l.acceptLoop()
	return l, nil
}

func (l *Listener) acceptLoop() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			continue
		}

		// Get original destination
		origDst, err := GetOriginalDestination(conn)
		if err != nil {
			// If we can't get original dest, use local addr
			origDst = &net.TCPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 0,
			}
		}

		l.wg.Add(1)
		go func(c net.Conn, dst *net.TCPAddr) {
			defer l.wg.Done()
			l.handleConn(c, dst)
		}(conn, origDst)
	}
}

func (l *Listener) handleConn(conn net.Conn, origDst *net.TCPAddr) {
	// Wrap connection with original destination info
	wrapped := &connWithDst{
		Conn:    conn,
		origDst: origDst,
	}

	sess, err := l.handler(wrapped)
	if err != nil {
		conn.Close()
		return
	}

	select {
	case l.sessions <- sess:
	default:
		sess.Close()
	}
}

// Accept accepts a session.
func (l *Listener) Accept() (transport.Session, error) {
	sess, ok := <-l.sessions
	if !ok {
		return nil, fmt.Errorf("listener closed")
	}
	return sess, nil
}

// Close closes the listener.
func (l *Listener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		l.ln.Close()
		close(l.sessions)
		l.wg.Wait()
	}
	return nil
}

// Addr returns the listen address.
func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}

// connWithDst wraps a connection with original destination info.
type connWithDst struct {
	net.Conn
	origDst *net.TCPAddr
}

// OriginalDestination returns the original destination.
func (c *connWithDst) OriginalDestination() *net.TCPAddr {
	return c.origDst
}

// PortMapper maps external ports to internal services.
type PortMapper struct {
	mu       sync.RWMutex
	mappings map[int]string // port -> service name
}

// NewPortMapper creates a new port mapper.
func NewPortMapper() *PortMapper {
	return &PortMapper{
		mappings: make(map[int]string),
	}
}

// Register registers a port mapping.
func (pm *PortMapper) Register(port int, service string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.mappings[port] = service
}

// Unregister removes a port mapping.
func (pm *PortMapper) Unregister(port int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.mappings, port)
}

// Lookup returns the service for a port.
func (pm *PortMapper) Lookup(port int) (string, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	service, ok := pm.mappings[port]
	return service, ok
}

// MultiPortListener listens on multiple ports.
type MultiPortListener struct {
	listeners map[int]net.Listener
	sessions  chan transport.Session
	handler   func(net.Conn, int) (transport.Session, error)
	mu        sync.RWMutex
	closed    atomic.Bool
	wg        sync.WaitGroup
}

// NewMultiPort creates a multi-port listener.
func NewMultiPort(handler func(net.Conn, int) (transport.Session, error)) *MultiPortListener {
	return &MultiPortListener{
		listeners: make(map[int]net.Listener),
		sessions:  make(chan transport.Session, 64),
		handler:   handler,
	}
}

// AddPort adds a port to listen on.
func (m *MultiPortListener) AddPort(port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.listeners[port]; ok {
		return fmt.Errorf("port %d already added", port)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}

	m.listeners[port] = ln

	m.wg.Add(1)
	go m.acceptLoop(ln, port)

	return nil
}

// RemovePort removes a port.
func (m *MultiPortListener) RemovePort(port int) error {
	m.mu.Lock()
	ln, ok := m.listeners[port]
	delete(m.listeners, port)
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("port %d not found", port)
	}

	return ln.Close()
}

func (m *MultiPortListener) acceptLoop(ln net.Listener, port int) {
	defer m.wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if m.closed.Load() {
				return
			}
			continue
		}

		m.wg.Add(1)
		go func(c net.Conn, p int) {
			defer m.wg.Done()
			m.handleConn(c, p)
		}(conn, port)
	}
}

func (m *MultiPortListener) handleConn(conn net.Conn, port int) {
	sess, err := m.handler(conn, port)
	if err != nil {
		conn.Close()
		return
	}

	select {
	case m.sessions <- sess:
	default:
		sess.Close()
	}
}

// Accept accepts a session.
func (m *MultiPortListener) Accept() (transport.Session, error) {
	sess, ok := <-m.sessions
	if !ok {
		return nil, fmt.Errorf("listener closed")
	}
	return sess, nil
}

// Close closes all listeners.
func (m *MultiPortListener) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		m.mu.RLock()
		listeners := make([]net.Listener, 0, len(m.listeners))
		for _, ln := range m.listeners {
			listeners = append(listeners, ln)
		}
		m.mu.RUnlock()

		for _, ln := range listeners {
			ln.Close()
		}

		close(m.sessions)
		m.wg.Wait()
	}
	return nil
}

// Addr returns the first listener's address (for transport.Listener interface).
func (m *MultiPortListener) Addr() net.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ln := range m.listeners {
		return ln.Addr()
	}
	return nil
}

// GetPorts returns the list of listening ports.
func (m *MultiPortListener) GetPorts() []int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ports := make([]int, 0, len(m.listeners))
	for port := range m.listeners {
		ports = append(ports, port)
	}
	return ports
}
