// Package tproxy provides Linux transparent proxy support using TPROXY.
package tproxy

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

var execCommand = exec.Command

// Server implements a transparent proxy server.
type Server struct {
	ListenAddr  string
	CaptureMode string // "tproxy" or "redirect"
	Rules       []Rule
	listener    net.Listener
}

// Rule represents a routing rule.
type Rule struct {
	SrcCIDR   string
	DstCIDR   string
	Protocol  string // tcp, udp, or ""
	Action    string // accept, drop, bypass
	Interface string
}

// NewServer creates a new TPROXY server.
func NewServer(addr, mode string) *Server {
	if mode == "" {
		mode = "tproxy"
	}
	return &Server{
		ListenAddr:  addr,
		CaptureMode: mode,
	}
}

// AddRule adds a routing rule.
func (s *Server) AddRule(rule Rule) {
	s.Rules = append(s.Rules, rule)
}

// Start starts the TPROXY server.
func (s *Server) Start() error {
	if s.CaptureMode == "tproxy" {
		return s.startTPROXY()
	}
	return s.startRedirect()
}

// startTPROXY starts in TPROXY mode.
func (s *Server) startTPROXY() error {
	addr, err := net.ResolveTCPAddr("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve address: %w", err)
	}

	// Create listener with IP_TRANSPARENT
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				// Enable IP_TRANSPARENT
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}

	ln, err := lc.Listen(nil, "tcp", addr.String())
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.listener = ln
	return nil
}

// startRedirect starts in REDIRECT mode.
func (s *Server) startRedirect() error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.listener = ln
	return nil
}

// Accept accepts a new connection.
func (s *Server) Accept() (net.Conn, error) {
	if s.listener == nil {
		return nil, fmt.Errorf("server not started")
	}
	return s.listener.Accept()
}

// Close closes the server.
func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Addr returns the server address.
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// SetupIPTables sets up iptables rules for TPROXY.
func SetupIPTables(listenPort int, mark int) error {
	// Create routing rule for marked packets
	cmd := execCommand("ip", "rule", "add", "fwmark", strconv.Itoa(mark), "lookup", "100")
	_ = cmd.Run() // Ignore error if already exists

	// Create routing table
	cmd = execCommand("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100")
	_ = cmd.Run()

	// Setup iptables rules
	// Mark TCP packets
	cmd = execCommand("iptables", "-t", "mangle", "-A", "PREROUTING", "-p", "tcp",
		"-j", "TPROXY", "--tproxy-mark", fmt.Sprintf("%d", mark), "--on-port", strconv.Itoa(listenPort))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables tproxy: %w", err)
	}

	return nil
}

// CleanupIPTables removes iptables rules.
func CleanupIPTables(listenPort int, mark int) error {
	// Remove iptables rules
	cmd := execCommand("iptables", "-t", "mangle", "-D", "PREROUTING", "-p", "tcp",
		"-j", "TPROXY", "--tproxy-mark", fmt.Sprintf("%d", mark), "--on-port", strconv.Itoa(listenPort))
	_ = cmd.Run()

	return nil
}

// GetOriginalDst gets the original destination of a TPROXY connection.
func GetOriginalDst(conn net.Conn) (net.Addr, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCP connection")
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("get original dst: not implemented for this platform")
	}

	file, err := tcpConn.File()
	if err != nil {
		return nil, fmt.Errorf("get file: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())
	const SO_ORIGINAL_DST = 80

	var addr syscall.RawSockaddrInet4
	addrLen := uint32(unsafe.Sizeof(addr))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IP),
		uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %v", errno)
	}

	return tcpAddrFromRawSockaddr(addr), nil
}

// RedirectServer implements a simple redirect server.
type RedirectServer struct {
	ListenAddr string
	TargetAddr string
	listener   net.Listener
}

// NewRedirectServer creates a new redirect server.
func NewRedirectServer(listenAddr, targetAddr string) *RedirectServer {
	return &RedirectServer{
		ListenAddr: listenAddr,
		TargetAddr: targetAddr,
	}
}

// Start starts the redirect server.
func (r *RedirectServer) Start() error {
	ln, err := net.Listen("tcp", r.ListenAddr)
	if err != nil {
		return err
	}
	r.listener = ln

	go r.serve()
	return nil
}

// serve handles incoming connections.
func (r *RedirectServer) serve() {
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return
		}

		go r.handle(conn)
	}
}

// handle handles a single connection.
func (r *RedirectServer) handle(conn net.Conn) {
	defer conn.Close()

	target, err := net.Dial("tcp", r.TargetAddr)
	if err != nil {
		return
	}
	defer target.Close()

	// Relay traffic
	go func() {
		io.Copy(target, conn)
		target.Close()
	}()
	io.Copy(conn, target)
}

// Close closes the server.
func (r *RedirectServer) Close() error {
	if r.listener != nil {
		return r.listener.Close()
	}
	return nil
}

func tcpAddrFromRawSockaddr(addr syscall.RawSockaddrInet4) *net.TCPAddr {
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(addr.Port>>8) | int(addr.Port<<8)
	return &net.TCPAddr{IP: ip, Port: port}
}
