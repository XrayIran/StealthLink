package warp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type StealthWrap struct {
	tunnel    *Tunnel
	mu        sync.RWMutex
	enabled   bool
	mode      string
	vpnSubnet string
}

func NewStealthWrap(cfg Config) (*StealthWrap, error) {
	if !cfg.Enabled {
		return &StealthWrap{enabled: false}, nil
	}

	tunnel, err := NewTunnel(cfg)
	if err != nil {
		return nil, fmt.Errorf("create WARP tunnel: %w", err)
	}

	return &StealthWrap{
		tunnel:    tunnel,
		enabled:   true,
		mode:      cfg.RoutingMode,
		vpnSubnet: cfg.VPNSubnet,
	}, nil
}

func (w *StealthWrap) Start(ctx context.Context) error {
	if !w.enabled || w.tunnel == nil {
		return nil
	}
	return w.tunnel.Start()
}

func (w *StealthWrap) Stop() error {
	if !w.enabled || w.tunnel == nil {
		return nil
	}
	return w.tunnel.Close()
}

func (w *StealthWrap) IsEnabled() bool {
	return w.enabled
}

func (w *StealthWrap) GetTunnel() *Tunnel {
	if !w.enabled {
		return nil
	}
	return w.tunnel
}

type WARPDialer struct {
	underlying net.Dialer
	wrap       *StealthWrap
	network    string
	addr       string
}

func (w *StealthWrap) WrapDialer(dialer *net.Dialer) *WARPDialer {
	return &WARPDialer{
		underlying: *dialer,
		wrap:       w,
	}
}

func (d *WARPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !d.wrap.enabled {
		return d.underlying.DialContext(ctx, network, addr)
	}

	if !ShouldRouteViaWARP(d.wrap.mode, addr, d.wrap.vpnSubnet) {
		return d.underlying.DialContext(ctx, network, addr)
	}

	conn, err := d.underlying.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	return &warpConnWrapper{Conn: conn, wrap: d.wrap}, nil
}

func (d *WARPDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

type warpConnWrapper struct {
	net.Conn
	wrap *StealthWrap
}

func (c *warpConnWrapper) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}

func (c *warpConnWrapper) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

func (c *warpConnWrapper) Close() error {
	return c.Conn.Close()
}

func (c *warpConnWrapper) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *warpConnWrapper) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *warpConnWrapper) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *warpConnWrapper) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *warpConnWrapper) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

type WARPListener struct {
	underlying net.Listener
	wrap       *StealthWrap
}

func (w *StealthWrap) WrapListener(listener net.Listener) *WARPListener {
	return &WARPListener{
		underlying: listener,
		wrap:       w,
	}
}

// WrapConn wraps an existing connection with WARP metadata.
func (w *StealthWrap) WrapConn(conn net.Conn) net.Conn {
	if conn == nil || !w.enabled {
		return conn
	}
	return &warpConnWrapper{Conn: conn, wrap: w}
}

func (l *WARPListener) Accept() (net.Conn, error) {
	conn, err := l.underlying.Accept()
	if err != nil {
		return nil, err
	}

	if !l.wrap.enabled {
		return conn, nil
	}

	return &warpConnWrapper{Conn: conn, wrap: l.wrap}, nil
}

func (l *WARPListener) Close() error {
	return l.underlying.Close()
}

func (l *WARPListener) Addr() net.Addr {
	return l.underlying.Addr()
}

func (w *StealthWrap) GetStats() TunnelStats {
	if !w.enabled || w.tunnel == nil {
		return TunnelStats{}
	}
	return w.tunnel.Stats()
}

func (w *StealthWrap) SetErrorHandler(fn func(error)) {
	if w.enabled && w.tunnel != nil {
		w.tunnel.SetErrorHandler(fn)
	}
}

type WARPConn struct {
	conn       net.Conn
	tunnel     *Tunnel
	localAddr  net.Addr
	remoteAddr net.Addr
	mu         sync.Mutex
	closed     bool
}

func (c *WARPConn) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *WARPConn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *WARPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

func (c *WARPConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return c.conn.LocalAddr()
}

func (c *WARPConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.conn.RemoteAddr()
}

func (c *WARPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *WARPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *WARPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func IsVPNReturnTraffic(srcIP string, vpnSubnet string) bool {
	if vpnSubnet == "" {
		return false
	}
	ip := net.ParseIP(srcIP)
	if ip == nil {
		host, _, err := net.SplitHostPort(srcIP)
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
		if ip == nil {
			return false
		}
	}
	_, subnet, err := net.ParseCIDR(vpnSubnet)
	if err != nil {
		return false
	}
	return subnet.Contains(ip)
}

func ShouldRouteViaWARP(mode string, dstIP string, vpnSubnet string) bool {
	switch mode {
	case "all":
		return true
	case "vpn_only":
		return IsVPNReturnTraffic(dstIP, vpnSubnet)
	default:
		return false
	}
}

type RoutingDecision struct {
	UseWARP     bool
	Reason      string
	Destination string
}

func DecideRouting(mode string, dst string, vpnSubnet string) RoutingDecision {
	if mode == "all" {
		return RoutingDecision{
			UseWARP:     true,
			Reason:      "full_tunnel_mode",
			Destination: dst,
		}
	}

	if mode == "vpn_only" && IsVPNReturnTraffic(dst, vpnSubnet) {
		return RoutingDecision{
			UseWARP:     true,
			Reason:      "vpn_return_traffic",
			Destination: dst,
		}
	}

	return RoutingDecision{
		UseWARP:     false,
		Reason:      "direct_connection",
		Destination: dst,
	}
}
