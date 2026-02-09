package carrier

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
)

// QUICCarrier uses native QUIC as the underlying transport.
// This is the default carrier when no specific carrier is configured.
type QUICCarrier struct {
	tlsConf  *tls.Config
	quicConf *quic.Config
	listener *quic.Listener
}

// NewQUICCarrier creates a new QUIC carrier
func NewQUICCarrier(tlsConf *tls.Config, quicConf *quic.Config) *QUICCarrier {
	return &QUICCarrier{
		tlsConf:  tlsConf,
		quicConf: quicConf,
	}
}

// Network returns "quic"
func (c *QUICCarrier) Network() string {
	return "quic"
}

// Dial establishes a QUIC connection to the address
func (c *QUICCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	// This method is not typically used directly - UQSP dialer handles QUIC connections natively
	// But we implement it for completeness
	conn, err := quic.DialAddr(ctx, addr, c.tlsConf, c.quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	// Open a stream for the connection
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "stream open failed")
		return nil, fmt.Errorf("quic stream open: %w", err)
	}

	return &quicStreamConn{
		stream: stream,
		conn:   conn,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
	}, nil
}

// Listen creates a QUIC listener
func (c *QUICCarrier) Listen(addr string) (Listener, error) {
	ln, err := quic.ListenAddr(addr, c.tlsConf, c.quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic listen: %w", err)
	}
	c.listener = ln
	return &quicListener{ln: ln}, nil
}

// Close closes the carrier
func (c *QUICCarrier) Close() error {
	if c.listener != nil {
		return c.listener.Close()
	}
	return nil
}

// IsAvailable returns true (QUIC is always available)
func (c *QUICCarrier) IsAvailable() bool {
	return true
}

// quicListener wraps a QUIC listener
type quicListener struct {
	ln *quic.Listener
}

func (l *quicListener) Accept() (net.Conn, error) {
	conn, err := l.ln.Accept(context.Background())
	if err != nil {
		return nil, err
	}

	// Accept a stream
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(0, "stream accept failed")
		return nil, err
	}

	return &quicStreamConn{
		stream: stream,
		conn:   conn,
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
	}, nil
}

func (l *quicListener) Close() error {
	return l.ln.Close()
}

func (l *quicListener) Addr() net.Addr {
	return l.ln.Addr()
}

// quicStreamConn adapts quic.Stream to net.Conn
type quicStreamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
	local  net.Addr
	remote net.Addr
}

func (c *quicStreamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *quicStreamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *quicStreamConn) Close() error {
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
	return c.stream.Close()
}
func (c *quicStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.remote }
func (c *quicStreamConn) SetDeadline(t time.Time) error {
	if err := c.stream.SetReadDeadline(t); err != nil {
		return err
	}
	return c.stream.SetWriteDeadline(t)
}
func (c *quicStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// Ensure we implement net.Conn
var _ net.Conn = (*quicStreamConn)(nil)
