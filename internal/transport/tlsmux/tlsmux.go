package tlsmux

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"stealthlink/internal/tlsutil"
	"stealthlink/internal/transport"

	"github.com/xtaci/smux"
)

type Dialer struct {
	TLSConfig   *tls.Config
	Smux        *smux.Config
	Fingerprint string
	Guard       string
	ProxyDial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

type Listener struct {
	ln    net.Listener
	smux  *smux.Config
	guard string
}

func NewDialer(cfg *tls.Config, smuxCfg *smux.Config, fingerprint, guard string) *Dialer {
	return &Dialer{TLSConfig: cfg, Smux: smuxCfg, Fingerprint: fingerprint, Guard: guard}
}

func Listen(addr string, cfg *tls.Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return &Listener{ln: ln, smux: smuxCfg, guard: guard}, nil
}

func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	tlsCfg, _ := tlsutil.EnsureServerName(d.TLSConfig, addr)
	dialer := d.ProxyDial
	if dialer == nil {
		dialer = (&net.Dialer{}).DialContext
	}
	conn, err := dialer(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn, err := tlsutil.WrapUTLS(ctx, conn, tlsCfg, d.Fingerprint)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := transport.SendGuard(tlsConn, d.Guard); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	sess, err := smux.Client(tlsConn, d.Smux)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return &session{conn: tlsConn, sess: sess}, nil
}

func (l *Listener) Accept() (transport.Session, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("expected tls.Conn")
	}
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if err := transport.RecvGuard(tlsConn, l.guard); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	sess, err := smux.Server(tlsConn, l.smux)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return &session{conn: tlsConn, sess: sess}, nil
}

func (l *Listener) Close() error {
	return l.ln.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}

type session struct {
	conn net.Conn
	sess *smux.Session
}

func (s *session) OpenStream() (net.Conn, error) {
	return s.sess.OpenStream()
}

func (s *session) AcceptStream() (net.Conn, error) {
	return s.sess.AcceptStream()
}

func (s *session) Close() error {
	if s.sess != nil {
		_ = s.sess.Close()
	}
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *session) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }
