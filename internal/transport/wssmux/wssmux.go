package wssmux

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"

	"stealthlink/internal/tlsutil"
	"stealthlink/internal/transport"

	"github.com/xtaci/smux"
	"nhooyr.io/websocket"
)

type Dialer struct {
	URL         string
	Origin      string
	TLSConfig   *tls.Config
	Smux        *smux.Config
	Fingerprint string
	ConnectAddr string
	Headers     map[string]string
	Guard       string
	ProxyDial   func(ctx context.Context, network, addr string) (net.Conn, error)
	uaRotator   *UserAgentRotator
}

type Listener struct {
	server   *http.Server
	ln       net.Listener
	path     string
	smux     *smux.Config
	guard    string
	padMin   int
	padMax   int
	sessions chan transport.Session
	once     sync.Once
}

func NewDialer(url, origin string, tlsCfg *tls.Config, smuxCfg *smux.Config, fingerprint, connectAddr, guard string) *Dialer {
	return &Dialer{URL: url, Origin: origin, TLSConfig: tlsCfg, Smux: smuxCfg, Fingerprint: fingerprint, ConnectAddr: connectAddr, Guard: guard}
}

// NewDialerWithUA creates a dialer with User-Agent rotation support.
func NewDialerWithUA(url, origin string, tlsCfg *tls.Config, smuxCfg *smux.Config, fingerprint, connectAddr, guard string, uaRotator *UserAgentRotator) *Dialer {
	return &Dialer{
		URL: url, Origin: origin, TLSConfig: tlsCfg, Smux: smuxCfg,
		Fingerprint: fingerprint, ConnectAddr: connectAddr, Guard: guard,
		uaRotator: uaRotator,
	}
}

func Listen(addr, path string, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string, padMin, padMax int) (*Listener, error) {
	if path == "" {
		path = "/_sl"
	}
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		ln:       ln,
		path:     path,
		smux:     smuxCfg,
		guard:    guard,
		padMin:   padMin,
		padMax:   padMax,
		sessions: make(chan transport.Session, 16),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, l.handleWS)
	l.server = &http.Server{Handler: mux}
	go func() {
		_ = l.server.Serve(ln)
	}()
	return l, nil
}

func (d *Dialer) Dial(ctx context.Context, _ string) (transport.Session, error) {
	opts := &websocket.DialOptions{}
	if d.Origin != "" {
		opts.HTTPHeader = http.Header{"Origin": []string{d.Origin}}
	}
	if len(d.Headers) > 0 {
		if opts.HTTPHeader == nil {
			opts.HTTPHeader = http.Header{}
		}
		for k, v := range d.Headers {
			opts.HTTPHeader.Set(k, v)
		}
	}

	// Add User-Agent (from rotation if enabled, otherwise from headers or default)
	if opts.HTTPHeader == nil {
		opts.HTTPHeader = http.Header{}
	}
	if d.uaRotator != nil {
		opts.HTTPHeader.Set("User-Agent", d.uaRotator.Get())
	} else if _, hasUA := d.Headers["User-Agent"]; !hasUA {
		opts.HTTPHeader.Set("User-Agent", RandomUserAgent())
	}
	if d.TLSConfig != nil {
		tlsCfg, _ := tlsutil.EnsureServerName(d.TLSConfig, hostFromURL(d.URL))
		dialer := d.ProxyDial
		if dialer == nil {
			dialer = (&net.Dialer{}).DialContext
		}
		opts.HTTPClient = &http.Client{Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialAddr := addr
				if d.ConnectAddr != "" {
					dialAddr = d.ConnectAddr
				}
				conn, err := dialer(ctx, network, dialAddr)
				if err != nil {
					return nil, err
				}
				return tlsutil.WrapUTLS(ctx, conn, tlsCfg, d.Fingerprint)
			},
		}}
	}
	c, _, err := websocket.Dial(ctx, d.URL, opts)
	if err != nil {
		return nil, err
	}
	conn := websocket.NetConn(ctx, c, websocket.MessageBinary)
	if err := transport.SendGuard(conn, d.Guard); err != nil {
		_ = conn.Close()
		return nil, err
	}
	sess, err := smux.Client(conn, d.Smux)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &session{conn: conn, sess: sess}, nil
}

func (l *Listener) Accept() (transport.Session, error) {
	sess, ok := <-l.sessions
	if !ok {
		return nil, fmt.Errorf("listener closed")
	}
	return sess, nil
}

func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.sessions)
		err = l.server.Close()
	})
	return err
}

func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

func (l *Listener) handleWS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if pad := padHeaderValue(l.padMin, l.padMax); pad != "" {
		w.Header().Set("X-Pad", pad)
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	conn := websocket.NetConn(r.Context(), c, websocket.MessageBinary)
	if err := transport.RecvGuard(conn, l.guard); err != nil {
		_ = conn.Close()
		return
	}
	sess, err := smux.Server(conn, l.smux)
	if err != nil {
		_ = conn.Close()
		return
	}
	select {
	case l.sessions <- &session{conn: conn, sess: sess}:
	default:
		_ = conn.Close()
	}
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

type session struct {
	conn net.Conn
	sess *smux.Session
}

func (s *session) OpenStream() (net.Conn, error)   { return s.sess.OpenStream() }
func (s *session) AcceptStream() (net.Conn, error) { return s.sess.AcceptStream() }
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
