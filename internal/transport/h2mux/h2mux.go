package h2mux

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"stealthlink/internal/tlsutil"
	"stealthlink/internal/transport"

	"github.com/xtaci/smux"
	"golang.org/x/net/http2"
)

type Dialer struct {
	URL         string
	TLSConfig   *tls.Config
	Smux        *smux.Config
	Fingerprint string
	ConnectAddr string
	Headers     map[string]string
	Guard       string
	ProxyDial   func(ctx context.Context, network, addr string) (net.Conn, error)
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

func NewDialer(url string, tlsCfg *tls.Config, smuxCfg *smux.Config, fingerprint, connectAddr, guard string) *Dialer {
	return &Dialer{URL: url, TLSConfig: tlsCfg, Smux: smuxCfg, Fingerprint: fingerprint, ConnectAddr: connectAddr, Guard: guard}
}

func Listen(addr, path string, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string, padMin, padMax int) (*Listener, error) {
	if path == "" {
		path = "/_sl"
	}
	if tlsCfg.NextProtos == nil {
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
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
	mux.HandleFunc(path, l.handleH2)
	l.server = &http.Server{Handler: mux}
	_ = http2.ConfigureServer(l.server, &http2.Server{})
	go func() {
		_ = l.server.Serve(ln)
	}()
	return l, nil
}

func (d *Dialer) Dial(ctx context.Context, _ string) (transport.Session, error) {
	tlsCfg, _ := tlsutil.EnsureServerName(d.TLSConfig, hostFromURL(d.URL))
	if tlsCfg.NextProtos == nil {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	}
	dialer := d.ProxyDial
	if dialer == nil {
		dialer = (&net.Dialer{}).DialContext
	}
	tr := &http2.Transport{
		TLSClientConfig: tlsCfg,
		AllowHTTP:       false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			dialAddr := addr
			if d.ConnectAddr != "" {
				dialAddr = d.ConnectAddr
			}
			conn, err := dialer(ctx, network, dialAddr)
			if err != nil {
				return nil, err
			}
			return tlsutil.WrapUTLS(ctx, conn, cfg, d.Fingerprint)
		},
	}
	client := &http.Client{Transport: tr}
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, pr)
	if err != nil {
		return nil, err
	}
	for k, v := range d.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("h2 connect failed: %s", resp.Status)
	}
	conn := &streamConn{
		reader: resp.Body,
		writer: pw,
		local:  dummyAddr("h2-client"),
		remote: dummyAddr("h2-server"),
	}
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

func (l *Listener) handleH2(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	fl, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	if pad := padHeaderValue(l.padMin, l.padMax); pad != "" {
		w.Header().Set("X-Pad", pad)
	}
	w.WriteHeader(http.StatusOK)
	if fl != nil {
		fl.Flush()
	}
	conn := &streamConn{
		reader: r.Body,
		writer: writeFlusher{w: w, fl: fl},
		local:  dummyAddr("h2-server"),
		remote: dummyAddr(r.RemoteAddr),
	}
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
	<-r.Context().Done()
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

type streamConn struct {
	reader io.ReadCloser
	writer io.WriteCloser
	local  net.Addr
	remote net.Addr
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *streamConn) Close() error {
	_ = c.writer.Close()
	return c.reader.Close()
}
func (c *streamConn) LocalAddr() net.Addr                { return c.local }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return nil }

type writeFlusher struct {
	w  io.Writer
	fl http.Flusher
}

func (wf writeFlusher) Write(p []byte) (int, error) {
	n, err := wf.w.Write(p)
	if wf.fl != nil {
		wf.fl.Flush()
	}
	return n, err
}

func (wf writeFlusher) Close() error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "h2" }
func (d dummyAddr) String() string  { return string(d) }
