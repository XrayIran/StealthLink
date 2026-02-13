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
	"stealthlink/internal/transport/xhttpmeta"

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
	Cookies     []*http.Cookie
	Guard       string
	ProxyDial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

type Listener struct {
	server      *http.Server
	ln          net.Listener
	path        string
	smux        *smux.Config
	guard       string
	padMin      int
	padMax      int
	metadataCfg xhttpmeta.MetadataConfig
	sessions    chan transport.Session
	done        chan struct{}
	once        sync.Once
}

func NewDialer(url string, tlsCfg *tls.Config, smuxCfg *smux.Config, fingerprint, connectAddr, guard string) *Dialer {
	return &Dialer{URL: url, TLSConfig: tlsCfg, Smux: smuxCfg, Fingerprint: fingerprint, ConnectAddr: connectAddr, Guard: guard}
}

func Listen(addr, path string, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string, padMin, padMax int, metaCfg xhttpmeta.MetadataConfig) (*Listener, error) {
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
		ln:          ln,
		path:        path,
		smux:        smuxCfg,
		guard:       guard,
		padMin:      padMin,
		padMax:      padMax,
		metadataCfg: metaCfg,
		sessions:    make(chan transport.Session, 16),
		done:        make(chan struct{}),
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
	for _, c := range d.Cookies {
		req.AddCookie(c)
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
	return &session{conn: conn, sess: sess, closed: make(chan struct{})}, nil
}

func (l *Listener) Accept() (transport.Session, error) {
	select {
	case sess := <-l.sessions:
		return sess, nil
	case <-l.done:
		return nil, fmt.Errorf("listener closed")
	}
}

func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
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

	// Phase 2: Metadata Extraction
	dec := xhttpmeta.NewPlacementDecoder(l.metadataCfg)
	meta, err := dec.Decode(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Requirement 11: Session ID length check
	if len(meta.SessionID) > 128 {
		w.WriteHeader(http.StatusBadRequest)
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

	// Use pipe to ensure we wait for all writes to finish before the handler returns
	pr, pw := io.Pipe()
	conn := &streamConn{
		reader: r.Body,
		writer: pw,
		local:  dummyAddr("h2-server"),
		remote: dummyAddr(r.RemoteAddr),
	}

	writeDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(writeFlusher{w: w, fl: fl}, pr)
		close(writeDone)
	}()

	if err := transport.RecvGuard(conn, l.guard); err != nil {
		_ = conn.Close()
		return
	}
	sess, err := smux.Server(conn, l.smux)
	if err != nil {
		_ = conn.Close()
		return
	}

	s := &session{conn: conn, sess: sess, closed: make(chan struct{})}
	select {
	case <-l.done:
		_ = s.Close()
	case l.sessions <- s:
		// Wait for session to be closed by someone or client disconnect
		select {
		case <-s.closed:
		case <-r.Context().Done():
			_ = s.Close()
		}
	default:
		_ = s.Close()
	}
	<-writeDone
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

type session struct {
	conn   net.Conn
	sess   *smux.Session
	closed chan struct{}
	once   sync.Once
}

func (s *session) OpenStream() (net.Conn, error)   { return s.sess.OpenStream() }
func (s *session) AcceptStream() (net.Conn, error) { return s.sess.AcceptStream() }
func (s *session) Close() error {
	s.once.Do(func() {
		if s.sess != nil {
			_ = s.sess.Close()
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
		close(s.closed)
	})
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
