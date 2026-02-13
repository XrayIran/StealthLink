package anytls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"stealthlink/internal/tlsutil"
	"stealthlink/internal/transport"

	anytls "github.com/anytls/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtaci/smux"
)

// Config holds AnyTLS configuration.
type Config struct {
	Padding            PaddingConfig
	IdleSessionTimeout time.Duration // default: 300s
	TLSConfig          *tls.Config
	Password           string // Internal password for AnyTLS handshake
}

// Dialer implements transport.Dialer for AnyTLS.
type Dialer struct {
	Config     *Config
	SmuxConfig *smux.Config
	Guard      string
	ServerAddr string
	client     *anytls.Client
}

// NewDialer creates a new AnyTLS dialer.
func NewDialer(cfg *Config, smuxCfg *smux.Config, guard string, server string) (*Dialer, error) {
	if cfg.IdleSessionTimeout == 0 {
		cfg.IdleSessionTimeout = 300 * time.Second
	}

	d := &Dialer{
		Config:     cfg,
		SmuxConfig: smuxCfg,
		Guard:      guard,
		ServerAddr: server,
	}

	// AnyTLS client needs to be long-lived because it manages connections
	client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password:           cfg.Password,
		IdleSessionTimeout: cfg.IdleSessionTimeout,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return d.dialOut(ctx)
		},
		Logger: &anytlsLogger{},
	})
	if err != nil {
		return nil, fmt.Errorf("new anytls client: %w", err)
	}
	d.client = client

	return d, nil
}

func (d *Dialer) dialOut(ctx context.Context) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	if fn, ok := tlsutil.BaseDialFuncFromContext(ctx); ok {
		conn, err = fn(ctx, "tcp", d.ServerAddr)
	} else {
		dialer := &net.Dialer{}
		conn, err = dialer.DialContext(ctx, "tcp", d.ServerAddr)
	}
	if err != nil {
		return nil, err
	}

	if d.Config.TLSConfig != nil {
		tlsCfg := d.Config.TLSConfig.Clone()
		if tlsCfg.ServerName == "" {
			host, _, _ := net.SplitHostPort(d.ServerAddr)
			tlsCfg.ServerName = host
		}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return conn, nil
}

// Dial connects to an AnyTLS server.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	// We wrap anytls.Client in a Session.
	return &anytlsClientSession{client: d.client, addr: addr, ctx: ctx}, nil
}

type anytlsClientSession struct {
	client *anytls.Client
	addr   string
	ctx    context.Context
}

func (s *anytlsClientSession) OpenStream() (net.Conn, error) {
	// Parse the address to create a proper Socksaddr
	addr := M.ParseSocksaddr(s.addr)
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return s.client.CreateProxy(ctx, addr)
}

func (s *anytlsClientSession) AcceptStream() (net.Conn, error) {
	return nil, fmt.Errorf("client session does not accept streams")
}

func (s *anytlsClientSession) Close() error {
	return nil
}

func (s *anytlsClientSession) LocalAddr() net.Addr  { return nil }
func (s *anytlsClientSession) RemoteAddr() net.Addr { return nil }

// Listener implements transport.Listener.
type Listener struct {
	ln         net.Listener
	config     *Config
	smuxConfig *smux.Config
	guard      string
	service    *anytls.Service
	sessions   chan transport.Session
	closed     chan struct{}
}

func Listen(addr string, cfg *Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		ln:         ln,
		config:     cfg,
		smuxConfig: smuxCfg,
		guard:      guard,
		sessions:   make(chan transport.Session, 16),
		closed:     make(chan struct{}),
	}

	// Produce padding scheme lines
	var paddingScheme []byte
	gen := NewGenerator(cfg.Padding)
	var lines []string

	// Add stop parameter (number of padding rounds)
	lines = append(lines, "stop=8")

	// Add padding ranges with index
	for i, r := range gen.ranges {
		if r.min == r.max {
			lines = append(lines, fmt.Sprintf("%d=%d", i, r.min))
		} else {
			lines = append(lines, fmt.Sprintf("%d=%d-%d", i, r.min, r.max))
		}
	}
	paddingScheme = []byte(strings.Join(lines, "\n"))

	service, err := anytls.NewService(anytls.ServiceConfig{
		PaddingScheme: paddingScheme,
		Handler:       l,
		Users: []anytls.User{
			{Password: cfg.Password},
		},
		Logger: &anytlsLogger{},
	})
	if err != nil {
		ln.Close()
		return nil, err
	}
	l.service = service

	go l.serve()

	return l, nil
}

func (l *Listener) serve() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		go l.handleRawConn(conn)
	}
}

func (l *Listener) handleRawConn(conn net.Conn) {
	if l.config.TLSConfig != nil {
		tlsConn := tls.Server(conn, l.config.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return
		}
		conn = tlsConn
	}
	_ = l.service.NewConnection(context.Background(), conn, M.ParseSocksaddr(conn.RemoteAddr().String()), nil)
}

// NewConnectionEx is called for EACH NEW STREAM in an AnyTLS session.
func (l *Listener) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	// Receive guard token
	if l.guard != "" {
		if err := transport.RecvGuard(conn, l.guard); err != nil {
			conn.Close()
			return
		}
	}

	l.sessions <- &anytlsServerSession{conn: conn, local: l.ln.Addr(), remote: source}
}

type anytlsServerSession struct {
	conn   net.Conn
	local  net.Addr
	remote net.Addr
}

func (s *anytlsServerSession) OpenStream() (net.Conn, error) {
	return nil, fmt.Errorf("server session does not open streams")
}

func (s *anytlsServerSession) AcceptStream() (net.Conn, error) {
	if s.conn != nil {
		c := s.conn
		s.conn = nil
		return c, nil
	}
	return nil, fmt.Errorf("no more streams")
}

func (s *anytlsServerSession) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *anytlsServerSession) LocalAddr() net.Addr  { return s.local }
func (s *anytlsServerSession) RemoteAddr() net.Addr { return s.remote }

func (l *Listener) Accept() (transport.Session, error) {
	select {
	case sess := <-l.sessions:
		return sess, nil
	case <-l.closed:
		return nil, fmt.Errorf("listener closed")
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("accept timeout")
	}
}

func (l *Listener) Close() error {
	close(l.closed)
	return l.ln.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}

type anytlsLogger struct{}

func (l *anytlsLogger) TraceContext(ctx context.Context, args ...any) {}
func (l *anytlsLogger) DebugContext(ctx context.Context, args ...any) {}
func (l *anytlsLogger) InfoContext(ctx context.Context, args ...any)  {}
func (l *anytlsLogger) WarnContext(ctx context.Context, args ...any)  {}
func (l *anytlsLogger) ErrorContext(ctx context.Context, args ...any) {}
func (l *anytlsLogger) FatalContext(ctx context.Context, args ...any) {}
func (l *anytlsLogger) PanicContext(ctx context.Context, args ...any) {}

func (l *anytlsLogger) Trace(args ...any) {}
func (l *anytlsLogger) Debug(args ...any) {}
func (l *anytlsLogger) Info(args ...any)  {}
func (l *anytlsLogger) Warn(args ...any)  {}
func (l *anytlsLogger) Error(args ...any) {}
func (l *anytlsLogger) Fatal(args ...any) {}
func (l *anytlsLogger) Panic(args ...any) {}
