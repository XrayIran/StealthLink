package h3mux

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
)

type H3MuxConfig struct {
	Enabled       bool
	Server        string
	Path          string
	Headers       map[string]string
	TLSConfig     *tls.Config
	MaxStreams    int64
	IdleTimeout   time.Duration
	SettingsSpoof *H2SettingsSpoofConfig
}

type H2SettingsSpoofConfig struct {
	Enabled           bool
	HeaderTableSize   uint32
	EnablePush        uint32
	MaxConcurrent     uint32
	InitialWindowSize uint32
	MaxFrameSize      uint32
	MaxHeaderSize     uint32
}

func DefaultH2SettingsSpoof() *H2SettingsSpoofConfig {
	return &H2SettingsSpoofConfig{
		Enabled:           true,
		HeaderTableSize:   65536,
		EnablePush:        1,
		MaxConcurrent:     1000,
		InitialWindowSize: 6291456,
		MaxFrameSize:      16384,
		MaxHeaderSize:     262144,
	}
}

func (c *H2SettingsSpoofConfig) EncodeSettings() []byte {
	settings := make([]byte, 0, 36)
	settings = appendSetting(settings, 0x01, c.HeaderTableSize)
	settings = appendSetting(settings, 0x02, c.EnablePush)
	settings = appendSetting(settings, 0x03, c.MaxConcurrent)
	settings = appendSetting(settings, 0x04, c.InitialWindowSize)
	settings = appendSetting(settings, 0x05, c.MaxFrameSize)
	settings = appendSetting(settings, 0x06, c.MaxHeaderSize)
	return settings
}

func appendSetting(buf []byte, id uint16, value uint32) []byte {
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint32(buf, value)
	return buf
}

type H3MuxClient struct {
	config    H3MuxConfig
	tlsConfig *tls.Config
	running   atomic.Bool
	mu        sync.RWMutex
}

func NewH3MuxClient(cfg H3MuxConfig) *H3MuxClient {
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = 100
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 30 * time.Second
	}
	if cfg.SettingsSpoof == nil {
		cfg.SettingsSpoof = DefaultH2SettingsSpoof()
	}

	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: false,
			NextProtos:         []string{"h3"},
		}
	}

	return &H3MuxClient{
		config:    cfg,
		tlsConfig: tlsConfig,
	}
}

func (c *H3MuxClient) Dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: c.config.IdleTimeout}

	addr := fmt.Sprintf("%s:443", c.config.Server)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	tlsConn := tls.Client(conn, c.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	metrics.IncTransportSession("h3mux")
	return &h3Conn{
		Conn: tlsConn,
	}, nil
}

func (c *H3MuxClient) parseURL() *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   c.config.Server,
		Path:   c.config.Path,
	}
}

func (c *H3MuxClient) buildHeaders() http.Header {
	h := make(http.Header)
	for k, v := range c.config.Headers {
		h.Set(k, v)
	}
	if c.config.SettingsSpoof.Enabled {
		settings := c.config.SettingsSpoof.EncodeSettings()
		h.Set("X-Http2-Settings", string(settings))
	}
	return h
}

func (c *H3MuxClient) Close() error {
	metrics.DecTransportSession("h3mux")
	return nil
}

type h3Conn struct {
	net.Conn
	writeBuf []byte
	mu       sync.Mutex
	closed   atomic.Bool
}

func (c *h3Conn) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

func (c *h3Conn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	c.writeBuf = append(c.writeBuf, b...)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *h3Conn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	metrics.DecTransportSession("h3mux")
	return c.Conn.Close()
}

type H3MuxServer struct {
	config  H3MuxConfig
	server  *http.Server
	running atomic.Bool
	mu      sync.RWMutex
}

func NewH3MuxServer(cfg H3MuxConfig) *H3MuxServer {
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = 100
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 30 * time.Second
	}
	return &H3MuxServer{config: cfg}
}

func (s *H3MuxServer) Listen(addr string) error {
	tlsConfig := s.config.TLSConfig
	if tlsConfig == nil {
		return fmt.Errorf("tls config required for h3 server")
	}

	mux := http.NewServeMux()
	mux.HandleFunc(s.config.Path, s.handleRequest)

	s.server = &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	s.running.Store(true)
	go s.server.ListenAndServeTLS("", "")

	return nil
}

func (s *H3MuxServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *H3MuxServer) Close() error {
	s.running.Store(false)
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}
