package snowflake

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
)

const (
	DefaultBrokerURL   = "https://snowflake-broker.torproject.net/"
	DefaultFrontDomain = "cdn.sstatic.net"
	DefaultRelayURL    = "wss://snowflake.torproject.net/"
	MaxPollAttempts    = 10
	PollInterval       = 5 * time.Second
	ClientTimeout      = 30 * time.Second
	MaxMessageSize     = 64 * 1024
	KeepaliveInterval  = 30 * time.Second
)

type SnowflakeConfig struct {
	BrokerURL   string
	FrontDomain string
	RelayURL    string
	ICEServers  []string
	MaxRetries  int
	PollTimeout time.Duration
	UserAgent   string
}

type BrokerClient struct {
	config     SnowflakeConfig
	httpClient *http.Client
	clientID   string
	mu         sync.Mutex
}

func NewBrokerClient(cfg SnowflakeConfig) *BrokerClient {
	if cfg.BrokerURL == "" {
		cfg.BrokerURL = DefaultBrokerURL
	}
	if cfg.FrontDomain == "" {
		cfg.FrontDomain = DefaultFrontDomain
	}
	if cfg.RelayURL == "" {
		cfg.RelayURL = DefaultRelayURL
	}
	if cfg.PollTimeout == 0 {
		cfg.PollTimeout = PollInterval
	}

	clientID := make([]byte, 16)
	rand.Read(clientID)

	return &BrokerClient{
		config:   cfg,
		clientID: base64.StdEncoding.EncodeToString(clientID),
		httpClient: &http.Client{
			Timeout: ClientTimeout,
			Transport: &http.Transport{
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
		},
	}
}

type ProxyOffer struct {
	URL      string
	OfferSDP string
	ID       string
}

func (b *BrokerClient) RequestProxy(ctx context.Context, offerSDP string) (*ProxyOffer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	formData := url.Values{}
	formData.Set("offer", offerSDP)
	formData.Set("client_id", b.clientID)

	reqURL := b.config.BrokerURL + "proxy"
	if b.config.FrontDomain != "" {
		reqURL = "https://" + b.config.FrontDomain + "/proxy"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Host", "snowflake-broker.torproject.net")
	if b.config.UserAgent != "" {
		req.Header.Set("User-Agent", b.config.UserAgent)
	}

	for i := 0; i < b.config.MaxRetries; i++ {
		resp, err := b.httpClient.Do(req)
		if err != nil {
			time.Sleep(b.config.PollTimeout)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			time.Sleep(b.config.PollTimeout)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}

		var result struct {
			Answer string `json:"answer"`
			ID     string `json:"id"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}

		if result.Answer != "" {
			return &ProxyOffer{
				OfferSDP: offerSDP,
				ID:       result.ID,
			}, nil
		}

		time.Sleep(b.config.PollTimeout)
	}

	return nil, fmt.Errorf("no proxy available after %d attempts", b.config.MaxRetries)
}

func (b *BrokerClient) SendAnswer(ctx context.Context, answerSDP, proxyID string) error {
	formData := url.Values{}
	formData.Set("answer", answerSDP)
	formData.Set("client_id", b.clientID)
	formData.Set("id", proxyID)

	reqURL := b.config.BrokerURL + "answer"
	if b.config.FrontDomain != "" {
		reqURL = "https://" + b.config.FrontDomain + "/answer"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Host", "snowflake-broker.torproject.net")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send answer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("broker returned status %d", resp.StatusCode)
	}

	return nil
}

type SnowflakeTransport struct {
	config    SnowflakeConfig
	broker    *BrokerClient
	conn      net.Conn
	running   atomic.Bool
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	onMessage func([]byte)
}

func NewSnowflakeTransport(cfg SnowflakeConfig) *SnowflakeTransport {
	ctx, cancel := context.WithCancel(context.Background())
	return &SnowflakeTransport{
		config: cfg,
		broker: NewBrokerClient(cfg),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (t *SnowflakeTransport) Connect(ctx context.Context) (net.Conn, error) {
	offerSDP, err := t.generateOffer()
	if err != nil {
		return nil, fmt.Errorf("generate offer: %w", err)
	}

	proxy, err := t.broker.RequestProxy(ctx, offerSDP)
	if err != nil {
		return nil, fmt.Errorf("request proxy: %w", err)
	}

	answerSDP, err := t.processOffer(offerSDP, proxy)
	if err != nil {
		return nil, fmt.Errorf("process offer: %w", err)
	}

	if err := t.broker.SendAnswer(ctx, answerSDP, proxy.ID); err != nil {
		return nil, fmt.Errorf("send answer: %w", err)
	}

	conn := &snowflakeConn{
		transport:  t,
		localAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		remoteAddr: &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0},
	}

	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()

	t.running.Store(true)
	metrics.IncTransportSession("snowflake")

	return conn, nil
}

func (t *SnowflakeTransport) generateOffer() (string, error) {
	ufrag := make([]byte, 8)
	pwd := make([]byte, 24)
	rand.Read(ufrag)
	rand.Read(pwd)

	offer := fmt.Sprintf(`v=0
o=- %x %x IN IP4 127.0.0.1
s=Snowflake
t=0 0
a=group:BUNDLE 0
m=application %d UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:%s
a=ice-pwd:%s
a=fingerprint:sha-256 %s
a=setup:actpass
a=mid:0
a=sctp-port:5000
a=max-message-size:%d
a=candidate:1 1 UDP 1 0.0.0.0 0 typ host
`, time.Now().UnixNano(), time.Now().UnixNano(), 0,
		base64.StdEncoding.EncodeToString(ufrag),
		base64.StdEncoding.EncodeToString(pwd),
		t.generateFingerprint(),
		MaxMessageSize)

	return offer, nil
}

func (t *SnowflakeTransport) generateFingerprint() string {
	cert := make([]byte, 32)
	rand.Read(cert)
	hash := sha256.Sum256(cert)
	fingerprint := ""
	for i, b := range hash {
		if i > 0 {
			fingerprint += ":"
		}
		fingerprint += fmt.Sprintf("%02X", b)
	}
	return fingerprint
}

func (t *SnowflakeTransport) processOffer(offerSDP string, proxy *ProxyOffer) (string, error) {
	answer := fmt.Sprintf(`v=0
o=- %x %x IN IP4 127.0.0.1
s=Snowflake
t=0 0
a=group:BUNDLE 0
m=application %d UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:client
a=ice-pwd:clientpassword
a=fingerprint:sha-256 %s
a=setup:active
a=mid:0
a=sctp-port:5000
a=max-message-size:%d
`, time.Now().UnixNano(), time.Now().UnixNano(), 0, t.generateFingerprint(), MaxMessageSize)

	return answer, nil
}

func (t *SnowflakeTransport) Close() error {
	t.running.Store(false)
	t.cancel()
	t.mu.Lock()
	if t.conn != nil {
		t.conn.Close()
	}
	t.mu.Unlock()
	metrics.DecTransportSession("snowflake")
	return nil
}

func (t *SnowflakeTransport) SetMessageHandler(handler func([]byte)) {
	t.mu.Lock()
	t.onMessage = handler
	t.mu.Unlock()
}

type snowflakeConn struct {
	transport  *SnowflakeTransport
	localAddr  net.Addr
	remoteAddr net.Addr
	readBuf    [][]byte
	mu         sync.Mutex
	closed     bool
}

func (c *snowflakeConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	for len(c.readBuf) == 0 {
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		c.mu.Lock()
		if c.closed {
			return 0, net.ErrClosed
		}
	}

	msg := c.readBuf[0]
	c.readBuf = c.readBuf[1:]
	n = copy(b, msg)
	return n, nil
}

func (c *snowflakeConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	metrics.AddTrafficOutbound(int64(len(b)))
	return len(b), nil
}

func (c *snowflakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *snowflakeConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *snowflakeConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *snowflakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *snowflakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *snowflakeConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *snowflakeConn) pushMessage(msg []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.readBuf = append(c.readBuf, msg)
		metrics.AddTrafficInbound(int64(len(msg)))
	}
}

type RendezvousMethod int

const (
	RendezvousHTTP RendezvousMethod = iota
	RendezvousDomainFronting
	RendezvousAMP
)

type RendezvousConfig struct {
	Method      RendezvousMethod
	BrokerURL   string
	FrontDomain string
	AMPPath     string
	AMPCacheURL string
}

func NewRendezvous(cfg RendezvousConfig) *Rendezvous {
	return &Rendezvous{
		config: cfg,
		httpClient: &http.Client{
			Timeout: ClientTimeout,
		},
	}
}

type Rendezvous struct {
	config     RendezvousConfig
	httpClient *http.Client
}

func (r *Rendezvous) Register(ctx context.Context, clientID string, offerSDP string) (string, error) {
	switch r.config.Method {
	case RendezvousDomainFronting:
		return r.registerDomainFront(ctx, clientID, offerSDP)
	case RendezvousAMP:
		return r.registerAMP(ctx, clientID, offerSDP)
	default:
		return r.registerHTTP(ctx, clientID, offerSDP)
	}
}

func (r *Rendezvous) registerHTTP(ctx context.Context, clientID, offerSDP string) (string, error) {
	formData := url.Values{}
	formData.Set("offer", offerSDP)
	formData.Set("client_id", clientID)

	resp, err := r.httpClient.PostForm(r.config.BrokerURL+"client", formData)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (r *Rendezvous) registerDomainFront(ctx context.Context, clientID, offerSDP string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+r.config.FrontDomain+"/client", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Host", "snowflake-broker.torproject.net")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (r *Rendezvous) registerAMP(ctx context.Context, clientID, offerSDP string) (string, error) {
	encodedOffer := base64.StdEncoding.EncodeToString([]byte(offerSDP))
	path := r.config.AMPPath
	if path == "" {
		path = "/amp/client"
	}

	reqURL := r.config.AMPCacheURL + path + "?offer=" + url.QueryEscape(encodedOffer)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return string(body), nil
	}
	return string(decoded), nil
}
