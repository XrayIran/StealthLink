package conjure

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"
	"stealthlink/internal/metrics"
)

const (
	PhantomPrefixLength  = 16
	SharedSecretLength   = 32
	MaxPhantomIPs        = 256
	RegistrationTimeout  = 30 * time.Second
	V6SubnetPrefix       = "2001:db8::"
	V4SubnetPrefix       = "198.51.100."
	StationPublicKeySize = 32
	SessionKeySize       = 32
)

type PhantomIPType int

const (
	PhantomIPv4 PhantomIPType = iota
	PhantomIPv6
)

type PhantomConfig struct {
	SharedSecret   string
	StationPubKey  []byte
	SubnetPrefixV4 string
	SubnetPrefixV6 string
	RegistrarURL   string
	FrontDomain    string
}

type PhantomProxy struct {
	IP        net.IP
	Port      int
	Type      PhantomIPType
	SessionID []byte
	Key       []byte
}

func (p *PhantomProxy) String() string {
	return fmt.Sprintf("%s:%d", p.IP.String(), p.Port)
}

type ConjureClient struct {
	config       PhantomConfig
	phantomCache sync.Map
	sessionKeys  sync.Map
	running      atomic.Bool
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.RWMutex
}

func NewConjureClient(cfg PhantomConfig) (*ConjureClient, error) {
	if cfg.SubnetPrefixV4 == "" {
		cfg.SubnetPrefixV4 = V4SubnetPrefix
	}
	if cfg.SubnetPrefixV6 == "" {
		cfg.SubnetPrefixV6 = V6SubnetPrefix
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &ConjureClient{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (c *ConjureClient) GeneratePhantomIPs(count int) ([]PhantomProxy, error) {
	if count > MaxPhantomIPs {
		count = MaxPhantomIPs
	}

	phantoms := make([]PhantomProxy, 0, count)
	secret := []byte(c.config.SharedSecret)

	if len(secret) < SharedSecretLength {
		extended := make([]byte, SharedSecretLength)
		copy(extended, secret)
		secret = extended
	}

	for i := 0; i < count; i++ {
		sessionID := make([]byte, 16)
		rand.Read(sessionID)

		phantom, err := c.derivePhantom(secret, sessionID, i)
		if err != nil {
			continue
		}
		phantoms = append(phantoms, phantom)
	}

	return phantoms, nil
}

func (c *ConjureClient) derivePhantom(secret, sessionID []byte, index int) (PhantomProxy, error) {
	info := make([]byte, 8)
	binary.BigEndian.PutUint32(info[0:4], uint32(index))
	binary.BigEndian.PutUint32(info[4:8], uint32(time.Now().Unix()))

	keyMaterial := make([]byte, 48)
	hkdf := hkdf.New(sha256.New, secret, sessionID, info)
	if _, err := hkdf.Read(keyMaterial); err != nil {
		return PhantomProxy{}, err
	}

	var ip net.IP
	var ipType PhantomIPType

	useV6 := keyMaterial[0]&0x80 != 0

	if useV6 {
		ipType = PhantomIPv6
		prefix := net.ParseIP(c.config.SubnetPrefixV6)
		if prefix == nil {
			prefix = net.ParseIP(V6SubnetPrefix)
		}
		ip = make(net.IP, 16)
		copy(ip, prefix)
		for i := 6; i < 16; i++ {
			ip[i] = keyMaterial[i]
		}
	} else {
		ipType = PhantomIPv4
		prefix := net.ParseIP(c.config.SubnetPrefixV4)
		if prefix == nil {
			prefix = net.ParseIP(V4SubnetPrefix)
		}
		ip = make(net.IP, 4)
		copy(ip, prefix.To4())
		for i := 0; i < 2; i++ {
			ip[2+i] = keyMaterial[1+i]
		}
	}

	sessionKey := make([]byte, SessionKeySize)
	copy(sessionKey, keyMaterial[16:48])

	port := 443
	portOffset := int(binary.BigEndian.Uint16(keyMaterial[14:16])) % 100
	if portOffset > 0 {
		port = 1024 + portOffset
	}

	return PhantomProxy{
		IP:        ip,
		Port:      port,
		Type:      ipType,
		SessionID: sessionID,
		Key:       sessionKey,
	}, nil
}

func (c *ConjureClient) Register(ctx context.Context, phantom *PhantomProxy) error {
	_, err := c.encryptRegistration(phantom)
	if err != nil {
		return fmt.Errorf("encrypt registration: %w", err)
	}

	c.sessionKeys.Store(hex.EncodeToString(phantom.SessionID), phantom.Key)
	c.phantomCache.Store(phantom.IP.String(), phantom)

	metrics.IncTransportSession("conjure")
	return nil
}

func (c *ConjureClient) encryptRegistration(phantom *PhantomProxy) ([]byte, error) {
	block, err := aes.NewCipher(phantom.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	registration := make([]byte, 64)
	copy(registration[0:16], phantom.SessionID)
	binary.BigEndian.PutUint64(registration[16:24], uint64(time.Now().Unix()))
	rand.Read(registration[24:64])

	encrypted := gcm.Seal(nonce, nonce, registration, nil)
	return encrypted, nil
}

func (c *ConjureClient) Connect(ctx context.Context, phantom *PhantomProxy) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", phantom.IP.String(), phantom.Port)

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to phantom %s: %w", phantom.String(), err)
	}

	wrapped := &phantomConn{
		Conn:      conn,
		client:    c,
		sessionID: phantom.SessionID,
		key:       phantom.Key,
	}

	return wrapped, nil
}

func (c *ConjureClient) GetPhantom(ip net.IP) (*PhantomProxy, bool) {
	val, ok := c.phantomCache.Load(ip.String())
	if !ok {
		return nil, false
	}
	return val.(*PhantomProxy), true
}

func (c *ConjureClient) ListPhantoms() []PhantomProxy {
	var phantoms []PhantomProxy
	c.phantomCache.Range(func(key, value interface{}) bool {
		phantoms = append(phantoms, *value.(*PhantomProxy))
		return true
	})
	return phantoms
}

func (c *ConjureClient) Close() error {
	c.running.Store(false)
	c.cancel()
	return nil
}

type phantomConn struct {
	net.Conn
	client    *ConjureClient
	sessionID []byte
	key       []byte
	readBuf   []byte
	mu        sync.Mutex
}

func (c *phantomConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.readBuf) > 0 {
		n = copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	buf := make([]byte, 4096)
	nRead, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}

	decrypted, err := c.decrypt(buf[:nRead])
	if err != nil {
		return 0, err
	}

	n = copy(b, decrypted)
	if n < len(decrypted) {
		c.readBuf = append(c.readBuf, decrypted[n:]...)
	}

	metrics.AddTrafficInbound(int64(n))
	return n, nil
}

func (c *phantomConn) Write(b []byte) (n int, err error) {
	encrypted, err := c.encrypt(b)
	if err != nil {
		return 0, err
	}

	_, err = c.Conn.Write(encrypted)
	if err != nil {
		return 0, err
	}

	metrics.AddTrafficOutbound(int64(len(b)))
	return len(b), nil
}

func (c *phantomConn) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *phantomConn) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (c *phantomConn) Close() error {
	metrics.DecTransportSession("conjure")
	return c.Conn.Close()
}

type DarkDecoyDetector struct {
	knownSubnets []*net.IPNet
}

func NewDarkDecoyDetector() *DarkDecoyDetector {
	d := &DarkDecoyDetector{}

	_, v4Net, _ := net.ParseCIDR(V4SubnetPrefix + "0/24")
	d.knownSubnets = append(d.knownSubnets, v4Net)

	_, v6Net, _ := net.ParseCIDR(V6SubnetPrefix + "/32")
	d.knownSubnets = append(d.knownSubnets, v6Net)

	return d
}

func (d *DarkDecoyDetector) IsPhantomIP(ip net.IP) bool {
	for _, subnet := range d.knownSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func GenerateRandomV6Address(prefix string) net.IP {
	prefixIP := net.ParseIP(prefix)
	if prefixIP == nil {
		prefixIP = net.ParseIP(V6SubnetPrefix)
	}

	addr := make(net.IP, 16)
	copy(addr, prefixIP)

	random := make([]byte, 10)
	rand.Read(random)
	copy(addr[6:], random)

	return addr
}

func GenerateRandomV4Address(prefix string) net.IP {
	prefixIP := net.ParseIP(prefix)
	if prefixIP == nil {
		prefixIP = net.ParseIP(V4SubnetPrefix)
	}

	addr := make(net.IP, 4)
	copy(addr, prefixIP.To4())

	var r1, r2 *big.Int
	r1, _ = rand.Int(rand.Reader, big.NewInt(256))
	r2, _ = rand.Int(rand.Reader, big.NewInt(256))
	addr[2] = byte(r1.Int64())
	addr[3] = byte(r2.Int64())

	return addr
}
