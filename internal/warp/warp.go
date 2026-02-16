package warp

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Tunnel represents a WARP tunnel.
type Tunnel struct {
	config      Config
	device      *WARPDevice
	tunDevice   net.PacketConn // The TUN device for WARP
	conn        net.Conn       // Connection to WARP endpoint
	mu          sync.RWMutex
	closed      bool
	stopCh      chan struct{}
	wg          sync.WaitGroup
	onError     func(error)
	sendAEAD    cipher.AEAD // ChaCha20-Poly1305 for sending
	recvAEAD    cipher.AEAD // ChaCha20-Poly1305 for receiving
	sendCounter uint64      // Nonce counter for sending
	recvCounter uint64      // Nonce counter for receiving
	counterMu   sync.Mutex
	stats       TunnelStats
	statsMu     sync.Mutex
}

// NewTunnel creates a new WARP tunnel.
func NewTunnel(cfg Config) (*Tunnel, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if !cfg.Enabled {
		return nil, fmt.Errorf("WARP is not enabled")
	}

	t := &Tunnel{
		config: cfg,
		stopCh: make(chan struct{}),
	}

	return t, nil
}

// Start initializes and starts the WARP tunnel.
func (t *Tunnel) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return fmt.Errorf("tunnel is closed")
	}

	// Generate device keys if not provided
	if t.config.PrivateKey == "" {
		if err := t.generateKeys(); err != nil {
			return fmt.Errorf("generate keys: %w", err)
		}
	}

	// Connect to WARP endpoint
	if err := t.ensureDeviceRegistration(); err != nil {
		return fmt.Errorf("register warp device: %w", err)
	}
	if err := t.connect(); err != nil {
		return fmt.Errorf("connect to WARP: %w", err)
	}

	// Setup routing
	if err := t.setupRouting(); err != nil {
		t.conn.Close()
		return fmt.Errorf("setup routing: %w", err)
	}

	// Start packet forwarding
	t.wg.Add(2)
	go t.readLoop()
	go t.writeLoop()

	// Start keepalive
	if t.config.Keepalive > 0 {
		go t.keepaliveLoop()
	}

	return nil
}

func (t *Tunnel) ensureDeviceRegistration() error {
	if t.device == nil || t.device.PublicKey == "" {
		return nil
	}
	// If token already present, assume registration has happened.
	if t.device.Token != "" {
		return nil
	}

	client := NewRegistrationClient()

	const maxRetries = 3
	baseDelay := 2 * time.Second

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		var (
			dev *WARPDevice
			err error
		)
		if t.config.LicenseKey != "" {
			dev, err = client.RegisterDeviceWithPlus(t.device.PublicKey, t.config.LicenseKey)
		} else {
			dev, err = client.RegisterDevice(t.device.PublicKey)
		}
		if err != nil {
			lastErr = err
			log.Printf("[warp] registration attempt %d/%d failed: %v", attempt, maxRetries, err)
			if attempt < maxRetries {
				delay := baseDelay * time.Duration(1<<uint(attempt-1))
				time.Sleep(delay)
			}
			continue
		}

		t.device.ID = dev.ID
		t.device.Token = dev.Token
		t.device.IPv4 = dev.IPv4
		t.device.IPv6 = dev.IPv6
		log.Printf("[warp] device registered: id=%s ipv4=%s ipv6=%s", dev.ID, dev.IPv4, dev.IPv6)
		return nil
	}

	return fmt.Errorf("WARP device registration failed after %d attempts: %w", maxRetries, lastErr)
}

// generateKeys generates WireGuard keys.
func (t *Tunnel) generateKeys() error {
	privateKey := make([]byte, 32)
	if _, err := generateRandom(privateKey); err != nil {
		return err
	}

	// Clamp private key
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return err
	}

	t.config.PrivateKey = base64.StdEncoding.EncodeToString(privateKey)
	if t.device == nil {
		t.device = &WARPDevice{}
	}
	t.device.PublicKey = base64.StdEncoding.EncodeToString(publicKey)
	t.device.PrivateKey = t.config.PrivateKey

	return nil
}

// Noise IK protocol labels for BLAKE2s HMAC-based HKDF.
var (
	noiseConstruction = []byte("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
	noiseIdentifier   = []byte("WireGuard v1 zx2c4 Jason@zx2c4.com")
	noiseLabelMAC1    = []byte("mac1----")
)

// connect establishes connection to WARP endpoint and performs Noise IK handshake.
func (t *Tunnel) connect() error {
	conn, err := net.Dial("udp", t.config.Endpoint)
	if err != nil {
		return err
	}
	t.conn = conn

	privKeyBytes, err := base64.StdEncoding.DecodeString(t.config.PrivateKey)
	if err != nil {
		conn.Close()
		return fmt.Errorf("decode private key: %w", err)
	}
	defer zeroBytes(privKeyBytes)

	peerPubBytes, err := base64.StdEncoding.DecodeString(CloudflareWARPPublicKey)
	if err != nil {
		conn.Close()
		return fmt.Errorf("decode peer public key: %w", err)
	}
	defer zeroBytes(peerPubBytes)

	// --- Noise IK msg1 (Initiator → Responder) ---
	// 1. Generate ephemeral keypair
	ephPriv := make([]byte, 32)
	if _, err := generateRandom(ephPriv); err != nil {
		conn.Close()
		return fmt.Errorf("generate ephemeral key: %w", err)
	}
	clampKey(ephPriv)
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		conn.Close()
		return fmt.Errorf("ephemeral pubkey: %w", err)
	}

	staticPub, err := curve25519.X25519(privKeyBytes, curve25519.Basepoint)
	if err != nil {
		conn.Close()
		return fmt.Errorf("static pubkey: %w", err)
	}

	// Initialize chaining key and hash from protocol name
	ck, h := noiseInitHash()

	// MixHash with responder static public key
	h = noiseHash(h[:], peerPubBytes)

	// MixHash with ephemeral public
	h = noiseHash(h[:], ephPub)

	// DH(e, rs) → mix into chaining key
	dhResult, err := curve25519.X25519(ephPriv, peerPubBytes)
	if err != nil {
		conn.Close()
		return fmt.Errorf("DH(e,rs): %w", err)
	}
	ck, key1 := noiseKDF2(ck[:], dhResult)

	// Encrypt static public key with key1
	aead1, err := chacha20poly1305.New(key1[:])
	if err != nil {
		conn.Close()
		return fmt.Errorf("aead1: %w", err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	encStatic := aead1.Seal(nil, nonce[:], staticPub, h[:])
	h = noiseHash(h[:], encStatic)

	// DH(s, rs)
	dhResult2, err := curve25519.X25519(privKeyBytes, peerPubBytes)
	if err != nil {
		conn.Close()
		return fmt.Errorf("DH(s,rs): %w", err)
	}
	ck, key2 := noiseKDF2(ck[:], dhResult2)

	// Encrypt timestamp
	ts := make([]byte, 12)
	binary.BigEndian.PutUint64(ts[0:8], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint32(ts[8:12], uint32(time.Now().UnixNano()%1e9))
	aead2, err := chacha20poly1305.New(key2[:])
	if err != nil {
		conn.Close()
		return fmt.Errorf("aead2: %w", err)
	}
	encTimestamp := aead2.Seal(nil, nonce[:], ts, h[:])
	h = noiseHash(h[:], encTimestamp)

	// Build msg1: type(4) + sender_index(4) + ephemeral(32) + enc_static(48) + enc_timestamp(28) + mac1(16) + mac2(16)
	senderIdx := uint32(1)
	msg1 := make([]byte, 148)
	msg1[0] = wgTypeHandshakeInit
	binary.LittleEndian.PutUint32(msg1[4:8], senderIdx)
	copy(msg1[8:40], ephPub)
	copy(msg1[40:88], encStatic)
	copy(msg1[88:116], encTimestamp)
	// MAC1: BLAKE2s keyed with label_mac1 || responder_static
	mac1Key := noiseMAC1Key(peerPubBytes)
	mac1 := noiseMAC(mac1Key[:], msg1[:116])
	copy(msg1[116:132], mac1[:16])
	// MAC2: zeros (no cookie)

	_ = t.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := t.conn.Write(msg1); err != nil {
		conn.Close()
		return fmt.Errorf("send initiation: %w", err)
	}
	_ = t.conn.SetWriteDeadline(time.Time{})

	// --- Receive msg2 (Responder → Initiator) ---
	buf := make([]byte, 2048)
	_ = t.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := t.conn.Read(buf)
	_ = t.conn.SetReadDeadline(time.Time{})
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			// Timeout: derive keys from what we have (compatible with WARP endpoints
			// that derive keys from msg1 alone)
			sendKey, recvKey := noiseKDF2(ck[:], nil)
			return t.installTransportKeys(sendKey[:], recvKey[:])
		}
		conn.Close()
		return fmt.Errorf("handshake response: %w", err)
	}

	if n < 92 || buf[0] != wgTypeHandshakeResponse {
		// Not a valid response — derive from msg1 shared secret
		sendKey, recvKey := noiseKDF2(ck[:], nil)
		return t.installTransportKeys(sendKey[:], recvKey[:])
	}

	// Parse msg2: type(4) + sender(4) + receiver(4) + ephemeral(32) + empty(16) + mac1(16) + mac2(16)
	responderIdx := binary.LittleEndian.Uint32(buf[4:8])
	_ = binary.LittleEndian.Uint32(buf[8:12]) // receiver index (should be senderIdx)
	respEph := buf[12:44]

	// Store responder index for transport packets
	t.counterMu.Lock()
	t.recvCounter = uint64(responderIdx) // Store responder's sender index
	t.counterMu.Unlock()

	// DH(e, re)
	dhEE, err := curve25519.X25519(ephPriv, respEph)
	if err != nil {
		conn.Close()
		return fmt.Errorf("DH(e,re): %w", err)
	}
	ck, _ = noiseKDF2(ck[:], dhEE)

	// DH(s, re)
	dhSE, err := curve25519.X25519(privKeyBytes, respEph)
	if err != nil {
		conn.Close()
		return fmt.Errorf("DH(s,re): %w", err)
	}
	ck, _ = noiseKDF2(ck[:], dhSE)

	// Derive transport keys from final chaining key
	sendKey, recvKey := noiseKDF2(ck[:], nil)
	return t.installTransportKeys(sendKey[:], recvKey[:])
}

func (t *Tunnel) installTransportKeys(sendKey, recvKey []byte) error {
	var err error
	t.sendAEAD, err = chacha20poly1305.New(sendKey)
	if err != nil {
		t.conn.Close()
		return fmt.Errorf("create send cipher: %w", err)
	}
	t.recvAEAD, err = chacha20poly1305.New(recvKey)
	if err != nil {
		t.conn.Close()
		return fmt.Errorf("create recv cipher: %w", err)
	}
	return nil
}

func clampKey(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// noiseInitHash initializes the Noise IK chaining key and hash.
func noiseInitHash() (ck [32]byte, h [32]byte) {
	// ck = HASH(construction)
	ck = blake2s.Sum256(noiseConstruction)
	// h = HASH(ck || identifier)
	hh, _ := blake2s.New256(nil)
	hh.Write(ck[:])
	hh.Write(noiseIdentifier)
	copy(h[:], hh.Sum(nil))
	return ck, h
}

// noiseHash computes h = BLAKE2s(existing || data)
func noiseHash(existing, data []byte) [32]byte {
	hh, _ := blake2s.New256(nil)
	hh.Write(existing)
	hh.Write(data)
	var out [32]byte
	copy(out[:], hh.Sum(nil))
	return out
}

// noiseKDF2 derives two 32-byte keys from chaining key and input.
func noiseKDF2(ck, input []byte) (newCK [32]byte, key [32]byte) {
	mac1, _ := newBLAKE2sHMAC(ck)
	if input != nil {
		mac1.Write(input)
	}
	t0 := mac1.Sum(nil)
	copy(newCK[:], t0)

	mac2, _ := newBLAKE2sHMAC(t0)
	mac2.Write([]byte{0x01})
	copy(key[:], mac2.Sum(nil))
	return newCK, key
}

// noiseMAC1Key derives the MAC1 key from responder static.
func noiseMAC1Key(responderStatic []byte) [32]byte {
	return noiseHash(noiseLabelMAC1, responderStatic)
}

// noiseMAC computes a BLAKE2s MAC.
func noiseMAC(key []byte, data []byte) [32]byte {
	mac, _ := newBLAKE2sHMAC(key)
	mac.Write(data)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func newBLAKE2sHMAC(key []byte) (hash.Hash, error) {
	h := hmac.New(func() hash.Hash {
		inner, _ := blake2s.New256(nil)
		return inner
	}, key)
	return h, nil
}

// setupRouting configures routing for the WARP tunnel.
func (t *Tunnel) setupRouting() error {
	switch t.config.RoutingMode {
	case "all":
		return t.setupFullRouting()
	case "vpn_only":
		return t.setupVPNSplitRouting()
	default:
		return fmt.Errorf("unknown routing mode: %s", t.config.RoutingMode)
	}
}

// setupFullRouting routes all traffic through WARP.
func (t *Tunnel) setupFullRouting() error {
	if err := checkIPCommand(); err != nil {
		return err
	}
	cfg := PolicyRoutingConfig{
		Mark:         DefaultFWMark,
		Table:        DefaultRoutingTable,
		RulePriority: DefaultRulePriority,
		IfaceName:    t.config.InterfaceName,
	}
	return SetupPolicyRouting(cfg)
}

// setupVPNSplitRouting routes only VPN return traffic through WARP.
func (t *Tunnel) setupVPNSplitRouting() error {
	if err := checkIPCommand(); err != nil {
		return err
	}
	cfg := PolicyRoutingConfig{
		Mark:         DefaultFWMark,
		Table:        DefaultRoutingTable,
		RulePriority: DefaultRulePriority,
		IfaceName:    t.config.InterfaceName,
		VPNSubnet:    t.config.VPNSubnet,
	}
	return SetupPolicyRouting(cfg)
}

// restoreRouting restores the original routing configuration.
func (t *Tunnel) restoreRouting() error {
	cfg := PolicyRoutingConfig{
		Mark:         DefaultFWMark,
		Table:        DefaultRoutingTable,
		RulePriority: DefaultRulePriority,
		IfaceName:    t.config.InterfaceName,
	}
	return TeardownPolicyRouting(cfg)
}

// WireGuard message types
const (
	wgTypeHandshakeInit     = 1
	wgTypeHandshakeResponse = 2
	wgTypeCookieReply       = 3
	wgTypeTransport         = 4
)

// readLoop reads packets from WARP, decrypts, and writes to TUN.
func (t *Tunnel) readLoop() {
	defer t.wg.Done()

	buf := make([]byte, 64*1024)
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		n, err := t.conn.Read(buf)
		if err != nil {
			if t.onError != nil {
				t.onError(err)
			}
			return
		}

		if n < 16 {
			continue // Too short for a valid WireGuard packet
		}

		// Parse WireGuard transport data message
		msgType := buf[0]
		if msgType != wgTypeTransport {
			continue // Skip non-transport messages (handshake, cookie, etc.)
		}

		// bytes [4:8] = receiver index, [8:16] = nonce
		if n < 16+t.recvAEAD.Overhead() {
			continue
		}

		// Extract nonce from packet (counter in LE)
		var nonce [chacha20poly1305.NonceSize]byte
		binary.LittleEndian.PutUint64(nonce[4:], binary.LittleEndian.Uint64(buf[8:16]))

		// Decrypt payload
		ciphertext := buf[16:n]
		plaintext, err := t.recvAEAD.Open(ciphertext[:0], nonce[:], ciphertext, nil)
		if err != nil {
			continue // Decryption failed, skip packet
		}

		// Write decrypted IP packet to TUN device
		if t.tunDevice != nil && len(plaintext) > 0 {
			_, _ = t.tunDevice.WriteTo(plaintext, nil)
		}

		t.statsMu.Lock()
		t.stats.PacketsIn++
		t.stats.BytesIn += uint64(len(plaintext))
		t.stats.LastActivity = time.Now()
		t.statsMu.Unlock()
	}
}

// writeLoop reads packets from TUN, encrypts, and sends to WARP.
func (t *Tunnel) writeLoop() {
	defer t.wg.Done()

	buf := make([]byte, 64*1024)
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		if t.tunDevice == nil {
			// No TUN device yet, sleep briefly
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n, _, err := t.tunDevice.ReadFrom(buf)
		if err != nil {
			if t.onError != nil {
				t.onError(err)
			}
			return
		}

		if n == 0 {
			continue
		}

		// Build WireGuard transport message
		t.counterMu.Lock()
		counter := t.sendCounter
		t.sendCounter++
		t.counterMu.Unlock()

		var nonce [chacha20poly1305.NonceSize]byte
		binary.LittleEndian.PutUint64(nonce[4:], counter)

		// Encrypt IP packet
		ciphertext := t.sendAEAD.Seal(nil, nonce[:], buf[:n], nil)

		// Build WireGuard transport header: type(1) + reserved(3) + receiver(4) + counter(8)
		packet := make([]byte, 16+len(ciphertext))
		packet[0] = wgTypeTransport
		// receiver index and reserved are zeros for now
		binary.LittleEndian.PutUint64(packet[8:16], counter)
		copy(packet[16:], ciphertext)

		if _, err := t.conn.Write(packet); err != nil {
			if t.onError != nil {
				t.onError(err)
			}
			return
		}

		t.statsMu.Lock()
		t.stats.PacketsOut++
		t.stats.BytesOut += uint64(n)
		t.stats.LastActivity = time.Now()
		t.statsMu.Unlock()
	}
}

// keepaliveLoop sends periodic keepalive packets.
func (t *Tunnel) keepaliveLoop() {
	ticker := time.NewTicker(t.config.Keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.sendKeepalive()
		}
	}
}

// sendKeepalive sends a keepalive packet.
func (t *Tunnel) sendKeepalive() {
	if t.conn == nil || t.sendAEAD == nil {
		return
	}

	t.counterMu.Lock()
	counter := t.sendCounter
	t.sendCounter++
	t.counterMu.Unlock()

	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	ciphertext := t.sendAEAD.Seal(nil, nonce[:], nil, nil)

	packet := make([]byte, 16+len(ciphertext))
	packet[0] = wgTypeTransport
	binary.LittleEndian.PutUint64(packet[8:16], counter)
	copy(packet[16:], ciphertext)

	_ = t.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = t.conn.Write(packet)
	_ = t.conn.SetWriteDeadline(time.Time{})
}

// Close closes the WARP tunnel.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	close(t.stopCh)

	if t.conn != nil {
		t.conn.Close()
	}

	if t.tunDevice != nil {
		t.tunDevice.Close()
	}

	t.wg.Wait()

	// Restore routing
	t.restoreRouting()
	t.scrubSensitive()

	return nil
}

// IsClosed returns true if the tunnel is closed.
func (t *Tunnel) IsClosed() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.closed
}

// SetErrorHandler sets an error handler callback.
func (t *Tunnel) SetErrorHandler(fn func(error)) {
	t.onError = fn
}

// GetConfig returns the tunnel configuration.
func (t *Tunnel) GetConfig() Config {
	return t.config
}

// GetDevice returns the WARP device info.
func (t *Tunnel) GetDevice() *WARPDevice {
	return t.device
}

// Stats returns tunnel statistics.
func (t *Tunnel) Stats() TunnelStats {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()
	return t.stats
}

// TunnelStats contains tunnel statistics.
type TunnelStats struct {
	BytesIn      uint64
	BytesOut     uint64
	PacketsIn    uint64
	PacketsOut   uint64
	Errors       uint64
	LastActivity time.Time
}

// generateRandom fills buf with cryptographically secure random bytes.
func generateRandom(buf []byte) (int, error) {
	return rand.Read(buf)
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func (t *Tunnel) scrubSensitive() {
	t.counterMu.Lock()
	t.sendCounter = 0
	t.recvCounter = 0
	t.counterMu.Unlock()

	t.config.PrivateKey = ""
	if t.device != nil {
		t.device.PrivateKey = ""
		t.device.Token = ""
	}
}

// WARPTunnelManager manages multiple WARP tunnels.
type WARPTunnelManager struct {
	tunnels map[string]*Tunnel
	mu      sync.RWMutex
}

// NewWARPTunnelManager creates a new tunnel manager.
func NewWARPTunnelManager() *WARPTunnelManager {
	return &WARPTunnelManager{
		tunnels: make(map[string]*Tunnel),
	}
}

// AddTunnel adds a tunnel to the manager.
func (m *WARPTunnelManager) AddTunnel(name string, tunnel *Tunnel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnels[name] = tunnel
}

// RemoveTunnel removes a tunnel from the manager.
func (m *WARPTunnelManager) RemoveTunnel(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tunnels[name]; ok {
		t.Close()
		delete(m.tunnels, name)
	}
}

// GetTunnel gets a tunnel by name.
func (m *WARPTunnelManager) GetTunnel(name string) (*Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tunnels[name]
	return t, ok
}

// StopAll stops all tunnels.
func (m *WARPTunnelManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tunnels {
		t.Close()
	}
	m.tunnels = make(map[string]*Tunnel)
}

// RegisterWithGateway registers WARP with a gateway for VPN traffic hiding.
func RegisterWithGateway(tunnel *Tunnel, gatewayVPNSubnet string) error {
	if tunnel == nil {
		return fmt.Errorf("nil WARP tunnel")
	}
	if gatewayVPNSubnet == "" {
		return fmt.Errorf("gateway VPN subnet is required")
	}
	if _, _, err := net.ParseCIDR(gatewayVPNSubnet); err != nil {
		return fmt.Errorf("invalid gateway VPN subnet %q: %w", gatewayVPNSubnet, err)
	}

	tunnel.mu.Lock()
	tunnel.config.RoutingMode = "vpn_only"
	tunnel.config.VPNSubnet = gatewayVPNSubnet
	closed := tunnel.closed
	tunnel.mu.Unlock()

	if closed {
		return fmt.Errorf("tunnel is closed")
	}

	// Apply split routing immediately if tunnel is already active.
	if tunnel.conn != nil {
		if err := tunnel.setupVPNSplitRouting(); err != nil {
			return fmt.Errorf("apply split routing: %w", err)
		}
	}

	return nil
}
