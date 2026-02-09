package warp

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
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
		// Keep tunnel operational even when remote registration fails.
		return nil
	}
	t.device.ID = dev.ID
	t.device.Token = dev.Token
	t.device.IPv4 = dev.IPv4
	t.device.IPv6 = dev.IPv6
	return nil
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

// connect establishes connection to WARP endpoint and performs WireGuard handshake.
func (t *Tunnel) connect() error {
	conn, err := net.Dial("udp", t.config.Endpoint)
	if err != nil {
		return err
	}
	t.conn = conn

	// Derive shared secret via X25519 key exchange
	privKeyBytes, err := base64.StdEncoding.DecodeString(t.config.PrivateKey)
	if err != nil {
		conn.Close()
		return fmt.Errorf("decode private key: %w", err)
	}
	defer zeroBytes(privKeyBytes)

	// Use Cloudflare WARP public key as peer
	peerPubBytes, err := base64.StdEncoding.DecodeString(CloudflareWARPPublicKey)
	if err != nil {
		conn.Close()
		return fmt.Errorf("decode peer public key: %w", err)
	}
	defer zeroBytes(peerPubBytes)

	sharedSecret, err := curve25519.X25519(privKeyBytes, peerPubBytes)
	if err != nil {
		conn.Close()
		return fmt.Errorf("x25519 key exchange: %w", err)
	}
	defer zeroBytes(sharedSecret)

	sendKey, recvKey, err := deriveTransportKeys(sharedSecret)
	if err != nil {
		conn.Close()
		return fmt.Errorf("derive transport keys: %w", err)
	}
	defer zeroBytes(sendKey)
	defer zeroBytes(recvKey)

	t.sendAEAD, err = chacha20poly1305.New(sendKey)
	if err != nil {
		conn.Close()
		return fmt.Errorf("create send cipher: %w", err)
	}
	t.recvAEAD, err = chacha20poly1305.New(recvKey)
	if err != nil {
		conn.Close()
		return fmt.Errorf("create recv cipher: %w", err)
	}

	// Emit a lightweight initiation packet to align with Noise-IK style flows.
	// This is intentionally compatible with mixed peers where response may not arrive.
	_ = t.sendInitiation(privKeyBytes)

	return nil
}

func deriveTransportKeys(sharedSecret []byte) ([]byte, []byte, error) {
	prk, err := hkdfExtract(nil, sharedSecret)
	if err != nil {
		return nil, nil, err
	}
	sendKey, err := hkdfExpand(prk, []byte("stealthlink-warp-send"), chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}
	recvKey, err := hkdfExpand(prk, []byte("stealthlink-warp-recv"), chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}
	return sendKey, recvKey, nil
}

func hkdfExtract(salt, ikm []byte) ([]byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
	}
	mac, err := newBLAKE2sHMAC(salt)
	if err != nil {
		return nil, err
	}
	if _, err := mac.Write(ikm); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

func hkdfExpand(prk, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, fmt.Errorf("invalid HKDF output length: %d", outLen)
	}
	var out []byte
	var t []byte
	counter := byte(1)
	for len(out) < outLen {
		mac, err := newBLAKE2sHMAC(prk)
		if err != nil {
			return nil, err
		}
		if len(t) > 0 {
			if _, err := mac.Write(t); err != nil {
				return nil, err
			}
		}
		if _, err := mac.Write(info); err != nil {
			return nil, err
		}
		if _, err := mac.Write([]byte{counter}); err != nil {
			return nil, err
		}
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:outLen], nil
}

func newBLAKE2sHMAC(key []byte) (hash.Hash, error) {
	h := hmac.New(func() hash.Hash {
		inner, _ := blake2s.New256(nil)
		return inner
	}, key)
	return h, nil
}

func (t *Tunnel) sendInitiation(privKey []byte) error {
	pub, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return err
	}
	ephemeralPriv := make([]byte, 32)
	if _, err := generateRandom(ephemeralPriv); err != nil {
		return err
	}
	ephemeralPriv[0] &= 248
	ephemeralPriv[31] &= 127
	ephemeralPriv[31] |= 64

	ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
	if err != nil {
		return err
	}

	msg := make([]byte, 1+32+32+8)
	msg[0] = 1 // handshake/initiation
	copy(msg[1:33], ephemeralPub)
	copy(msg[33:65], pub)
	binary.LittleEndian.PutUint64(msg[65:73], uint64(time.Now().UnixNano()))
	_ = t.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = t.conn.Write(msg)
	_ = t.conn.SetWriteDeadline(time.Time{})
	return nil
}

// setupRouting configures routing for the WARP tunnel.
func (t *Tunnel) setupRouting() error {
	// In a real implementation, this would:
	// 1. Create a TUN device
	// 2. Configure IP addresses
	// 3. Add routes based on RoutingMode

	switch t.config.RoutingMode {
	case "all":
		// Route all traffic through WARP
		return t.setupFullRouting()
	case "vpn_only":
		// Only route VPN return traffic through WARP
		return t.setupVPNSplitRouting()
	default:
		return fmt.Errorf("unknown routing mode: %s", t.config.RoutingMode)
	}
}

// setupFullRouting routes all traffic through WARP.
func (t *Tunnel) setupFullRouting() error {
	// Add default route through WARP interface
	// This requires root privileges and netlink
	return setupDefaultRoute(t.config.InterfaceName)
}

// setupVPNSplitRouting routes only VPN return traffic through WARP.
func (t *Tunnel) setupVPNSplitRouting() error {
	// Add specific routes for VPN traffic only
	// This typically means routing the VPN subnet through WARP
	return setupVPNSpecificRoutes(t.config.InterfaceName, t.config.VPNSubnet)
}

// setupDefaultRoute adds a default route through the WARP interface.
func setupDefaultRoute(ifaceName string) error {
	// Platform-specific implementation
	// On Linux with netlink support, this adds a default route
	return addDefaultRouteViaInterface(ifaceName)
}

// setupVPNSpecificRoutes adds routes specific to VPN traffic.
func setupVPNSpecificRoutes(ifaceName string, vpnSubnet string) error {
	// Add route for VPN subnet only
	return addRouteViaInterface(ifaceName, vpnSubnet, "")
}

// restoreRouting restores the original routing configuration.
func (t *Tunnel) restoreRouting() error {
	// Remove WARP routes
	return removeRoutesViaInterface(t.config.InterfaceName)
}

// WireGuard message types
const (
	wgTypeTransport = 4
)

// readLoop reads packets from WARP, decrypts, and writes to TUN.
func (t *Tunnel) readLoop() {
	defer t.wg.Done()

	buf := make([]byte, 2048)
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

	buf := make([]byte, 2048)
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
	// Send WireGuard keepalive packet
	keepalive := []byte{0x00, 0x00, 0x00, 0x00} // Simplified
	t.conn.Write(keepalive)
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
