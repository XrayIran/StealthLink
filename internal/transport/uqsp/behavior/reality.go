package behavior

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"stealthlink/internal/config"
	"stealthlink/internal/crypto/pqsig"
)

// RealityOverlay ports XTLS REALITY behaviors as a UQSP overlay.
// REALITY provides X25519 handshake and fingerprint mimicry without private keys.
type RealityOverlay struct {
	EnabledField    bool
	Dest            string
	ServerNames     []string
	PrivateKey      string
	ServerPublicKey string
	ShortIDs        []string
	SpiderX         string
	Show            bool

	// Post-quantum signature support (ML-DSA-65)
	PQSigEnabled bool
	PQPrivateKey []byte
	PQPublicKey  []byte
	pqSigner     *pqsig.MLDSA65Signer
	pqVerifier   *pqsig.MLDSA65Verifier
}

// NewRealityOverlay creates a new REALITY overlay from config
func NewRealityOverlay(cfg config.RealityBehaviorConfig) *RealityOverlay {
	return &RealityOverlay{
		EnabledField:    cfg.Enabled,
		Dest:            cfg.Dest,
		ServerNames:     cfg.ServerNames,
		PrivateKey:      cfg.PrivateKey,
		ServerPublicKey: cfg.ServerPublicKey,
		ShortIDs:        cfg.ShortIDs,
		SpiderX:         cfg.SpiderX,
		Show:            cfg.Show,
	}
}

// EnablePQSignatures enables post-quantum signatures with ML-DSA-65
func (o *RealityOverlay) EnablePQSignatures(privateKey []byte) error {
	if len(privateKey) == 0 {
		return fmt.Errorf("private key is required for PQ signatures")
	}

	signer, err := pqsig.NewMLDSA65Signer(privateKey)
	if err != nil {
		return fmt.Errorf("create PQ signer: %w", err)
	}

	o.PQSigEnabled = true
	o.PQPrivateKey = privateKey
	o.pqSigner = signer
	return nil
}

// EnablePQVerification enables post-quantum signature verification
func (o *RealityOverlay) EnablePQVerification(publicKey []byte) error {
	if len(publicKey) == 0 {
		return fmt.Errorf("public key is required for PQ verification")
	}

	verifier, err := pqsig.NewMLDSA65Verifier(publicKey)
	if err != nil {
		return fmt.Errorf("create PQ verifier: %w", err)
	}

	o.PQSigEnabled = true
	o.PQPublicKey = publicKey
	o.pqVerifier = verifier
	return nil
}

// SignWithPQ creates a hybrid signature (classical + post-quantum)
func (o *RealityOverlay) SignWithPQ(message []byte) (*pqsig.HybridSignature, error) {
	if !o.PQSigEnabled || o.pqSigner == nil {
		return nil, fmt.Errorf("PQ signatures not enabled")
	}

	var classicalSig []byte
	if edPriv := o.deriveEd25519PrivateKey(); len(edPriv) > 0 {
		classicalSig = ed25519.Sign(edPriv, message)
	}

	pqSig, err := o.pqSigner.Sign(nil, message, nil)
	if err != nil {
		return nil, fmt.Errorf("PQ sign: %w", err)
	}

	return &pqsig.HybridSignature{
		Classical: classicalSig,
		PQ:        pqSig,
	}, nil
}

// VerifyWithPQ verifies a hybrid signature
func (o *RealityOverlay) VerifyWithPQ(message []byte, sig *pqsig.HybridSignature) error {
	if !o.PQSigEnabled || o.pqVerifier == nil {
		return fmt.Errorf("PQ verification not enabled")
	}

	if len(sig.Classical) > 0 {
		if edPub := o.deriveEd25519PublicKey(); len(edPub) > 0 {
			if !ed25519.Verify(edPub, message, sig.Classical) {
				return fmt.Errorf("classical signature verification failed")
			}
		}
	}

	if err := o.pqVerifier.Verify(message, sig.PQ); err != nil {
		return fmt.Errorf("PQ signature verification: %w", err)
	}

	return nil
}

// deriveEd25519PublicKey derives the Ed25519 public key from the X25519 private key
func (o *RealityOverlay) deriveEd25519PublicKey() ed25519.PublicKey {
	privKey, err := parseRealityKey(o.PrivateKey)
	if err != nil {
		return nil
	}
	material := append([]byte("stealthlink-reality-ed25519:"), privKey...)
	seed := [32]byte{}
	copy(seed[:], material)
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey)
}

// deriveEd25519PrivateKey derives the Ed25519 private key from the X25519 private key
func (o *RealityOverlay) deriveEd25519PrivateKey() ed25519.PrivateKey {
	privKey, err := parseRealityKey(o.PrivateKey)
	if err != nil {
		return nil
	}
	material := append([]byte("stealthlink-reality-ed25519:"), privKey...)
	seed := [32]byte{}
	copy(seed[:], material)
	return ed25519.NewKeyFromSeed(seed[:])
}

// Name returns "reality"
func (o *RealityOverlay) Name() string {
	return "reality"
}

// Enabled returns whether this overlay is enabled
func (o *RealityOverlay) Enabled() bool {
	return o.EnabledField
}

// Apply applies REALITY behavior to the connection
func (o *RealityOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}

	wrapper := &realityConn{
		Conn:            conn,
		dest:            o.Dest,
		serverNames:     o.ServerNames,
		privateKey:      o.PrivateKey,
		serverPublicKey: o.ServerPublicKey,
		shortIDs:        o.ShortIDs,
		spiderX:         o.SpiderX,
		show:            o.Show,
		isClient:        true,
		state:           realityStateInitial,
	}

	// Perform REALITY handshake
	if err := wrapper.clientHandshake(); err != nil {
		return nil, fmt.Errorf("reality handshake: %w", err)
	}

	return wrapper, nil
}

// realityState represents the REALITY handshake state
type realityState int

const (
	realityStateInitial realityState = iota
	realityStateClientHello
	realityStateServerHello
	realityStateEstablished
)

// realityConn wraps a connection with REALITY behavior
type realityConn struct {
	net.Conn
	dest            string
	serverNames     []string
	privateKey      string
	serverPublicKey string
	shortIDs        []string
	spiderX         string
	show            bool
	isClient        bool
	state           realityState
	sharedKey       []byte
	serverPublic    []byte
}

// clientHandshake performs the REALITY client handshake
func (c *realityConn) clientHandshake() error {
	if c.state != realityStateInitial {
		return nil
	}

	// Parse private key
	privateKey, err := parseRealityKey(c.privateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	// Generate client public key
	clientPublic, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("generate client key: %w", err)
	}

	// Build ClientHello
	clientHello, err := c.buildClientHello(clientPublic)
	if err != nil {
		return fmt.Errorf("build client hello: %w", err)
	}

	// Send ClientHello
	if err := c.sendHandshakeMessage(clientHello); err != nil {
		return fmt.Errorf("send client hello: %w", err)
	}

	c.state = realityStateClientHello

	// Receive ServerHello
	serverHello, err := c.receiveHandshakeMessage()
	if err != nil {
		return fmt.Errorf("receive server hello: %w", err)
	}

	// Process ServerHello
	if err := c.processServerHello(serverHello, privateKey); err != nil {
		return fmt.Errorf("process server hello: %w", err)
	}

	c.state = realityStateEstablished
	return nil
}

// buildClientHello builds the REALITY ClientHello
func (c *realityConn) buildClientHello(clientPublic []byte) ([]byte, error) {
	// Select SNI
	sni := c.dest
	if len(c.serverNames) > 0 {
		sni = c.serverNames[0]
	}

	// Build handshake message
	// Format: [version:1][client_public:32][sni_len:2][sni][timestamp:8]
	sniBytes := []byte(sni)
	msg := make([]byte, 1+32+2+len(sniBytes)+8)
	offset := 0

	msg[offset] = 0x01 // Version
	offset++

	copy(msg[offset:], clientPublic)
	offset += 32

	binary.BigEndian.PutUint16(msg[offset:], uint16(len(sniBytes)))
	offset += 2

	copy(msg[offset:], sniBytes)
	offset += len(sniBytes)

	binary.BigEndian.PutUint64(msg[offset:], uint64(time.Now().Unix()))

	return msg, nil
}

// processServerHello processes the REALITY ServerHello
func (c *realityConn) processServerHello(data []byte, clientPrivate []byte) error {
	if len(data) < 1+32+64+8 {
		return fmt.Errorf("server hello too short")
	}

	offset := 0

	// Check version
	version := data[offset]
	if version != 0x01 {
		return fmt.Errorf("unsupported version: %d", version)
	}
	offset++

	// Extract server public key
	c.serverPublic = make([]byte, 32)
	copy(c.serverPublic, data[offset:offset+32])
	offset += 32

	if c.serverPublicKey != "" {
		expectedServerPublic, err := parseRealityKey(c.serverPublicKey)
		if err != nil {
			return fmt.Errorf("parse server public key: %w", err)
		}
		if len(expectedServerPublic) != 32 {
			return fmt.Errorf("invalid server public key length: %d", len(expectedServerPublic))
		}
		if !equalBytes(c.serverPublic, expectedServerPublic) {
			return fmt.Errorf("server public key mismatch")
		}
	}

	// Extract signature
	signature := data[offset : offset+64]
	offset += 64

	// Extract timestamp
	timestamp := binary.BigEndian.Uint64(data[offset:])

	// Verify timestamp
	now := uint64(time.Now().Unix())
	if timestamp > now+60 || timestamp < now-300 {
		return fmt.Errorf("timestamp out of range")
	}

	// Compute shared key
	sharedKey, err := curve25519.X25519(clientPrivate, c.serverPublic)
	if err != nil {
		return fmt.Errorf("compute shared key: %w", err)
	}
	c.sharedKey = sharedKey

	// Verify signature
	sigData := append(c.serverPublic, c.serverPublic...) // Simplified
	if !ed25519.Verify(c.deriveServerPublicKey(), sigData, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// deriveServerPublicKey derives the server's Ed25519 public key from X25519
// public key material (explicitly configured or learned from ServerHello).
func (c *realityConn) deriveServerPublicKey() ed25519.PublicKey {
	if c.serverPublicKey != "" {
		if key, err := parseRealityKey(c.serverPublicKey); err == nil && len(key) == 32 {
			if pub, derr := deriveRealityEd25519PublicKeyFromX25519Public(key); derr == nil {
				return pub
			}
		}
	}

	if len(c.serverPublic) == 32 {
		if pub, err := deriveRealityEd25519PublicKeyFromX25519Public(c.serverPublic); err == nil {
			return pub
		}
	}

	return nil
}

// sendHandshakeMessage sends a handshake message with length prefix
func (c *realityConn) sendHandshakeMessage(msg []byte) error {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(msg)))

	if _, err := c.Conn.Write(length); err != nil {
		return err
	}
	_, err := c.Conn.Write(msg)
	return err
}

// receiveHandshakeMessage receives a handshake message with length prefix
func (c *realityConn) receiveHandshakeMessage() ([]byte, error) {
	c.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.Conn.SetReadDeadline(time.Time{})

	lengthBuf := make([]byte, 2)
	if _, err := c.Conn.Read(lengthBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(lengthBuf)
	if length > 8192 {
		return nil, fmt.Errorf("handshake message too large: %d", length)
	}

	msg := make([]byte, length)
	if _, err := c.Conn.Read(msg); err != nil {
		return nil, err
	}

	return msg, nil
}

// parseRealityKey parses a private key from base64 or hex
func parseRealityKey(key string) ([]byte, error) {
	key = strings.TrimSpace(key)

	// Try base64 first
	if decoded, err := base64.StdEncoding.DecodeString(key); err == nil {
		if len(decoded) == 32 {
			return decoded, nil
		}
	}

	// Try hex
	if decoded, err := hex.DecodeString(key); err == nil {
		if len(decoded) == 32 {
			return decoded, nil
		}
		return nil, fmt.Errorf("invalid key length: got %d, want 32", len(decoded))
	}

	return nil, fmt.Errorf("key must be base64 or hex encoded")
}

// RealityServerConn wraps a server-side REALITY connection
type RealityServerConn struct {
	net.Conn
	PrivateKey  []byte
	ServerNames []string
	state       realityState
}

// ServerHandshake performs the server-side REALITY handshake
func (c *RealityServerConn) ServerHandshake() error {
	if c.state != realityStateInitial {
		return nil
	}

	// Receive ClientHello
	clientHello, err := c.receiveHandshakeMessage()
	if err != nil {
		return fmt.Errorf("receive client hello: %w", err)
	}

	// Process ClientHello
	clientPublic, err := c.processClientHello(clientHello)
	if err != nil {
		return fmt.Errorf("process client hello: %w", err)
	}

	// Compute server public key
	serverPublic, err := curve25519.X25519(c.PrivateKey, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}

	// Compute shared key
	_, err = curve25519.X25519(c.PrivateKey, clientPublic)
	if err != nil {
		return fmt.Errorf("compute shared key: %w", err)
	}

	// Build and send ServerHello
	serverHello, err := c.buildServerHello(serverPublic)
	if err != nil {
		return fmt.Errorf("build server hello: %w", err)
	}

	if err := c.sendHandshakeMessage(serverHello); err != nil {
		return fmt.Errorf("send server hello: %w", err)
	}

	c.state = realityStateEstablished
	return nil
}

// processClientHello processes the client hello and returns the client public key
func (c *RealityServerConn) processClientHello(data []byte) ([]byte, error) {
	if len(data) < 43 {
		return nil, fmt.Errorf("client hello too short")
	}

	offset := 0

	// Check version
	version := data[offset]
	if version != 0x01 {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}
	offset++

	// Extract client public key
	clientPublic := make([]byte, 32)
	copy(clientPublic, data[offset:offset+32])
	offset += 32

	// Extract SNI
	sniLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if len(data) < offset+int(sniLen)+8 {
		return nil, fmt.Errorf("client hello truncated")
	}

	sni := string(data[offset : offset+int(sniLen)])
	offset += int(sniLen)

	// Validate SNI
	if len(c.ServerNames) > 0 {
		valid := false
		for _, name := range c.ServerNames {
			if name == sni {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("SNI not allowed: %s", sni)
		}
	}

	// Validate timestamp
	timestamp := binary.BigEndian.Uint64(data[offset:])
	now := uint64(time.Now().Unix())
	if timestamp > now+60 || timestamp < now-300 {
		return nil, fmt.Errorf("timestamp out of range")
	}

	return clientPublic, nil
}

// buildServerHello builds the server hello response
func (c *RealityServerConn) buildServerHello(serverPublic []byte) ([]byte, error) {
	msg := make([]byte, 1+32+64+8)
	offset := 0

	msg[offset] = 0x01 // Version
	offset++

	copy(msg[offset:], serverPublic)
	offset += 32

	// Sign the handshake
	sigData := append(serverPublic, serverPublic...) // Simplified
	privateKey := c.deriveEd25519PrivateKey()
	sig := ed25519.Sign(privateKey, sigData)
	copy(msg[offset:], sig)
	offset += 64

	binary.BigEndian.PutUint64(msg[offset:], uint64(time.Now().Unix()))

	return msg, nil
}

// deriveEd25519PrivateKey derives the Ed25519 private key
func (c *RealityServerConn) deriveEd25519PrivateKey() ed25519.PrivateKey {
	key, err := deriveRealityEd25519PrivateKey(c.PrivateKey)
	if err != nil {
		return nil
	}
	return key
}

func deriveRealityEd25519PrivateKey(privateKey []byte) (ed25519.PrivateKey, error) {
	// Bind signing identity to X25519 identity material so server/client derive
	// consistent verification keys from the same REALITY private key.
	x25519Public, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	material := append([]byte("stealthlink-reality-ed25519:"), x25519Public...)
	seed := [32]byte{}
	copy(seed[:], material)
	return ed25519.NewKeyFromSeed(seed[:]), nil
}

func deriveRealityEd25519PublicKeyFromX25519Public(serverPublic []byte) (ed25519.PublicKey, error) {
	material := append([]byte("stealthlink-reality-ed25519:"), serverPublic...)
	seed := [32]byte{}
	copy(seed[:], material)
	return ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey), nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sendHandshakeMessage sends a handshake message with length prefix
func (c *RealityServerConn) sendHandshakeMessage(msg []byte) error {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(msg)))

	if _, err := c.Conn.Write(length); err != nil {
		return err
	}
	_, err := c.Conn.Write(msg)
	return err
}

// receiveHandshakeMessage receives a handshake message with length prefix
func (c *RealityServerConn) receiveHandshakeMessage() ([]byte, error) {
	c.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.Conn.SetReadDeadline(time.Time{})

	lengthBuf := make([]byte, 2)
	if _, err := c.Conn.Read(lengthBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(lengthBuf)
	if length > 8192 {
		return nil, fmt.Errorf("handshake message too large: %d", length)
	}

	msg := make([]byte, length)
	if _, err := c.Conn.Read(msg); err != nil {
		return nil, err
	}

	return msg, nil
}

// Ensure realityConn implements net.Conn
var _ net.Conn = (*realityConn)(nil)
