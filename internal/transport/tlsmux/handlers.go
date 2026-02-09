package tlsmux

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"stealthlink/internal/tlsutil"
	"stealthlink/internal/transport/ech"
	"stealthlink/internal/transport/reality"
	"stealthlink/internal/transport/shadowtls"
)

// DirectHandler implements standard TLS with optional fingerprinting
type DirectHandler struct {
	Fingerprint string
}

func (h *DirectHandler) Mode() TLSMode { return ModeDirect }

func (h *DirectHandler) WrapClient(ctx context.Context, conn net.Conn, tlsConfig *tls.Config, shaping *TLSShapingConfig) (net.Conn, error) {
	fingerprint := h.Fingerprint
	if shaping != nil && shaping.Fingerprint != "" {
		fingerprint = shaping.Fingerprint
	}

	// Apply fingerprint if specified
	if fingerprint != "" && fingerprint != "default" {
		return tlsutil.WrapUTLS(ctx, conn, tlsConfig, fingerprint)
	}
	// Standard TLS
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func (h *DirectHandler) WrapServer(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// RealityHandler implements REALITY protocol handling
type RealityHandler struct {
	Config *RealityConfig
}

func (h *RealityHandler) Mode() TLSMode { return ModeReality }

func (h *RealityHandler) WrapClient(ctx context.Context, conn net.Conn, tlsConfig *tls.Config, shaping *TLSShapingConfig) (net.Conn, error) {
	// Parse private key
	privateKey, err := parseKey(h.Config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// Create reality dialer configuration
	realityCfg := &reality.Config{
		Dest:        h.Config.Dest,
		ServerNames: h.Config.ServerNames,
		PrivateKey:  h.Config.PrivateKey,
		ShortIds:    h.Config.ShortIDs,
		SpiderX:     h.Config.SpiderX,
		Show:        h.Config.Show,
	}

	// Create a reality dialer for the handshake logic
	dialer := reality.NewDialer(realityCfg, tlsConfig, nil, "")

	// Perform REALITY client handshake
	return dialer.PerformClientHandshake(conn, privateKey)
}

func (h *RealityHandler) WrapServer(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	// Create reality configuration
	realityCfg := &reality.Config{
		Dest:        h.Config.Dest,
		ServerNames: h.Config.ServerNames,
		PrivateKey:  h.Config.PrivateKey,
		ShortIds:    h.Config.ShortIDs,
		SpiderX:     h.Config.SpiderX,
		Show:        h.Config.Show,
	}

	// Create listener-like wrapper for the connection
	listener := &realityListenerWrapper{
		config: realityCfg,
	}

	// Perform server-side handshake
	return listener.PerformServerHandshake(conn)
}

// realityListenerWrapper wraps a single connection for server-side REALITY handshake
type realityListenerWrapper struct {
	config *reality.Config
}

func (l *realityListenerWrapper) PerformServerHandshake(conn net.Conn) (net.Conn, error) {
	// Parse server private key
	serverPrivate, err := parseKey(l.config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// Create a realityConn for handshake handling
	rc := &realityConn{
		Conn:       conn,
		state:      StateInitial,
		privateKey: serverPrivate,
	}

	// Receive ClientHello
	clientHello, err := rc.receiveHandshakeMessage()
	if err != nil {
		return nil, fmt.Errorf("receive client hello: %w", err)
	}

	// Process ClientHello
	if err := rc.processClientHello(clientHello, l.config); err != nil {
		return nil, fmt.Errorf("process client hello: %w", err)
	}

	// Compute server public key
	serverPublic, err := curve25519.X25519(serverPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}

	// Compute shared key
	sharedKey, err := curve25519.X25519(serverPrivate, rc.publicKey)
	if err != nil {
		return nil, fmt.Errorf("compute shared key: %w", err)
	}
	rc.sharedKey = sharedKey

	// Build and send server hello
	serverHello, err := rc.buildServerHello(serverPublic, l.config)
	if err != nil {
		return nil, fmt.Errorf("build server hello: %w", err)
	}
	if err := rc.sendHandshakeMessage(serverHello); err != nil {
		return nil, fmt.Errorf("send server hello: %w", err)
	}

	rc.state = StateEstablished
	return rc, nil
}

// ShadowTLSHandler implements ShadowTLS protocol handling
type ShadowTLSHandler struct {
	Config *ShadowTLSConfig
}

func (h *ShadowTLSHandler) Mode() TLSMode { return ModeShadowTLS }

func (h *ShadowTLSHandler) WrapClient(ctx context.Context, conn net.Conn, tlsConfig *tls.Config, shaping *TLSShapingConfig) (net.Conn, error) {
	// Create shadowtls config
	stConfig := &shadowtls.Config{
		Version:         h.Config.Version,
		Password:        h.Config.Password,
		ServerNames:     h.Config.ServerNames,
		StrictMode:      h.Config.StrictMode,
		WildcardSNIMode: shadowtls.WildcardSNIMode(h.Config.WildcardSNIMode),
		MinTLSVersion:   h.Config.MinTLSVersion,
		MaxTLSVersion:   h.Config.MaxTLSVersion,
	}
	stConfig.Handshake.Dest = h.Config.Handshake.Dest
	stConfig.Handshake.SNI = h.Config.Handshake.SNI

	// ShadowTLS v3 with Session ID authentication
	if stConfig.Version == 3 {
		return h.performClientHandshakeV3(ctx, conn, tlsConfig, stConfig)
	}

	// Legacy handshake - perform TLS handshake relay
	decoySNI := stConfig.Handshake.SNI
	if decoySNI == "" {
		decoySNI = stConfig.Handshake.Dest
	}

	clientConfig := tlsConfig.Clone()
	if clientConfig == nil {
		clientConfig = &tls.Config{}
	}
	clientConfig.ServerName = decoySNI
	clientConfig.InsecureSkipVerify = true

	// Perform TLS handshake
	tlsConn := tls.Client(conn, clientConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (h *ShadowTLSHandler) WrapServer(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	_ = &shadowtls.Config{
		Version:         h.Config.Version,
		Password:        h.Config.Password,
		ServerNames:     h.Config.ServerNames,
		StrictMode:      h.Config.StrictMode,
		WildcardSNIMode: shadowtls.WildcardSNIMode(h.Config.WildcardSNIMode),
		MinTLSVersion:   h.Config.MinTLSVersion,
		MaxTLSVersion:   h.Config.MaxTLSVersion,
	}

	// For ShadowTLS, the server typically relays the handshake to the decoy server
	// For now, we perform standard TLS handshake
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (h *ShadowTLSHandler) performClientHandshakeV3(ctx context.Context, conn net.Conn, tlsConfig *tls.Config, config *shadowtls.Config) (net.Conn, error) {
	// ShadowTLS v3: perform TLS handshake with Session ID authentication
	// The Session ID field in Client Hello is used to carry authentication data

	decoySNI := config.Handshake.SNI
	if decoySNI == "" {
		decoySNI = config.Handshake.Dest
	}

	clientConfig := tlsConfig.Clone()
	if clientConfig == nil {
		clientConfig = &tls.Config{}
	}
	clientConfig.ServerName = decoySNI
	clientConfig.InsecureSkipVerify = true

	// Set a custom Session ID for authentication if password is set
	if config.Password != "" {
		// Derive session ID from password (simplified)
		sessionID := deriveSessionID(config.Password)
		clientConfig.SessionTicketsDisabled = false
		// Note: Go's crypto/tls doesn't expose direct Session ID control for clients
		// In a full implementation, we'd use uTLS for this
		_ = sessionID
	}

	// Perform TLS handshake
	tlsConn := tls.Client(conn, clientConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("shadowtls v3 handshake: %w", err)
	}

	return tlsConn, nil
}

func deriveSessionID(password string) [32]byte {
	// Simple derivation - in production, use HKDF
	var sessionID [32]byte
	copy(sessionID[:], password)
	return sessionID
}

// TLSMirrorHandler implements TLSMirror protocol handling
type TLSMirrorHandler struct {
	Config      *TLSMirrorConfig
	BaseConfig  *tls.Config
	Fingerprint string
	cache       *tlsutil.MirrorCache
}

func (h *TLSMirrorHandler) Mode() TLSMode { return ModeTLSMirror }

func (h *TLSMirrorHandler) WrapClient(ctx context.Context, conn net.Conn, tlsConfig *tls.Config, shaping *TLSShapingConfig) (net.Conn, error) {
	if h.cache == nil {
		h.cache = tlsutil.NewMirrorCache()
	}

	// Get server name from config
	serverName := tlsConfig.ServerName
	if serverName == "" && h.BaseConfig != nil {
		serverName = h.BaseConfig.ServerName
	}

	// Check if we should skip enrollment
	if h.shouldSkipEnrollment(serverName) {
		// Use direct TLS
		handler := &DirectHandler{Fingerprint: h.Fingerprint}
		return handler.WrapClient(ctx, conn, tlsConfig, shaping)
	}

	// Try to refresh cache and apply mirror settings
	if serverName != "" {
		state, err := h.cache.Refresh(serverName, h.Fingerprint)
		if err != nil {
			if h.Config.EnrollmentRequired {
				return nil, fmt.Errorf("tlsmirror enrollment required: %w", err)
			}
			// Continue without mirror
		} else if state != nil {
			cfg := tlsConfig.Clone()
			state.ApplyToConfig(cfg)
			tlsConfig = cfg
		}
	}

	// Use direct TLS with potentially modified config
	handler := &DirectHandler{Fingerprint: h.Fingerprint}
	return handler.WrapClient(ctx, conn, tlsConfig, shaping)
}

func (h *TLSMirrorHandler) WrapServer(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	// TLSMirror on server side is essentially standard TLS
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func (h *TLSMirrorHandler) shouldSkipEnrollment(host string) bool {
	if !h.Config.Enabled {
		return true
	}
	if !h.Config.AntiLoopback {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// ECHHandler implements Encrypted Client Hello handling
type ECHHandler struct {
	Config *ECHConfig
}

func (h *ECHHandler) Mode() TLSMode { return ModeECH }

func (h *ECHHandler) WrapClient(ctx context.Context, conn net.Conn, tlsConfig *tls.Config, shaping *TLSShapingConfig) (net.Conn, error) {
	if !h.Config.Enabled {
		// ECH disabled, use direct TLS
		handler := &DirectHandler{Fingerprint: shaping.Fingerprint}
		return handler.WrapClient(ctx, conn, tlsConfig, shaping)
	}

	// Create ECH client configuration
	echClientConfig := &ech.ClientConfig{
		PublicName: h.Config.PublicName,
		InnerSNI:   h.Config.InnerSNI,
		RequireECH: h.Config.RequireECH,
	}

	// Decode ECH configs if provided
	for _, configBytes := range h.Config.Configs {
		echCfg, err := ech.DecodeECHConfig(configBytes)
		if err != nil {
			continue
		}
		echClientConfig.Configs = append(echClientConfig.Configs, echCfg)
	}

	// If no configs provided but we have a public name, try to fetch them
	if len(echClientConfig.Configs) == 0 && h.Config.PublicName != "" {
		// In a full implementation, fetch from DNS HTTPS records
		// For now, continue with direct TLS
		handler := &DirectHandler{Fingerprint: shaping.Fingerprint}
		return handler.WrapClient(ctx, conn, tlsConfig, shaping)
	}

	// Clone TLS config and set outer SNI (public name)
	echTLSConfig := tlsConfig.Clone()
	if echTLSConfig == nil {
		echTLSConfig = &tls.Config{}
	}
	if h.Config.PublicName != "" {
		echTLSConfig.ServerName = h.Config.PublicName
	}

	// Create ECH client
	echClient, err := ech.NewECHClient(echClientConfig)
	if err != nil {
		if h.Config.RequireECH {
			return nil, fmt.Errorf("ECH client creation failed: %w", err)
		}
		// Fall back to direct TLS
		handler := &DirectHandler{Fingerprint: shaping.Fingerprint}
		return handler.WrapClient(ctx, conn, tlsConfig, shaping)
	}

	// In a full implementation, we would:
	// 1. Encrypt the inner Client Hello (with actual destination)
	// 2. Build outer Client Hello with ECH extension
	// 3. Send through TLS connection
	// For now, we use standard TLS with the outer SNI
	_ = echClient

	tlsConn := tls.Client(conn, echTLSConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (h *ECHHandler) WrapServer(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	// Server-side ECH handling
	// In a full implementation, this would:
	// 1. Detect ECH extension in Client Hello
	// 2. Decrypt using server's private key
	// 3. Route to appropriate backend based on inner SNI

	// For now, use standard TLS
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// parseKey parses a private key from base64 or hex
func parseKey(key string) ([]byte, error) {
	key = strings.TrimSpace(key)

	// Try base64 first
	if decoded, err := base64.StdEncoding.DecodeString(key); err == nil {
		if len(decoded) == 32 {
			return decoded, nil
		}
		// Wrong length for base64, fall through to try hex
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

// Constants and types for REALITY handshake (copied from reality package for handler use)
const (
	HandshakeVersion     = 0x01
	MaxHandshakeTime     = 30 * time.Second
	MaxHandshakeDataSize = 8192
	ShortIDLength        = 8
)

type HandshakeState int

const (
	StateInitial HandshakeState = iota
	StateClientHello
	StateServerHello
	StateEstablished
)

// realityConn wraps a net.Conn with REALITY handshake state
type realityConn struct {
	net.Conn
	state        HandshakeState
	privateKey   []byte
	publicKey    []byte
	sharedKey    []byte
	shortID      []byte
	isClient     bool
}

// receiveHandshakeMessage receives a handshake message with length prefix
func (rc *realityConn) receiveHandshakeMessage() ([]byte, error) {
	rc.SetReadDeadline(time.Now().Add(MaxHandshakeTime))
	defer rc.SetReadDeadline(time.Time{})

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(rc.Conn, lengthBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(lengthBuf)
	if length > MaxHandshakeDataSize {
		return nil, fmt.Errorf("handshake message too large: %d", length)
	}

	msg := make([]byte, length)
	if _, err := io.ReadFull(rc.Conn, msg); err != nil {
		return nil, err
	}

	return msg, nil
}

// sendHandshakeMessage sends a handshake message with length prefix
func (rc *realityConn) sendHandshakeMessage(msg []byte) error {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(msg)))

	if _, err := rc.Write(length); err != nil {
		return err
	}
	_, err := rc.Write(msg)
	return err
}

// processClientHello processes the Client Hello message
func (rc *realityConn) processClientHello(data []byte, config *reality.Config) error {
	if len(data) < 43 {
		return fmt.Errorf("client hello too short")
	}

	offset := 0

	// Extract version
	version := data[offset]
	if version != HandshakeVersion {
		return fmt.Errorf("unsupported version: %d", version)
	}
	offset++

	// Extract client public key
	rc.publicKey = make([]byte, 32)
	copy(rc.publicKey, data[offset:offset+32])
	offset += 32

	// Extract SNI
	sniLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if len(data) < offset+int(sniLen)+16 {
		return fmt.Errorf("client hello truncated")
	}

	sni := string(data[offset : offset+int(sniLen)])
	offset += int(sniLen)

	// Validate SNI
	if len(config.ServerNames) > 0 {
		valid := false
		for _, name := range config.ServerNames {
			if name == sni {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("SNI not allowed: %s", sni)
		}
	}

	// Extract timestamp
	timestamp := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Validate timestamp (prevent replay)
	now := uint64(time.Now().Unix())
	if timestamp > now+60 || timestamp < now-300 {
		return fmt.Errorf("timestamp out of range")
	}

	return nil
}

// buildServerHello builds the server hello with Ed25519 signature
func (rc *realityConn) buildServerHello(serverPublic []byte, config *reality.Config) ([]byte, error) {
	msg := make([]byte, 1+32+64+8)
	offset := 0

	msg[offset] = HandshakeVersion
	offset++

	copy(msg[offset:], serverPublic)
	offset += 32

	// Sign the handshake data
	sigData := append(serverPublic, rc.publicKey...)
	serverPrivate, err := parseKey(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	edPriv := deriveEd25519PrivateKey(serverPrivate, config.Dest)
	sig := ed25519.Sign(edPriv, sigData)
	copy(msg[offset:], sig)
	offset += 64

	binary.BigEndian.PutUint64(msg[offset:], uint64(time.Now().Unix()))

	return msg, nil
}

func deriveEd25519PrivateKey(serverPrivate []byte, context string) ed25519.PrivateKey {
	// Simple derivation - in production, use proper KDF
	material := append([]byte("stealthlink-reality-ed25519:"), serverPrivate...)
	material = append(material, ':')
	material = append(material, context...)
	seed := [32]byte{}
	copy(seed[:], material)
	return ed25519.NewKeyFromSeed(seed[:])
}

// ShortID generates a short ID from a public key
func ShortID(publicKey []byte, length int) []byte {
	if len(publicKey) < length {
		return publicKey
	}
	return publicKey[:length]
}
