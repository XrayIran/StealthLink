package tlsutil

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

func DialUTLS(ctx context.Context, network, addr string, cfg *tls.Config, fingerprint string) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	if fn, ok := BaseDialFuncFromContext(ctx); ok {
		conn, err = fn(ctx, network, addr)
	} else {
		d := &net.Dialer{}
		conn, err = d.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	return WrapUTLS(ctx, conn, cfg, fingerprint)
}

// DialUTLSWithFragmentation dials with uTLS and optional TLS fragmentation.
func DialUTLSWithFragmentation(ctx context.Context, network, addr string, cfg *tls.Config, fingerprint string, fragConfig FragmentConfig) (net.Conn, error) {
	if !fragConfig.Enabled {
		return DialUTLS(ctx, network, addr, cfg, fingerprint)
	}

	fragConfig.ApplyDefaults()

	var (
		conn net.Conn
		err  error
	)
	if fn, ok := BaseDialFuncFromContext(ctx); ok {
		conn, err = fn(ctx, network, addr)
	} else {
		d := &net.Dialer{}
		conn, err = d.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}

	// Wrap with fragmentation before uTLS
	fragConn := NewFragmentedConn(conn, fragConfig)

	// Perform uTLS handshake over fragmented connection
	uCfg := &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.RootCAs,
		NextProtos:         cfg.NextProtos,
		MinVersion:         cfg.MinVersion,
		MaxVersion:         cfg.MaxVersion,
	}

	hello := helloID(fingerprint)
	uconn := utls.UClient(fragConn, uCfg, hello)
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return uconn, nil
}

// WrapUTLS performs a uTLS handshake over an existing connection.
func WrapUTLS(ctx context.Context, conn net.Conn, cfg *tls.Config, fingerprint string) (net.Conn, error) {
	uCfg := &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.RootCAs,
		NextProtos:         cfg.NextProtos,
		MinVersion:         cfg.MinVersion,
		MaxVersion:         cfg.MaxVersion,
	}

	hello := helloID(fingerprint)
	uconn := utls.UClient(conn, uCfg, hello)
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return uconn, nil
}

// Extended fingerprint database with browser fingerprints
// Uses only fingerprints available in the current utls version
type fingerprintInfo struct {
	ID     utls.ClientHelloID
	Weight int // Weight for random selection
}

// fingerprintDatabase contains all available fingerprints with weights.
// Weights are based on real-world browser usage statistics.
var fingerprintDatabase = map[string]fingerprintInfo{
	// Chrome variants (highest weight due to popularity)
	"chrome":      {utls.HelloChrome_Auto, 30},
	"chrome_auto": {utls.HelloChrome_Auto, 30},
	"chrome_120":  {utls.HelloChrome_120, 25},
	"chrome_102":  {utls.HelloChrome_102, 10},
	"chrome_100":  {utls.HelloChrome_100, 5},
	"chrome_96":   {utls.HelloChrome_96, 3},
	"chrome_87":   {utls.HelloChrome_102, 2}, // Fallback to available version
	"chrome_83":   {utls.HelloChrome_102, 1}, // Fallback to available version

	// Firefox variants
	"firefox":      {utls.HelloFirefox_Auto, 15},
	"ff":           {utls.HelloFirefox_Auto, 15},
	"firefox_auto": {utls.HelloFirefox_Auto, 15},
	"firefox_105":  {utls.HelloFirefox_105, 10},
	"firefox_102":  {utls.HelloFirefox_102, 8},
	"firefox_99":   {utls.HelloFirefox_99, 3},

	// Safari variants
	"safari":      {utls.HelloSafari_Auto, 12},
	"safari_auto": {utls.HelloSafari_Auto, 12},
	"safari_16":   {utls.HelloSafari_16_0, 8},
	"safari_16_0": {utls.HelloSafari_16_0, 8},

	// iOS variants
	"ios":      {utls.HelloIOS_Auto, 10},
	"ios_auto": {utls.HelloIOS_Auto, 10},
	"ios_16":   {utls.HelloSafari_16_0, 6},

	// Edge variants
	"edge":      {utls.HelloEdge_Auto, 8},
	"edge_auto": {utls.HelloEdge_Auto, 8},
	"edge_106":  {utls.HelloEdge_106, 5},

	// 360 Browser (popular in China)
	"360":      {utls.Hello360_Auto, 5},
	"360_auto": {utls.Hello360_Auto, 5},
	"360_11_0": {utls.Hello360_11_0, 3},
	"360_7_5":  {utls.Hello360_7_5, 1},

	// QQ Browser (popular in China)
	"qq":      {utls.HelloQQ_Auto, 4},
	"qq_auto": {utls.HelloQQ_Auto, 4},

	// Special fingerprints
	"random":            {utls.HelloRandomized, 1},
	"randomized":        {utls.HelloRandomized, 1},
	"randomized_noalpn": {utls.HelloRandomizedALPN, 1},
	"golang":            {utls.HelloGolang, 1},
	"hello_golang":      {utls.HelloGolang, 1},
}

func helloID(name string) utls.ClientHelloID {
	if info, ok := fingerprintDatabase[name]; ok {
		return info.ID
	}

	// Fallback for common prefixes
	switch name {
	case "chrome", "chrome_auto":
		return utls.HelloChrome_Auto
	case "firefox", "ff":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "360":
		return utls.Hello360_Auto
	case "qq":
		return utls.HelloQQ_Auto
	case "random", "randomized":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

// GetWeightedRandomFingerprint returns a fingerprint based on weighted random selection.
// This mimics real-world browser distribution.
func GetWeightedRandomFingerprint() utls.ClientHelloID {
	totalWeight := 0
	for _, info := range fingerprintDatabase {
		totalWeight += info.Weight
	}

	r := mathrand.Intn(totalWeight)
	cumulative := 0

	for _, info := range fingerprintDatabase {
		cumulative += info.Weight
		if r < cumulative {
			return info.ID
		}
	}

	return utls.HelloChrome_Auto // Fallback
}

// GetFingerprintByWeight returns a fingerprint from a specific category with weighting.
func GetFingerprintByWeight(category string) utls.ClientHelloID {
	var candidates []fingerprintInfo

	for name, info := range fingerprintDatabase {
		if strings.HasPrefix(name, category) {
			candidates = append(candidates, info)
		}
	}

	if len(candidates) == 0 {
		return utls.HelloChrome_Auto
	}

	totalWeight := 0
	for _, info := range candidates {
		totalWeight += info.Weight
	}

	r := mathrand.Intn(totalWeight)
	cumulative := 0

	for _, info := range candidates {
		cumulative += info.Weight
		if r < cumulative {
			return info.ID
		}
	}

	return candidates[0].ID
}

func EnsureServerName(cfg *tls.Config, addr string) (*tls.Config, error) {
	if cfg == nil {
		return nil, fmt.Errorf("tls config required")
	}
	if cfg.ServerName != "" {
		return cfg, nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return cfg, nil
	}
	copyCfg := cfg.Clone()
	copyCfg.ServerName = host
	return copyCfg, nil
}

// RotatingFingerprint provides automatic rotation of TLS fingerprints.
type RotatingFingerprint struct {
	mu           sync.RWMutex
	fingerprints []string      // List of fingerprint names to rotate through
	currentIndex int           // Current position in the list
	interval     time.Duration // Rotation interval
	maxUses      int           // Max uses before rotation
	useCount     int           // Current use count
	lastRotation time.Time     // Last rotation timestamp
	ticker       *time.Ticker  // Rotation ticker
	stopCh       chan struct{} // Stop signal
}

// NewRotatingFingerprint creates a new rotating fingerprint manager.
func NewRotatingFingerprint(fingerprints []string, interval time.Duration, maxUses int) *RotatingFingerprint {
	if len(fingerprints) == 0 {
		fingerprints = []string{"chrome", "firefox", "safari", "edge"}
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if maxUses <= 0 {
		maxUses = 100
	}

	r := &RotatingFingerprint{
		fingerprints: fingerprints,
		interval:     interval,
		maxUses:      maxUses,
		lastRotation: time.Now(),
		stopCh:       make(chan struct{}),
	}

	// Start background rotation
	r.ticker = time.NewTicker(interval)
	go r.rotationLoop()

	return r
}

// rotationLoop handles time-based rotation.
func (r *RotatingFingerprint) rotationLoop() {
	for {
		select {
		case <-r.ticker.C:
			r.rotate()
		case <-r.stopCh:
			r.ticker.Stop()
			return
		}
	}
}

// rotate advances to the next fingerprint.
func (r *RotatingFingerprint) rotate() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.currentIndex = (r.currentIndex + 1) % len(r.fingerprints)
	r.useCount = 0
	r.lastRotation = time.Now()
}

// GetFingerprint returns the current fingerprint and checks if rotation is needed.
func (r *RotatingFingerprint) GetFingerprint() utls.ClientHelloID {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we need to rotate based on use count
	r.useCount++
	if r.useCount >= r.maxUses {
		r.currentIndex = (r.currentIndex + 1) % len(r.fingerprints)
		r.useCount = 0
		r.lastRotation = time.Now()
	}

	return helloID(r.fingerprints[r.currentIndex])
}

// GetFingerprintName returns the current fingerprint name.
func (r *RotatingFingerprint) GetFingerprintName() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fingerprints[r.currentIndex]
}

// Stop stops the rotation ticker.
func (r *RotatingFingerprint) Stop() {
	close(r.stopCh)
}

// RandomFingerprint returns a random fingerprint from the standard set.
// Uses weighted random selection based on real-world browser usage.
func RandomFingerprint() utls.ClientHelloID {
	return GetWeightedRandomFingerprint()
}

// CustomFingerprint builds a fingerprint from captured traffic data.
// This is a placeholder for future implementation that would allow
// building fingerprints from real browser captures.
type CustomFingerprint struct {
	CipherSuites       []uint16
	Extensions         []utls.TLSExtension
	CompressionMethods []uint8
}

// ToClientHelloID converts a custom fingerprint to a uTLS ClientHelloID.
func (cf *CustomFingerprint) ToClientHelloID() utls.ClientHelloID {
	// This would require implementing a custom spec function
	// For now, return randomized
	return utls.HelloRandomized
}

// BuildClientHello builds a TLS 1.3 ClientHello for the given server name
func BuildClientHello(serverName string) ([]byte, error) {
	// Create a uTLS config
	config := &utls.Config{
		ServerName: serverName,
		MinVersion: utls.VersionTLS13,
		MaxVersion: utls.VersionTLS13,
	}

	// Use Chrome fingerprint for realistic ClientHello
	helloID := utls.HelloChrome_Auto

	// Create a mock connection (we only need the serialized ClientHello)
	// We'll use utls to build the ClientHello message
	spec, err := utls.UTLSIdToSpec(helloID)
	if err != nil {
		// Fallback to building manually
		return buildClientHelloManual(serverName)
	}

	// Apply server name to SNI extension
	for i, ext := range spec.Extensions {
		if sni, ok := ext.(*utls.SNIExtension); ok {
			sni.ServerName = serverName
			spec.Extensions[i] = sni
			break
		}
	}

	// Create a ClientHello message
	uconn := utls.UClient(nil, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		return buildClientHelloManual(serverName)
	}

	// Marshal the ClientHello
	helloBytes, err := uconn.HandshakeState.Hello.Marshal()
	if err != nil {
		return buildClientHelloManual(serverName)
	}

	// Build TLS record
	record := make([]byte, 5+len(helloBytes))
	record[0] = 0x16 // Content type: Handshake
	record[1] = 0x03 // Version: TLS 1.0 (for record layer compatibility)
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(helloBytes)))
	copy(record[5:], helloBytes)

	return record, nil
}

// buildClientHelloManual builds a ClientHello manually (fallback)
func buildClientHelloManual(serverName string) ([]byte, error) {
	// Build a minimal TLS 1.3 ClientHello
	random := make([]byte, 32)
	rand.Read(random)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	// Cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
	cipherSuites := []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03}

	// Compression methods: null
	compressionMethods := []byte{0x01, 0x00}

	// Build extensions
	extensions := buildExtensions(serverName)

	// Calculate lengths
	sessionIDLen := len(sessionID)
	cipherSuitesLen := len(cipherSuites)
	compressionLen := len(compressionMethods)
	extensionsLen := len(extensions)

	// Build ClientHello body
	// Version (2) + Random (32) + SessionID Len (1) + SessionID + CipherSuites Len (2) + CipherSuites +
	// Compression Len (1) + Compression + Extensions Len (2) + Extensions
	bodyLen := 2 + 32 + 1 + sessionIDLen + 2 + cipherSuitesLen + 1 + compressionLen + 2 + extensionsLen
	body := make([]byte, bodyLen)
	offset := 0

	// Version TLS 1.2 (0x0303)
	body[offset] = 0x03
	body[offset+1] = 0x03
	offset += 2

	// Random
	copy(body[offset:], random)
	offset += 32

	// Session ID length and value
	body[offset] = byte(sessionIDLen)
	offset++
	copy(body[offset:], sessionID)
	offset += sessionIDLen

	// Cipher suites length and value
	binary.BigEndian.PutUint16(body[offset:], uint16(cipherSuitesLen))
	offset += 2
	copy(body[offset:], cipherSuites)
	offset += cipherSuitesLen

	// Compression methods length and value
	body[offset] = byte(compressionLen)
	offset++
	copy(body[offset:], compressionMethods)
	offset += compressionLen

	// Extensions length and value
	binary.BigEndian.PutUint16(body[offset:], uint16(extensionsLen))
	offset += 2
	copy(body[offset:], extensions)

	// Build handshake message
	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01 // ClientHello
	binaryBigEndianPutUint24(handshake[1:4], uint32(len(body)))
	copy(handshake[4:], body)

	// Build TLS record
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16 // Content type: Handshake
	record[1] = 0x03 // Version: TLS 1.0
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	return record, nil
}

// buildExtensions builds standard TLS extensions
func buildExtensions(serverName string) []byte {
	extensions := []byte{}

	// SNI Extension (0x0000)
	sniExt := buildSNIExtension(serverName)
	extensions = append(extensions, sniExt...)

	// Supported Versions (0x002b) - TLS 1.3
	supportedVersions := []byte{
		0x00, 0x2b, // Extension type
		0x00, 0x03, // Length
		0x02,       // Versions list length
		0x03, 0x04, // TLS 1.3
	}
	extensions = append(extensions, supportedVersions...)

	// Supported Groups (0x000a)
	supportedGroups := []byte{
		0x00, 0x0a, // Extension type
		0x00, 0x08, // Length
		0x00, 0x06, // Groups list length
		0x00, 0x17, // secp256r1
		0x00, 0x18, // secp384r1
		0x00, 0x19, // secp521r1
	}
	extensions = append(extensions, supportedGroups...)

	// EC Point Formats (0x000b)
	ecPointFormats := []byte{
		0x00, 0x0b, // Extension type
		0x00, 0x02, // Length
		0x01, // Formats length
		0x00, // uncompressed
	}
	extensions = append(extensions, ecPointFormats...)

	// Signature Algorithms (0x000d)
	sigAlgorithms := []byte{
		0x00, 0x0d, // Extension type
		0x00, 0x12, // Length
		0x00, 0x10, // Algorithms list length
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x05, 0x03, // ecdsa_secp384r1_sha384
		0x06, 0x03, // ecdsa_secp521r1_sha512
		0x08, 0x07, // ed25519
		0x08, 0x08, // ed448
		0x08, 0x04, // rsa_pss_rsae_sha256
		0x08, 0x05, // rsa_pss_rsae_sha384
		0x08, 0x06, // rsa_pss_rsae_sha512
	}
	extensions = append(extensions, sigAlgorithms...)

	// ALPN (0x0010)
	alpn := []byte{
		0x00, 0x10, // Extension type
		0x00, 0x0b, // Length
		0x00, 0x09, // ALPN list length
		0x02, 0x68, 0x32, // "h2"
		0x05, 0x68, 0x32, 0x2d, 0x31, 0x34, // "h2-14"
	}
	extensions = append(extensions, alpn...)

	// Key Share (0x0033)
	keyShare := []byte{
		0x00, 0x33, // Extension type
		0x00, 0x02, // Length
		0x00, 0x00, // Empty key share (for simplicity)
	}
	extensions = append(extensions, keyShare...)

	// PSK Key Exchange Modes (0x002d)
	pskModes := []byte{
		0x00, 0x2d, // Extension type
		0x00, 0x02, // Length
		0x01, // Modes length
		0x01, // PSK with (EC)DHE key establishment
	}
	extensions = append(extensions, pskModes...)

	return extensions
}

// buildSNIExtension builds the SNI extension
func buildSNIExtension(serverName string) []byte {
	nameLen := len(serverName)
	listLen := nameLen + 3 // name_type (1) + name_len (2) + name
	sniLen := listLen + 2  // list_length (2) + list

	ext := make([]byte, 4+sniLen)
	offset := 0

	// Extension type
	ext[offset] = 0x00
	ext[offset+1] = 0x00
	offset += 2

	// Extension length
	binary.BigEndian.PutUint16(ext[offset:], uint16(sniLen))
	offset += 2

	// SNI list length
	binary.BigEndian.PutUint16(ext[offset:], uint16(listLen))
	offset += 2

	// Name type (hostname = 0)
	ext[offset] = 0x00
	offset++

	// Name length
	binary.BigEndian.PutUint16(ext[offset:], uint16(nameLen))
	offset += 2

	// Name
	copy(ext[offset:], serverName)

	return ext
}

// ParseSNI extracts the SNI from a ClientHello
func ParseSNI(clientHello []byte) (string, error) {
	if len(clientHello) < 5 {
		return "", fmt.Errorf("client hello too short")
	}

	// Skip TLS record header
	offset := 5

	if len(clientHello) < offset+4 {
		return "", fmt.Errorf("incomplete handshake header")
	}

	// Skip handshake type
	if clientHello[offset] != 0x01 {
		return "", fmt.Errorf("not a ClientHello")
	}
	offset++

	// Get handshake length
	handshakeLen := int(clientHello[offset])<<16 | int(clientHello[offset+1])<<8 | int(clientHello[offset+2])
	offset += 3

	if len(clientHello) < offset+handshakeLen {
		return "", fmt.Errorf("incomplete ClientHello")
	}

	// Skip version (2) and random (32)
	offset += 34

	if offset >= len(clientHello) {
		return "", fmt.Errorf("truncated ClientHello")
	}

	// Skip session ID
	sessionIDLen := int(clientHello[offset])
	offset += 1 + sessionIDLen

	if offset >= len(clientHello) {
		return "", fmt.Errorf("truncated ClientHello after session ID")
	}

	// Skip cipher suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(clientHello[offset:]))
	offset += 2 + cipherSuitesLen

	if offset >= len(clientHello) {
		return "", fmt.Errorf("truncated ClientHello after cipher suites")
	}

	// Skip compression methods
	compressionLen := int(clientHello[offset])
	offset += 1 + compressionLen

	if offset+2 > len(clientHello) {
		return "", fmt.Errorf("no extensions")
	}

	// Get extensions length
	extensionsLen := int(binary.BigEndian.Uint16(clientHello[offset:]))
	offset += 2

	if offset+extensionsLen > len(clientHello) {
		return "", fmt.Errorf("truncated extensions")
	}

	// Parse extensions looking for SNI (type 0x0000)
	extEnd := offset + extensionsLen
	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(clientHello[offset:])
		extLen := int(binary.BigEndian.Uint16(clientHello[offset+2:]))
		offset += 4

		if offset+extLen > extEnd {
			break
		}

		if extType == 0x0000 { // SNI
			// Parse SNI list
			if extLen < 2 {
				break
			}
			listLen := int(binary.BigEndian.Uint16(clientHello[offset:]))
			listOffset := offset + 2

			if listOffset+listLen > offset+extLen {
				break
			}

			// Parse SNI entry
			if listOffset+3 <= offset+extLen {
				// name_type := clientHello[listOffset]
				nameLen := int(binary.BigEndian.Uint16(clientHello[listOffset+1:]))
				nameOffset := listOffset + 3

				if nameOffset+nameLen <= offset+extLen {
					return string(clientHello[nameOffset : nameOffset+nameLen]), nil
				}
			}
		}

		offset += extLen
	}

	return "", fmt.Errorf("SNI not found")
}

// BuildServerHello builds a TLS 1.3 ServerHello
func BuildServerHello() []byte {
	// Generate random
	random := make([]byte, 32)
	rand.Read(random)

	// Session ID (echo client's, empty for now)
	sessionID := []byte{}

	// Cipher suite: TLS_AES_128_GCM_SHA256
	cipherSuite := []byte{0x13, 0x01}

	// Compression method: null
	compression := []byte{0x00}

	// Extensions
	extensions := []byte{
		// Supported Versions (TLS 1.3)
		0x00, 0x2b, // Extension type
		0x00, 0x03, // Length
		0x02,       // Version list length
		0x03, 0x04, // TLS 1.3
	}

	// Build ServerHello body
	bodyLen := 2 + 32 + 1 + len(sessionID) + 2 + 1 + 2 + len(extensions)
	body := make([]byte, bodyLen)
	offset := 0

	// Version TLS 1.2 (0x0303)
	body[offset] = 0x03
	body[offset+1] = 0x03
	offset += 2

	// Random
	copy(body[offset:], random)
	offset += 32

	// Session ID length and value
	body[offset] = byte(len(sessionID))
	offset++
	copy(body[offset:], sessionID)
	offset += len(sessionID)

	// Cipher suite
	copy(body[offset:], cipherSuite)
	offset += 2

	// Compression method
	copy(body[offset:], compression)
	offset++

	// Extensions length and value
	binary.BigEndian.PutUint16(body[offset:], uint16(len(extensions)))
	offset += 2
	copy(body[offset:], extensions)

	// Build handshake message
	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x02 // ServerHello
	binaryBigEndianPutUint24(handshake[1:4], uint32(len(body)))
	copy(handshake[4:], body)

	// Build TLS record
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16 // Content type: Handshake
	record[1] = 0x03 // Version: TLS 1.2
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	return record
}

// Helper function for big-endian 24-bit
func binaryBigEndianPutUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}
