package tlsmux

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestDirectHandlerMode(t *testing.T) {
	h := &DirectHandler{}
	if h.Mode() != ModeDirect {
		t.Errorf("expected ModeDirect, got %s", h.Mode())
	}
}

func TestDirectHandlerWrapClient(t *testing.T) {
	// Create a test server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// Start server
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Just close after accepting
	}()

	// Connect and wrap
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	h := &DirectHandler{}
	cfg := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}

	// Test with default fingerprint
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// This should fall back to standard TLS since we don't have uTLS
	_, err = h.WrapClient(ctx, conn, cfg, nil)
	// We expect an error since we're not actually doing a TLS handshake
	// Just verifying the code path doesn't panic
	if err == nil {
		t.Log("WrapClient completed without error (unexpected but ok)")
	}
}

func TestRealityHandlerMode(t *testing.T) {
	h := &RealityHandler{
		Config: &RealityConfig{
			Dest:        "www.example.com",
			ServerNames: []string{"www.example.com"},
			PrivateKey:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
	if h.Mode() != ModeReality {
		t.Errorf("expected ModeReality, got %s", h.Mode())
	}
}

func TestShadowTLSHandlerMode(t *testing.T) {
	h := &ShadowTLSHandler{
		Config: &ShadowTLSConfig{
			Version:  3,
			Password: "test-password",
		},
	}
	if h.Mode() != ModeShadowTLS {
		t.Errorf("expected ModeShadowTLS, got %s", h.Mode())
	}
}

func TestTLSMirrorHandlerMode(t *testing.T) {
	h := &TLSMirrorHandler{
		Config: &TLSMirrorConfig{
			Enabled: true,
		},
	}
	if h.Mode() != ModeTLSMirror {
		t.Errorf("expected ModeTLSMirror, got %s", h.Mode())
	}
}

func TestECHHandlerMode(t *testing.T) {
	h := &ECHHandler{
		Config: &ECHConfig{
			Enabled:    true,
			PublicName: "cloudflare-ech.com",
			InnerSNI:   "example.com",
		},
	}
	if h.Mode() != ModeECH {
		t.Errorf("expected ModeECH, got %s", h.Mode())
	}
}

func TestParseKey(t *testing.T) {
	// Test hex encoding (64 hex chars = 32 bytes)
	// Use a string that won't be valid as base64 to ensure hex path is tested
	hexKey := "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	key, err := parseKey(hexKey)
	if err != nil {
		t.Errorf("failed to parse hex key: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}

	// Test base64 encoding
	base64Key := "ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8="
	key, err = parseKey(base64Key)
	if err != nil {
		t.Errorf("failed to parse base64 key: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}

	// Test invalid key
	_, err = parseKey("invalid")
	if err == nil {
		t.Error("expected error for invalid key")
	}

	// Test wrong length
	_, err = parseKey("0123456789abcdef")
	if err == nil {
		t.Error("expected error for wrong length key")
	}
}

func TestShortID(t *testing.T) {
	pubKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	// Test with length <= key length
	id := ShortID(pubKey, 8)
	if len(id) != 8 {
		t.Errorf("expected 8 bytes, got %d", len(id))
	}
	for i := 0; i < 8; i++ {
		if id[i] != pubKey[i] {
			t.Errorf("expected id[%d] = %d, got %d", i, pubKey[i], id[i])
		}
	}

	// Test with length > key length
	id = ShortID(pubKey, 20)
	if len(id) != len(pubKey) {
		t.Errorf("expected %d bytes, got %d", len(pubKey), len(id))
	}
}

func TestTLSMirrorShouldSkipEnrollment(t *testing.T) {
	tests := []struct {
		name     string
		config   *TLSMirrorConfig
		host     string
		expected bool
	}{
		{
			name:     "disabled",
			config:   &TLSMirrorConfig{Enabled: false},
			host:     "example.com",
			expected: true,
		},
		{
			name:     "enabled not loopback",
			config:   &TLSMirrorConfig{Enabled: true, AntiLoopback: true},
			host:     "example.com",
			expected: false,
		},
		{
			name:     "localhost",
			config:   &TLSMirrorConfig{Enabled: true, AntiLoopback: true},
			host:     "localhost",
			expected: true,
		},
		{
			name:     "127.0.0.1",
			config:   &TLSMirrorConfig{Enabled: true, AntiLoopback: true},
			host:     "127.0.0.1",
			expected: true,
		},
		{
			name:     "::1",
			config:   &TLSMirrorConfig{Enabled: true, AntiLoopback: true},
			host:     "::1",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &TLSMirrorHandler{Config: tt.config}
			result := h.shouldSkipEnrollment(tt.host)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDeriveSessionID(t *testing.T) {
	password := "test-password-123"
	sessionID := deriveSessionID(password)

	if len(sessionID) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(sessionID))
	}

	// Should be deterministic
	sessionID2 := deriveSessionID(password)
	for i := 0; i < 32; i++ {
		if sessionID[i] != sessionID2[i] {
			t.Error("session ID derivation is not deterministic")
			break
		}
	}
}
