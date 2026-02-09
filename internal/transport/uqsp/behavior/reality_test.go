package behavior

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestDeriveServerPublicKeyFromPrivateKey(t *testing.T) {
	private := make([]byte, 32)
	for i := range private {
		private[i] = byte(i + 1)
	}
	serverPublic, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive x25519 public: %v", err)
	}

	conn := &realityConn{
		serverPublic: serverPublic,
	}
	got := conn.deriveServerPublicKey()
	if len(got) != ed25519.PublicKeySize {
		t.Fatalf("public key size=%d want=%d", len(got), ed25519.PublicKeySize)
	}
	if bytes.Equal(got, make([]byte, ed25519.PublicKeySize)) {
		t.Fatal("derived public key is all zeros")
	}

	server := &RealityServerConn{PrivateKey: private}
	want := server.deriveEd25519PrivateKey().Public().(ed25519.PublicKey)
	if !bytes.Equal(got, want) {
		t.Fatalf("public key mismatch")
	}
}

func TestDeriveServerPublicKeyOverride(t *testing.T) {
	override := make([]byte, 32)
	for i := range override {
		override[i] = byte(255 - i)
	}
	conn := &realityConn{
		serverPublicKey: hex.EncodeToString(override),
	}
	got := conn.deriveServerPublicKey()
	want, err := deriveRealityEd25519PublicKeyFromX25519Public(override)
	if err != nil {
		t.Fatalf("derive want: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("override key mismatch")
	}
}

func TestDeriveServerPublicKeyMissing(t *testing.T) {
	conn := &realityConn{}
	if got := conn.deriveServerPublicKey(); got != nil {
		t.Fatalf("expected nil public key, got len=%d", len(got))
	}
}
