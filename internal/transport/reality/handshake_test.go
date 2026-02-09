package reality

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func testPrivateKeyB64() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestBuildServerHelloSignsWithDerivedKey(t *testing.T) {
	cfg := &Config{
		PrivateKey: testPrivateKeyB64(),
		Dest:       "example.com:443",
	}
	rc := &realityConn{publicKey: bytes.Repeat([]byte{0x42}, 32)}

	serverPriv, err := parseKey(cfg.PrivateKey)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	serverPublic, err := curve25519.X25519(serverPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive public: %v", err)
	}

	msg, err := rc.buildServerHello(serverPublic, cfg)
	if err != nil {
		t.Fatalf("build server hello: %v", err)
	}
	if got, want := len(msg), 105; got != want {
		t.Fatalf("unexpected server hello length: got %d want %d", got, want)
	}

	sig := msg[33:97]
	sigData := append(append([]byte{}, serverPublic...), rc.publicKey...)
	verifyKey := deriveEd25519Private(serverPriv, signingContext(cfg)).Public().(ed25519.PublicKey)
	if !ed25519.Verify(verifyKey, sigData, sig) {
		t.Fatalf("signature verification failed")
	}
}

func TestClientHelloServerParseRoundTrip(t *testing.T) {
	cfg := &Config{
		Dest:        "example.com",
		ServerNames: []string{"example.com"},
		PrivateKey:  testPrivateKeyB64(),
	}
	d := &Dialer{Config: cfg}
	rc := &realityConn{}

	clientPub := bytes.Repeat([]byte{0x24}, 32)
	msg, err := rc.buildRealityClientHello(d, clientPub, ShortID(clientPub, ShortIDLength))
	if err != nil {
		t.Fatalf("build client hello: %v", err)
	}

	serverConn := &realityConn{}
	if err := serverConn.processClientHello(msg, cfg); err != nil {
		t.Fatalf("process client hello: %v", err)
	}
	if !bytes.Equal(serverConn.publicKey, clientPub) {
		t.Fatalf("unexpected parsed client public key")
	}
}
