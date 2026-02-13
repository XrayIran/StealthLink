package behavior

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"
)

func TestObfs4OverlayValidateDerivesKeypairFromSeed(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	ov := &Obfs4Overlay{
		EnabledField: true,
		Seed:         base64.StdEncoding.EncodeToString(seed),
		ServerMode:   true,
	}
	if err := ov.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if len(ov.publicKeyBytes) != 32 {
		t.Fatalf("public key length = %d, want 32", len(ov.publicKeyBytes))
	}
	if len(ov.privateKeyBytes) != 32 {
		t.Fatalf("private key length = %d, want 32", len(ov.privateKeyBytes))
	}
	if len(ov.nodeIDBytes) != 32 {
		t.Fatalf("node id length = %d, want 32", len(ov.nodeIDBytes))
	}
}

func TestObfs4OverlayRoundTripWithSeedOnly(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(255 - i)
	}
	seedB64 := base64.StdEncoding.EncodeToString(seed)

	clientOverlay := &Obfs4Overlay{
		EnabledField: true,
		Seed:         seedB64,
		IATMode:      0,
	}
	serverOverlay := &Obfs4Overlay{
		EnabledField: true,
		Seed:         seedB64,
		IATMode:      0,
		ServerMode:   true,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		baseConn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer baseConn.Close()
		serverConn, err := serverOverlay.Apply(baseConn)
		if err != nil {
			serverErr <- err
			return
		}
		defer serverConn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(buf, []byte("ping")) {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		_, err = serverConn.Write([]byte("pong"))
		serverErr <- err
	}()

	baseClientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer baseClientConn.Close()

	clientConn, err := clientOverlay.Apply(baseClientConn)
	if err != nil {
		t.Fatalf("client Apply() error = %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("client write error: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("client read error: %v", err)
	}
	if !bytes.Equal(reply, []byte("pong")) {
		t.Fatalf("reply = %q, want %q", string(reply), "pong")
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server roundtrip error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server roundtrip timed out")
	}
}

func TestDeriveKeysReturns64Bytes(t *testing.T) {
	shared := bytes.Repeat([]byte{0x11}, 32)
	clientPub := bytes.Repeat([]byte{0x22}, 32)
	serverPub := bytes.Repeat([]byte{0x33}, 32)
	keys := deriveKeys(shared, clientPub, serverPub)
	if len(keys) != 64 {
		t.Fatalf("deriveKeys length = %d, want 64", len(keys))
	}
}
