package behavior

import (
	"io"
	"net"
	"testing"
	"time"

	"stealthlink/internal/config"
)

func TestAnyTLSOverlayRoundTrip(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	ov := NewAnyTLSOverlay(config.AnyTLSBehaviorConfig{
		Enabled:    true,
		Password:   "secret",
		PaddingMin: 1,
		PaddingMax: 8,
	})

	clientConn, err := ov.Apply(clientRaw)
	if err != nil {
		t.Fatalf("client apply: %v", err)
	}
	serverConn, err := ov.Apply(serverRaw)
	if err != nil {
		t.Fatalf("server apply: %v", err)
	}

	want := []byte("hello-anytls-roundtrip")
	go func() {
		_, _ = clientConn.Write(want)
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("read full: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

func TestAnyTLSOverlayWrongPasswordFails(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	clientOv := NewAnyTLSOverlay(config.AnyTLSBehaviorConfig{
		Enabled:  true,
		Password: "a",
	})
	serverOv := NewAnyTLSOverlay(config.AnyTLSBehaviorConfig{
		Enabled:  true,
		Password: "b",
	})

	clientConn, err := clientOv.Apply(clientRaw)
	if err != nil {
		t.Fatalf("client apply: %v", err)
	}
	serverConn, err := serverOv.Apply(serverRaw)
	if err != nil {
		t.Fatalf("server apply: %v", err)
	}

	go func() {
		_, _ = clientConn.Write([]byte("mismatch"))
	}()

	_ = serverConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 32)
	_, err = serverConn.Read(buf)
	if err == nil {
		t.Fatal("expected read error with wrong password")
	}
}
