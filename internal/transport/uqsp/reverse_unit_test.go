package uqsp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// UPSTREAM_WIRING: daggerConnect
// UPSTREAM_WIRING: Tunnel

func TestReverseDialer_BackoffWithJitter_DeterministicAndBounded(t *testing.T) {
	mode := &ReverseMode{
		Enabled:       true,
		Role:          "dialer",
		ClientAddress: "1.2.3.4:443",
		ServerAddress: "0.0.0.0:0",
		AuthToken:     "token",
	}
	a := NewReverseDialer(mode, nil)
	b := NewReverseDialer(mode, nil)

	base := 2 * time.Second
	max := 10 * time.Second

	aj := a.backoffWithJitter(base, max)
	bj := b.backoffWithJitter(base, max)
	if aj != bj {
		t.Fatalf("expected deterministic jitter for identical dialers, got %v vs %v", aj, bj)
	}
	if aj < base {
		t.Fatalf("expected jitter >= base, got %v < %v", aj, base)
	}
	if aj > max {
		t.Fatalf("expected jitter <= max, got %v > %v", aj, max)
	}
	// Jitter is bounded to 15% of base (see reverse.go).
	if aj > base+(base*15)/100 {
		t.Fatalf("expected jitter <= base*1.15, got %v", aj)
	}
}

func TestReverseDialer_AuthToken_Validated(t *testing.T) {
	mode := &ReverseMode{Enabled: true, Role: "dialer", AuthToken: "secret"}
	d := NewReverseDialer(mode, nil)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errc := make(chan error, 2)
	go func() { errc <- d.sendAuth(c1) }()
	go func() { errc <- d.verifyAuth(c2) }()

	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Fatalf("auth path failed: %v", err)
		}
	}
}

func TestReverseDialer_UsesInjectedDialFn(t *testing.T) {
	var calls atomic.Int64
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		if network != "tcp" || addr != "127.0.0.1:1" {
			return nil, errors.New("unexpected dial args")
		}
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	mode := &ReverseMode{
		Enabled:          true,
		Role:             "dialer",
		ClientAddress:    "127.0.0.1:1",
		MaxRetries:       1,
		ReconnectBackoff: 10 * time.Millisecond,
		ReconnectDelay:   10 * time.Millisecond,
	}
	d := NewReverseDialerWithDialFunc(mode, nil, dialFn)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Close()

	// Dial waits for a connection to be established by the dial loop.
	c, err := d.Dial("tcp", "")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = c.Close()
	if calls.Load() == 0 {
		t.Fatal("expected injected dialFn to be called")
	}
}

func TestReverseDialer_AuthReplayRejected(t *testing.T) {
	mode := &ReverseMode{Enabled: true, Role: "listener", AuthToken: "secret"}
	d := NewReverseDialer(mode, nil)

	nonce := make([]byte, reverseAuthNonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	pkt := buildAuthPacket(t, time.Now().UnixNano(), nonce, "secret")

	resp1, err1 := verifyWithPacket(t, d, pkt)
	if err1 != nil {
		t.Fatalf("first auth should succeed, got error: %v", err1)
	}
	if resp1 != [2]byte{0x00, 0x00} {
		t.Fatalf("first auth expected success response, got %x", resp1)
	}

	resp2, err2 := verifyWithPacket(t, d, pkt)
	if err2 == nil {
		t.Fatal("expected replay auth to fail")
	}
	if resp2 != [2]byte{0xFF, 0xFF} {
		t.Fatalf("replay auth expected rejection response, got %x", resp2)
	}
}

func TestReverseDialer_AuthTimestampSkewRejected(t *testing.T) {
	mode := &ReverseMode{Enabled: true, Role: "listener", AuthToken: "secret"}
	d := NewReverseDialer(mode, nil)

	nonce := make([]byte, reverseAuthNonceSize)
	nonce[0] = 0x42
	pkt := buildAuthPacket(t, time.Now().Add(-2*time.Minute).UnixNano(), nonce, "secret")

	resp, err := verifyWithPacket(t, d, pkt)
	if err == nil {
		t.Fatal("expected timestamp skew auth to fail")
	}
	if resp != [2]byte{0xFF, 0xFF} {
		t.Fatalf("timestamp skew expected rejection response, got %x", resp)
	}
}

func buildAuthPacket(t *testing.T, ts int64, nonce []byte, token string) []byte {
	t.Helper()
	if len(nonce) != reverseAuthNonceSize {
		t.Fatalf("nonce must be %d bytes, got %d", reverseAuthNonceSize, len(nonce))
	}
	if len(token) > 4096 {
		t.Fatalf("token too long: %d", len(token))
	}

	pkt := make([]byte, 1+8+reverseAuthNonceSize+len(token))
	pkt[0] = reverseAuthVersion
	binary.BigEndian.PutUint64(pkt[1:9], uint64(ts))
	copy(pkt[9:9+reverseAuthNonceSize], nonce)
	copy(pkt[9+reverseAuthNonceSize:], []byte(token))
	return pkt
}

func verifyWithPacket(t *testing.T, d *ReverseDialer, pkt []byte) ([2]byte, error) {
	t.Helper()
	c1, c2 := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.verifyAuth(c2)
	}()

	if _, err := c1.Write(pkt); err != nil {
		_ = c1.Close()
		_ = c2.Close()
		t.Fatalf("write auth packet: %v", err)
	}

	var resp [2]byte
	if _, err := io.ReadFull(c1, resp[:]); err != nil {
		_ = c1.Close()
		_ = c2.Close()
		t.Fatalf("read auth response: %v", err)
	}

	_ = c1.Close()
	_ = c2.Close()
	return resp, <-errCh
}
