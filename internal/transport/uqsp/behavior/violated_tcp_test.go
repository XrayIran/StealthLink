package behavior

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"stealthlink/internal/config"
)

func TestViolatedTCPOverlayModes(t *testing.T) {
	modes := []ViolatedTCPMode{
		ViolatedTCPModeMalformed,
		ViolatedTCPModeNoHandshake,
		ViolatedTCPModeRandomFlags,
		ViolatedTCPModeBrokenSeq,
	}

	for _, mode := range modes {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			cfg := config.ViolatedTCPBehaviorConfig{
				Enabled:       true,
				Mode:          string(mode),
				SeqRandomness: 1000,
				FlagCycling:   true,
				WindowJitter:  500,
			}

			overlay := NewViolatedTCPOverlay(cfg)
			if !overlay.Enabled() {
				t.Fatal("overlay should be enabled")
			}
			if overlay.Mode != mode {
				t.Fatalf("expected mode %s, got %s", mode, overlay.Mode)
			}

			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()

			wrapped, err := overlay.Apply(a)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}

			payload := []byte("test payload for violated tcp")
			errCh := make(chan error, 1)
			go func() {
				_, err := wrapped.Write(payload)
				errCh <- err
			}()

			buf := make([]byte, 1024)
			n, err := b.Read(buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			if n < len(payload)+22 {
				t.Fatalf("frame too short: got %d, expected at least %d", n, len(payload)+22)
			}

			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("write error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("write timeout")
			}
		})
	}
}

func TestViolatedTCPDisabled(t *testing.T) {
	cfg := config.ViolatedTCPBehaviorConfig{Enabled: false}
	overlay := NewViolatedTCPOverlay(cfg)

	if overlay.Enabled() {
		t.Fatal("overlay should be disabled")
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	wrapped, err := overlay.Apply(a)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	payload := []byte("plain data")
	go func() {
		wrapped.Write(payload)
	}()

	buf := make([]byte, 1024)
	n, err := b.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("disabled overlay should pass data unchanged: got %q", buf[:n])
	}
}

func TestViolatedTCPDefaultsToMalformed(t *testing.T) {
	cfg := config.ViolatedTCPBehaviorConfig{Enabled: true}
	overlay := NewViolatedTCPOverlay(cfg)

	if overlay.Mode != ViolatedTCPModeMalformed {
		t.Fatalf("expected default mode %s, got %s", ViolatedTCPModeMalformed, overlay.Mode)
	}
}

func TestViolatedTCPConnClose(t *testing.T) {
	cfg := config.ViolatedTCPBehaviorConfig{Enabled: true}
	overlay := NewViolatedTCPOverlay(cfg)

	a, b := net.Pipe()
	defer b.Close()

	wrapped, err := overlay.Apply(a)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err = wrapped.Write([]byte("after close"))
	if err == nil {
		t.Fatal("write after close should fail")
	}
}

func TestViolatedTCPFrameEncoding(t *testing.T) {
	cfg := config.ViolatedTCPBehaviorConfig{
		Enabled:       true,
		Mode:          string(ViolatedTCPModeMalformed),
		SeqRandomness: 0,
		FlagCycling:   false,
		WindowJitter:  0,
	}
	overlay := NewViolatedTCPOverlay(cfg)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	wrapped, err := overlay.Apply(a)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	payload := []byte("frame test")
	var received []byte
	var mu sync.Mutex

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := b.Read(buf)
		mu.Lock()
		received = buf[:n]
		mu.Unlock()
		errCh <- err
	}()

	if _, err := wrapped.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read timeout")
	}

	mu.Lock()
	defer mu.Unlock()

	if len(received) < 22+len(payload) {
		t.Fatalf("frame too short: got %d, expected at least %d", len(received), 22+len(payload))
	}

	header := received[:20]
	if header[12]&0x40 == 0 {
		t.Error("expected data offset to be set in malformed mode")
	}
}

func TestViolatedTCPRoundTrip(t *testing.T) {
	cfg := config.ViolatedTCPBehaviorConfig{
		Enabled: true,
		Mode:    string(ViolatedTCPModeRandomFlags),
	}
	overlay := NewViolatedTCPOverlay(cfg)

	leftRaw, rightRaw := net.Pipe()
	defer leftRaw.Close()
	defer rightRaw.Close()

	left, err := overlay.Apply(leftRaw)
	if err != nil {
		t.Fatalf("apply left: %v", err)
	}
	right, err := overlay.Apply(rightRaw)
	if err != nil {
		t.Fatalf("apply right: %v", err)
	}

	payload := []byte("roundtrip payload over violated tcp framing")
	writeErr := make(chan error, 1)
	go func() {
		_, err := left.Write(payload)
		writeErr <- err
	}()

	buf := make([]byte, 1024)
	n, err := right.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("unexpected payload: got %q, want %q", string(buf[:n]), string(payload))
	}

	select {
	case err := <-writeErr:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write timeout")
	}
}

func TestViolatedTCPFakeHTTPPrefaceIsFiltered(t *testing.T) {
	cfg := config.ViolatedTCPBehaviorConfig{
		Enabled:           true,
		Mode:              string(ViolatedTCPModeMalformed),
		FakeHTTPEnabled:   true,
		FakeHTTPHost:      "cdn.cloudflare.com",
		FakeHTTPUserAgent: "test-agent",
	}
	overlay := NewViolatedTCPOverlay(cfg)

	leftRaw, rightRaw := net.Pipe()
	defer leftRaw.Close()
	defer rightRaw.Close()

	left, err := overlay.Apply(leftRaw)
	if err != nil {
		t.Fatalf("apply left: %v", err)
	}
	right, err := overlay.Apply(rightRaw)
	if err != nil {
		t.Fatalf("apply right: %v", err)
	}

	payload := []byte("payload-after-preface")
	writeErr := make(chan error, 1)
	go func() {
		_, err := left.Write(payload)
		writeErr <- err
	}()

	buf := make([]byte, 1024)
	n, err := right.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("unexpected payload: got %q want %q", string(buf[:n]), string(payload))
	}

	select {
	case err := <-writeErr:
		if err != nil {
			t.Fatalf("write error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write timeout")
	}
}
