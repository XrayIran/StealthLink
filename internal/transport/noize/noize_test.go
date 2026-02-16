package noize

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfigApplyDefaults(t *testing.T) {
	cfg := Config{Enabled: true}
	cfg.ApplyDefaults()
	if cfg.JunkInterval == 0 {
		t.Fatalf("expected JunkInterval default to be set when enabled")
	}
	if cfg.JunkMinSize <= 0 {
		t.Fatalf("expected JunkMinSize default > 0")
	}
	if cfg.JunkMaxSize < cfg.JunkMinSize {
		t.Fatalf("expected JunkMaxSize >= JunkMinSize")
	}
	if cfg.MaxJunkPercent <= 0 || cfg.MaxJunkPercent > 95 {
		t.Fatalf("expected MaxJunkPercent in (0,95], got %d", cfg.MaxJunkPercent)
	}
}

func TestGenerateJunkSizeBounds(t *testing.T) {
	n := New(Config{
		Enabled:          true,
		Preset:           "",
		JunkInterval:     0,
		JunkMinSize:      50,
		JunkMaxSize:      80,
		SignaturePackets: []string{},
	})
	for i := 0; i < 200; i++ {
		b := n.GenerateJunk()
		if len(b) < 50 || len(b) > 80 {
			t.Fatalf("expected junk size in [50,80], got %d", len(b))
		}
	}
}

func TestGenerateJunkSignatureHTTPSLooksLikeTLS(t *testing.T) {
	n := New(Config{
		Enabled:          true,
		JunkInterval:     0,
		JunkMinSize:      200,
		JunkMaxSize:      200,
		SignaturePackets: []string{"https"},
	})
	b := n.GenerateJunk()
	if len(b) != 200 {
		t.Fatalf("expected fixed junk size 200, got %d", len(b))
	}
	// TLS ClientHello record content type is 0x16. We only assert it often matches.
	if b[0] != 0x16 {
		t.Fatalf("expected https signature to start with 0x16, got 0x%02x", b[0])
	}
}

func TestStartStopSendsJunk(t *testing.T) {
	var sent atomic.Int64
	n := New(Config{
		Enabled:          true,
		JunkInterval:     5 * time.Millisecond,
		JunkMinSize:      64,
		JunkMaxSize:      80,
		SignaturePackets: []string{"dns"},
	})

	n.Start(func(b []byte) error {
		if len(b) < 64 || len(b) > 80 {
			t.Fatalf("expected sent junk size in [64,80], got %d", len(b))
		}
		// DNS payload should usually contain a header with QDCOUNT=1 in our generator,
		// but don't overfit; just ensure it isn't all zeros.
		if bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("unexpected all-zero junk")
		}
		sent.Add(1)
		return nil
	})

	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		if sent.Load() > 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	n.Stop()

	if sent.Load() == 0 {
		t.Fatalf("expected at least one junk send before Stop()")
	}
}
