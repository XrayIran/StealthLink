package kcpbase

import (
	"context"
	"testing"
	"time"
)

func TestKCPConnCloseStopsAutoTuneLoop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AutoTuneFEC = true

	ln, err := Listen("127.0.0.1:0", cfg, nil)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := NewDialer(cfg, nil).Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	kc, ok := conn.(*KCPConn)
	if !ok {
		_ = conn.Close()
		t.Fatalf("expected *KCPConn, got %T", conn)
	}
	if kc.autoTuneStop == nil || kc.autoTuneDone == nil {
		_ = conn.Close()
		t.Fatal("auto-tune channels were not initialized")
	}

	if err := kc.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case <-kc.autoTuneDone:
	case <-time.After(2 * time.Second):
		t.Fatal("auto-tune loop did not stop after Close")
	}
}

func TestKCPConnCloseIsIdempotentForAutoTuneStop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AutoTuneFEC = true

	ln, err := Listen("127.0.0.1:0", cfg, nil)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := NewDialer(cfg, nil).Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	kc, ok := conn.(*KCPConn)
	if !ok {
		_ = conn.Close()
		t.Fatalf("expected *KCPConn, got %T", conn)
	}

	_ = kc.Close()
	_ = kc.Close()
}
