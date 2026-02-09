package behavior

import (
	"net"
	"testing"
	"time"
)

func TestGFWResistTLSOverlayWrapsConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ov := NewGFWResistTLSOverlay()
	conn, err := ov.Apply(a)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	clientHelloLike := make([]byte, 80)
	clientHelloLike[0] = 0x16
	clientHelloLike[5] = 0x01

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		total := 0
		for total < len(clientHelloLike) {
			n, err := b.Read(buf)
			if n > 0 {
				total += n
			}
			if err != nil {
				return
			}
		}
	}()

	if _, err := conn.Write(clientHelloLike); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = conn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for write")
	}
}

func TestGFWResistTCPOverlayChunksWrites(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ov := NewGFWResistTCPOverlay()
	ov.ChunkMin = 8
	ov.ChunkMax = 16
	conn, err := ov.Apply(a)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	payload := make([]byte, 128)
	done := make(chan int, 1)
	go func() {
		buf := make([]byte, 64)
		total := 0
		for total < len(payload) {
			n, err := b.Read(buf)
			if n > 0 {
				total += n
			}
			if err != nil {
				break
			}
		}
		done <- total
	}()

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = conn.Close()
	select {
	case n := <-done:
		if n != len(payload) {
			t.Fatalf("read=%d want=%d", n, len(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for read")
	}
}
