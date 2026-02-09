package behavior

import (
	"io"
	"net"
	"testing"
	"time"

	"stealthlink/internal/config"
)

func TestCSTPOverlayRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() {
		_ = c1.Close()
		_ = c2.Close()
	})

	ov := NewCSTPOverlay(config.CSTPBehaviorConfig{
		Enabled:     true,
		DPDInterval: 5 * time.Millisecond,
		MTU:         32,
	})

	a, err := ov.Apply(c1)
	if err != nil {
		t.Fatalf("apply client overlay: %v", err)
	}
	b, err := ov.Apply(c2)
	if err != nil {
		t.Fatalf("apply server overlay: %v", err)
	}

	want := []byte("hello-over-cstp")
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(b, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != string(want) {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- nil
	}()

	if _, err := a.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("read/verify: %v", err)
	}
}
