package uqsp

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"stealthlink/internal/transport/underlay"
	uqspcarrier "stealthlink/internal/transport/uqsp/carrier"
)

type stubCarrier struct{}

func (c *stubCarrier) Network() string { return "stub" }
func (c *stubCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return nil, context.Canceled
}
func (c *stubCarrier) Listen(addr string) (uqspcarrier.Listener, error) {
	return nil, fmt.Errorf("not supported")
}
func (c *stubCarrier) Close() error      { return nil }
func (c *stubCarrier) IsAvailable() bool { return true }

type fakeUnderlay struct {
	n atomic.Int64
}

func (d *fakeUnderlay) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.n.Add(1)
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}
func (d *fakeUnderlay) Type() string { return "fake" }
func (d *fakeUnderlay) Close() error { return nil }

func TestUnifiedProtocol_ReverseInitUsesUnderlayDialer(t *testing.T) {
	u := &fakeUnderlay{}

	p, err := NewUnifiedProtocol(VariantConfig{
		Variant:       VariantXHTTP_TLS,
		Carrier:       &stubCarrier{},
		EnableReverse: true,
		ReverseMode: &ReverseMode{
			Enabled:       true,
			Role:          "dialer",
			ClientAddress: "127.0.0.1:1",
			MaxRetries:    1,
			ReconnectBackoff: 10 * time.Millisecond,
			ReconnectDelay:   10 * time.Millisecond,
		},
		UnderlayDialer: u,
	})
	if err != nil {
		t.Fatalf("NewUnifiedProtocol: %v", err)
	}

	ln, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Accept should observe a connection delivered via ReverseDialer which must use underlay.Dial.
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, aerr := ln.Accept()
		if aerr == nil && c != nil {
			_ = c.Close()
		}
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for reverse accept")
	}

	if u.n.Load() == 0 {
		t.Fatal("expected underlay dialer to be used for reverse-init dials")
	}

	// Ensure type satisfies interface at compile time.
	var _ underlay.Dialer = u
}
