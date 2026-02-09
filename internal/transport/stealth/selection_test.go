package stealth

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
)

// These tests are skipped - legacy stealth transport selection/profiles have been
// removed in favor of UQSP transport which uses QUIC as the unified carrier.

type stubDialer struct {
	err     error
	calls   *int
	session transport.Session
}

func (d *stubDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	if d.calls != nil {
		*d.calls = *d.calls + 1
	}
	if d.err != nil {
		return nil, d.err
	}
	return d.session, nil
}

type stubSession struct{}

func (s *stubSession) OpenStream() (net.Conn, error) {
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func (s *stubSession) AcceptStream() (net.Conn, error) {
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func (s *stubSession) Close() error { return nil }

func (s *stubSession) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
}

func (s *stubSession) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
}

func TestSelectedProfilesOrderAndDedup(t *testing.T) {
	t.Skip("Legacy stealth transport removed - UQSP is the only supported transport")
	_ = config.StealthProfileHTTPSWSS // keep imports
}

func TestFallbackDialerTriesNextCandidate(t *testing.T) {
	t.Skip("Legacy stealth transport removed - UQSP is the only supported transport")
	_ = errors.New("skip")
	_ = context.Background()
	_ = time.Millisecond
	_ = transport.Dialer(nil)
}
