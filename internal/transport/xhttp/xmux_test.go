package xhttp

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stealthlink/internal/transport"
)

type mockSession struct {
	transport.Session
	id       int
	closed   atomic.Int32
	streams  atomic.Int32
}

func (s *mockSession) Close() error {
	s.closed.Store(1)
	return nil
}

func (s *mockSession) OpenStream() (net.Conn, error) {
	s.streams.Add(1)
	return nil, nil // Return nil, nil for simplicity in tests
}

func (s *mockSession) IsClosed() bool {
	return s.closed.Load() == 1
}

type mockDialer struct {
	conns atomic.Int32
	mu    sync.Mutex
}

func (d *mockDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	id := int(d.conns.Add(1))
	return &mockSession{id: id}, nil
}

func TestXMuxLifecycle_ReuseLimit(t *testing.T) {
	cfg := XMuxConfig{
		Enabled:        true,
		MaxConnections: 1,
		CMaxReuseTimes: 2,
	}
	dialer := &mockDialer{}
	pool := NewXMuxPool(cfg, dialer)
	defer pool.Close()

	// 1st use
	sess1, err := pool.Get(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	ps1 := sess1.(*pooledSession)
	if ps1.pc.reuseCount != 1 {
		t.Errorf("expected reuseCount 1, got %d", ps1.pc.reuseCount)
	}
	sess1.Close()

	// 2nd use
	sess2, err := pool.Get(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	ps2 := sess2.(*pooledSession)
	if ps2.pc.reuseCount != 2 {
		t.Errorf("expected reuseCount 2, got %d", ps2.pc.reuseCount)
	}
	if !ps2.pc.shouldRetire(pool.config) {
		t.Error("should be marked for retirement")
	}
	sess2.Close()

	// 3rd use - should trigger rotation (mark as draining and dial new)
	sess3, err := pool.Get(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	ps3 := sess3.(*pooledSession)
	if ps3.pc.id == ps2.pc.id {
		t.Error("should have rotated to a new connection")
	}
	if ps3.pc.reuseCount != 1 {
		t.Errorf("expected new connection reuseCount 1, got %d", ps3.pc.reuseCount)
	}
	
	// Check that previous connection is draining
	pool.mu.RLock()
	foundDraining := false
	for _, pc := range pool.conns {
		if pc.id == ps2.pc.id && pc.isDraining() {
			foundDraining = true
			break
		}
	}
	pool.mu.RUnlock()
	if !foundDraining {
		t.Error("previous connection should be in pool and draining")
	}
}

func TestXMuxLifecycle_RequestLimit(t *testing.T) {
	cfg := XMuxConfig{
		Enabled:          true,
		MaxConnections:   1,
		HMaxRequestTimes: 3,
	}
	dialer := &mockDialer{}
	pool := NewXMuxPool(cfg, dialer)
	defer pool.Close()

	sess, err := pool.Get(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	
	// Open 3 streams
	for i := 0; i < 3; i++ {
		sess.OpenStream()
	}
	
	ps := sess.(*pooledSession)
	if ps.pc.requestCount != 3 {
		t.Errorf("expected requestCount 3, got %d", ps.pc.requestCount)
	}
	if !ps.pc.shouldRetire(pool.config) {
		t.Error("should be marked for retirement")
	}
	sess.Close()

	// Next Get should rotate
	sess2, err := pool.Get(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	ps2 := sess2.(*pooledSession)
	if ps2.pc.id == ps.pc.id {
		t.Error("should have rotated")
	}
}

func TestXMuxLifecycle_AgeLimit(t *testing.T) {
	cfg := XMuxConfig{
		Enabled:          true,
		MaxConnections:   1,
		HMaxReusableSecs: 1, // 1 second
	}
	dialer := &mockDialer{}
	pool := NewXMuxPool(cfg, dialer)
	defer pool.Close()

	sess, err := pool.Get(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	ps := sess.(*pooledSession)
	sess.Close()

	time.Sleep(1100 * time.Millisecond)

	sess2, err := pool.Get(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if sess2.(*pooledSession).pc.id == ps.pc.id {
		t.Error("should have rotated due to age")
	}
}

func TestXMuxLifecycle_DrainTimeout(t *testing.T) {
	cfg := XMuxConfig{
		Enabled:        true,
		MaxConnections: 1,
		CMaxReuseTimes: 1,
		DrainTimeout:   200 * time.Millisecond,
	}
	dialer := &mockDialer{}
	pool := NewXMuxPool(cfg, dialer)
	defer pool.Close()

	sess, err := pool.Get(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	
	// sess is now inUse=1, but it should retire after Close
	ps := sess.(*pooledSession)
	pc := ps.pc
	sess.Close()
	
	// Next Get will rotate it.
	sess2, err := pool.Get(context.Background(), "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	sess2.Close()
	
	if !pc.isDraining() {
		t.Fatal("should be draining")
	}
	
	// Wait for drain timeout
	time.Sleep(300 * time.Millisecond)
	
	pool.doScavenge()
	
	pool.mu.RLock()
	found := false
	for _, pcc := range pool.conns {
		if pcc.id == pc.id {
			found = true
		}
	}
	pool.mu.RUnlock()
	
	if found {
		t.Error("draining connection should have been scavenged after timeout")
	}
	
	if pc.session.(*mockSession).IsClosed() == false {
		t.Error("draining connection should have been closed")
	}
}

func TestXMuxMode_RoundRobin(t *testing.T) {
	cfg := XMuxConfig{
		Enabled:        true,
		MaxConnections: 2,
		Mode:           XMuxModeRoundRobin,
	}
	dialer := &mockDialer{}
	pool := NewXMuxPool(cfg, dialer)
	defer pool.Close()

	s1, _ := pool.Get(context.Background(), "127.0.0.1:443")
	s2, _ := pool.Get(context.Background(), "127.0.0.1:443")
	s1.Close()
	s2.Close()

	// Should pick s1 (id 1)
	s3, _ := pool.Get(context.Background(), "127.0.0.1:443")
	if s3.(*pooledSession).pc.id != 1 {
		t.Errorf("expected id 1, got %d", s3.(*pooledSession).pc.id)
	}
	s3.Close()

	// Should pick s2 (id 2)
	s4, _ := pool.Get(context.Background(), "127.0.0.1:443")
	if s4.(*pooledSession).pc.id != 2 {
		t.Errorf("expected id 2, got %d", s4.(*pooledSession).pc.id)
	}
	s4.Close()
}
