package pool

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"stealthlink/internal/transport"
)

type mockSession struct {
	id int
}

func (m *mockSession) OpenStream() (net.Conn, error)  { return nil, nil }
func (m *mockSession) AcceptStream() (net.Conn, error) { return nil, nil }
func (m *mockSession) Close() error                  { return nil }
func (m *mockSession) LocalAddr() net.Addr           { return nil }
func (m *mockSession) RemoteAddr() net.Addr          { return nil }

type mockDialer struct {
	dialCount atomic.Int64
}

func (m *mockDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	m.dialCount.Add(1)
	return &mockSession{id: int(m.dialCount.Load())}, nil
}

func TestAdaptivePool_InitialSize(t *testing.T) {
	config := PoolConfig{
		MinSize: 5,
		MaxSize: 10,
	}
	dialer := &mockDialer{}
	pool := NewAdaptivePool(config, dialer, "test")
	defer pool.Close()

	if pool.dialer.(*mockDialer).dialCount.Load() != 5 {
		t.Errorf("expected initial size 5, got %d", pool.dialer.(*mockDialer).dialCount.Load())
	}
}

func TestAdaptivePool_ScaleUp(t *testing.T) {
	config := PoolConfig{
		MinSize:      2,
		MaxSize:      10,
		Mode:         PoolModeAggressive,
		CooldownSecs: 1,
	}
	dialer := &mockDialer{}
	pool := NewAdaptivePool(config, dialer, "test")
	defer pool.Close()

	// Use all connections
	ctx := context.Background()
	s1, _ := pool.Get(ctx)
	s2, _ := pool.Get(ctx)

	// Utilization is 1.0 > 0.8
	pool.adjust()

	// Scale up should be 25% of 2 = 1 (rounded up by min step 1)
	// So new size 3.
	time.Sleep(100 * time.Millisecond) // wait for dialNew

	pool.mu.RLock()
	size := len(pool.conns)
	pool.mu.RUnlock()

	if size != 3 {
		t.Errorf("expected size 3 after scale up, got %d", size)
	}

	s1.Close()
	s2.Close()
}

func TestAdaptivePool_ScaleDown(t *testing.T) {
	config := PoolConfig{
		MinSize:      2,
		MaxSize:      10,
		Mode:         PoolModeAggressive,
		CooldownSecs: 0,
		DrainTimeout: 100 * time.Millisecond,
	}
	dialer := &mockDialer{}
	pool := NewAdaptivePool(config, dialer, "test")
	defer pool.Close()

	// Manually add more connections for testing scale down
	for i := 0; i < 4; i++ {
		pool.dialNew(context.Background())
	}

	// Now size is 2 + 4 = 6.
	// Keep one in use so it's not immediately scavenged if marked for drain
	s, _ := pool.Get(context.Background())
	defer s.Close()

	// utilization = 1 / 6 = 0.166 < 0.3.
	pool.adjust()

	// Scale down should be 25% of 6 = 1.5 -> 1.
	// So 1 connection marked for drain.
	
	pool.mu.RLock()
	drainingCount := 0
	for _, c := range pool.conns {
		if c.draining.Load() {
			drainingCount++
		}
	}
	pool.mu.RUnlock()

	if drainingCount != 1 {
		t.Errorf("expected 1 connection draining, got %d", drainingCount)
	}

	// Scavenge
	time.Sleep(200 * time.Millisecond)
	pool.mu.Lock()
	pool.scavenge()
	size := len(pool.conns)
	pool.mu.Unlock()

	if size != 5 {
		t.Errorf("expected size 5 after scavenge, got %d", size)
	}
}

func TestAdaptivePool_Cooldown(t *testing.T) {
	config := PoolConfig{
		MinSize:      2,
		MaxSize:      10,
		CooldownSecs: 60,
	}
	dialer := &mockDialer{}
	pool := NewAdaptivePool(config, dialer, "test")
	defer pool.Close()

	pool.Get(context.Background())
	pool.Get(context.Background())

	pool.adjust() // Should adjust
	firstAdjust := pool.lastAdjust

	pool.adjust() // Should NOT adjust due to cooldown
	if pool.lastAdjust != firstAdjust {
		t.Error("adjustment happened despite cooldown")
	}
}

func TestAdaptivePool_MinMaxSize(t *testing.T) {
	config := PoolConfig{
		MinSize: 2,
		MaxSize: 2,
	}
	dialer := &mockDialer{}
	pool := NewAdaptivePool(config, dialer, "test")
	defer pool.Close()

	pool.Get(context.Background())
	pool.Get(context.Background())

	pool.adjust()
	
	pool.mu.RLock()
	size := len(pool.conns)
	pool.mu.RUnlock()

	if size > 2 {
		t.Errorf("exceeded max size: %d", size)
	}
}
