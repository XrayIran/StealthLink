package xhttp

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestPropertyXMuxLifecycle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		maxReuse := rapid.IntRange(1, 10).Draw(t, "max_reuse")
		maxReqs := rapid.IntRange(1, 10).Draw(t, "max_reqs")
		maxAgeSecs := rapid.IntRange(1, 5).Draw(t, "max_age_secs")

		cfg := XMuxConfig{
			Enabled:          true,
			MaxConnections:   1,
			CMaxReuseTimes:   maxReuse,
			HMaxRequestTimes: maxReqs,
			HMaxReusableSecs: maxAgeSecs,
			DrainTimeout:     10 * time.Second,
		}

		dialer := &mockDialer{}
		pool := NewXMuxPool(cfg, dialer)
		defer pool.Close()

		// Property 5 & 6: Limits trigger rotation and draining exclusion
		for i := 0; i < maxReuse+1; i++ {
			sess, err := pool.Get(context.Background(), "127.0.0.1:443")
			if err != nil {
				t.Fatalf("Get failed: %v", err)
			}
			
			ps := sess.(*pooledSession)
			pc := ps.pc

			// If we are at the reuse limit, it should be marked for retirement
			reachedReuse := int(atomic.LoadUint64(&pc.reuseCount)) >= maxReuse
			
			// Simulate requests
			numReqs := rapid.IntRange(0, maxReqs).Draw(t, "num_reqs")
			for j := 0; j < numReqs; j++ {
				_, _ = sess.OpenStream()
			}
			reachedReqs := int(atomic.LoadUint64(&pc.requestCount)) >= maxReqs

			sess.Close()

			if reachedReuse || reachedReqs {
				// The connection MUST be marked draining (either immediately or on next Get/Scavenge)
				// In our implementation, markDraining happens in findIdle or selectByMode or scavenge.
				
				// Let's force a Get and see if it rotates
				sessNext, err := pool.Get(context.Background(), "127.0.0.1:443")
				if err != nil {
					t.Fatalf("Get next failed: %v", err)
				}
				psNext := sessNext.(*pooledSession)
				if psNext.pc.id == pc.id {
					// It didn't rotate. Is it because it didn't reach limits yet?
					// Wait, we checked reuseCount before sending requests.
					// Let's re-check retirement after Close.
					if pc.shouldRetire(pool.config) {
						t.Errorf("Connection %d should have retired but was selected again", pc.id)
					}
				}
				sessNext.Close()
			}
		}
	})
}

func TestPropertyXMuxDrainingExclusion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := XMuxConfig{
			Enabled:        true,
			MaxConnections: 2,
		}
		dialer := &mockDialer{}
		pool := NewXMuxPool(cfg, dialer)
		defer pool.Close()

		s1, _ := pool.Get(context.Background(), "127.0.0.1:443")
		ps1 := s1.(*pooledSession)
		ps1.pc.markDraining()
		s1.Close()

		// Property 6: Draining connection MUST NOT be selected
		for i := 0; i < 10; i++ {
			s, err := pool.Get(context.Background(), "127.0.0.1:443")
			if err != nil {
				t.Fatalf("Get failed: %v", err)
			}
			if s.(*pooledSession).pc.id == ps1.pc.id {
				t.Errorf("Draining connection %d selected", ps1.pc.id)
			}
			s.Close()
		}
	})
}
