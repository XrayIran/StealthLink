package phantom

import (
	"testing"
)

func TestPoolDeterministic(t *testing.T) {
	cfg := Config{
		Enabled:        true,
		SharedSecret:   "test-secret",
		EpochSeed:      "epoch-1",
		SubnetPrefixV4: "198.51.100.0/24",
		SubnetPrefixV6: "2001:db8::/64",
		PoolSize:       8,
	}
	p1, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	p2, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	for i := 0; i < 8; i++ {
		a := p1.Next()
		b := p2.Next()
		if a == nil || b == nil {
			t.Fatalf("nil ip at %d", i)
		}
		if a.String() != b.String() {
			t.Fatalf("non-deterministic at %d: %s != %s", i, a.String(), b.String())
		}
	}
}

func TestPoolEpochSeedChangesOrdering(t *testing.T) {
	a, err := NewPool(Config{Enabled: true, SharedSecret: "test-secret", EpochSeed: "e1", PoolSize: 8})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	b, err := NewPool(Config{Enabled: true, SharedSecret: "test-secret", EpochSeed: "e2", PoolSize: 8})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	ai := a.Next().String()
	bi := b.Next().String()
	if ai == "" || bi == "" {
		t.Fatal("unexpected empty ip")
	}
	if ai == bi {
		t.Fatalf("expected different ordering across epochs, got same first ip=%q", ai)
	}
}

func TestPoolRotationWraps(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		SharedSecret: "test-secret",
		PoolSize:     3,
	}
	p, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	a := p.Next().String()
	b := p.Next().String()
	c := p.Next().String()
	d := p.Next().String()
	if a == "" || b == "" || c == "" {
		t.Fatal("unexpected empty ip")
	}
	if d != a {
		t.Fatalf("expected rotation to wrap: got %q want %q", d, a)
	}
}
