package reverse

import (
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func TestRegistrationMessageRoundTripParse(t *testing.T) {
	cfg := &Config{}
	d := NewDialer(cfg, nil, smux.DefaultConfig(), "guard", "agent-1")
	msg := d.buildRegistrationMessage("conn-123")
	if len(msg) < 32 {
		t.Fatalf("expected message length to be reasonable, got %d", len(msg))
	}

	// Listener parse expects totalLen = msgLen + 8, but parseRegistration itself
	// just needs the payload structure.
	l := &Listener{}
	agentID, connID, err := l.parseRegistration(msg)
	if err != nil {
		t.Fatalf("parseRegistration: %v", err)
	}
	if agentID != "agent-1" {
		t.Fatalf("agent id mismatch: got %q", agentID)
	}
	if connID != "conn-123" {
		t.Fatalf("conn id mismatch: got %q", connID)
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	c := &Config{}
	c.ApplyDefaults()
	if c.RetryInterval <= 0 || c.KeepAliveInterval <= 0 || c.MaxConnections <= 0 {
		t.Fatalf("expected defaults to be applied")
	}
	if c.RegistrationPath == "" {
		t.Fatalf("expected registration path default")
	}
	// sanity: should be stable over time
	t0 := c.RetryInterval
	time.Sleep(1 * time.Millisecond)
	c.ApplyDefaults()
	if c.RetryInterval != t0 {
		t.Fatalf("expected ApplyDefaults to be idempotent")
	}
}
