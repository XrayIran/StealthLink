package behavior

import (
	"context"
	"net"
	"testing"

	"stealthlink/internal/config"
)

func TestDynamicOverlayChainAddRemove(t *testing.T) {
	chain := NewDynamicOverlayChain()

	chain.Add(&DomainFrontOverlay{EnabledField: true}, 1, false)
	chain.Add(&ECHOverlay{EnabledField: true}, 0, false)
	chain.Add(&TLSMirrorOverlay{EnabledField: true}, 2, true)

	overlays := chain.List()
	if len(overlays) != 3 {
		t.Fatalf("expected 3 overlays, got %d", len(overlays))
	}

	if overlays[0].Priority != 0 || overlays[0].Name != "ech" {
		t.Errorf("first overlay should be ech with priority 0, got %s with %d", overlays[0].Name, overlays[0].Priority)
	}
	if overlays[1].Priority != 1 || overlays[1].Name != "domainfront" {
		t.Errorf("second overlay should be domainfront with priority 1, got %s with %d", overlays[1].Name, overlays[1].Priority)
	}
	if overlays[2].Priority != 2 || overlays[2].Name != "tlsmirror" {
		t.Errorf("third overlay should be tlsmirror with priority 2, got %s with %d", overlays[2].Name, overlays[2].Priority)
	}

	chain.Remove("domainfront")
	overlays = chain.List()
	if len(overlays) != 2 {
		t.Fatalf("expected 2 overlays after remove, got %d", len(overlays))
	}
}

func TestDynamicOverlayChainEnableDisable(t *testing.T) {
	chain := NewDynamicOverlayChain()

	chain.Add(&DomainFrontOverlay{EnabledField: true}, 0, false)
	chain.Add(&TLSMirrorOverlay{EnabledField: true}, 1, true)

	if !chain.IsEnabled("domainfront") {
		t.Error("domainfront should be enabled")
	}

	if err := chain.Disable("domainfront"); err != nil {
		t.Fatalf("disable domainfront: %v", err)
	}
	if chain.IsEnabled("domainfront") {
		t.Error("domainfront should be disabled")
	}

	if err := chain.Disable("tlsmirror"); err == nil {
		t.Error("should not be able to disable required overlay")
	}
}

func TestDynamicOverlayChainSetPriority(t *testing.T) {
	chain := NewDynamicOverlayChain()

	chain.Add(&DomainFrontOverlay{EnabledField: true}, 2, false)
	chain.Add(&ECHOverlay{EnabledField: true}, 0, false)
	chain.Add(&TLSMirrorOverlay{EnabledField: true}, 1, false)

	overlays := chain.List()
	if overlays[0].Name != "ech" {
		t.Errorf("first should be ech, got %s", overlays[0].Name)
	}

	if err := chain.SetPriority("domainfront", -1); err != nil {
		t.Fatalf("set priority: %v", err)
	}

	overlays = chain.List()
	if overlays[0].Name != "domainfront" {
		t.Errorf("first should now be domainfront, got %s", overlays[0].Name)
	}
}

func TestDynamicOverlayChainSetPriorityNotFound(t *testing.T) {
	chain := NewDynamicOverlayChain()
	chain.Add(&DomainFrontOverlay{EnabledField: true}, 0, false)

	err := chain.SetPriority("nonexistent", 5)
	if err == nil {
		t.Error("should error for nonexistent overlay")
	}
}

func TestDynamicOverlayChainEnableNotFound(t *testing.T) {
	chain := NewDynamicOverlayChain()

	err := chain.Enable("nonexistent")
	if err == nil {
		t.Error("should error for nonexistent overlay")
	}
}

func TestDynamicOverlayChainDisableNotFound(t *testing.T) {
	chain := NewDynamicOverlayChain()

	err := chain.Disable("nonexistent")
	if err == nil {
		t.Error("should error for nonexistent overlay")
	}
}

func TestDynamicOverlayChainState(t *testing.T) {
	chain := NewDynamicOverlayChain()

	chain.SetState("test_key", "test_value")
	chain.SetState("number", 42)

	val, ok := chain.GetState("test_key")
	if !ok || val != "test_value" {
		t.Errorf("expected 'test_value', got %v, ok=%v", val, ok)
	}

	val, ok = chain.GetState("number")
	if !ok || val != 42 {
		t.Errorf("expected 42, got %v, ok=%v", val, ok)
	}

	_, ok = chain.GetState("nonexistent")
	if ok {
		t.Error("nonexistent key should return ok=false")
	}
}

func TestOverlayChainBuilderFluent(t *testing.T) {
	chain := NewOverlayChainBuilder().
		AddPreDial(&DomainFrontOverlay{EnabledField: true}, false).
		AddContextPreparer(&ECHOverlay{EnabledField: true}, false).
		AddTransportMutator(NewQPPOverlay(config.QPPBehaviorConfig{
			Enabled: true,
			Key:     "builder-test-key-32-bytes!!!",
		}), true).
		AddFlowOverlay(&TLSMirrorOverlay{EnabledField: true}, false).
		AddPostProcessor(&CSTPOverlay{EnabledField: true}, false).
		Build()

	overlays := chain.List()
	if len(overlays) != 5 {
		t.Fatalf("expected 5 overlays, got %d", len(overlays))
	}

	expectedOrder := []struct {
		name     string
		priority int
	}{
		{"domainfront", 0},
		{"ech", 1},
		{"qpp", 2},
		{"tlsmirror", 3},
		{"cstp", 4},
	}

	for i, exp := range expectedOrder {
		if overlays[i].Name != exp.name {
			t.Errorf("overlay %d: expected %s, got %s", i, exp.name, overlays[i].Name)
		}
		if overlays[i].Priority != exp.priority {
			t.Errorf("overlay %d: expected priority %d, got %d", i, exp.priority, overlays[i].Priority)
		}
	}
}

func TestConditionalOverlay(t *testing.T) {
	base := &DomainFrontOverlay{EnabledField: true}

	callCount := 0
	condition := func(ctx context.Context) bool {
		callCount++
		return ctx.Value("allowed") == true
	}

	cond := NewConditionalOverlay(base, condition)

	if cond.Name() != "domainfront.conditional" {
		t.Errorf("expected name 'domainfront.conditional', got %q", cond.Name())
	}

	ctxAllowed := context.WithValue(context.Background(), "allowed", true)
	ctxBlocked := context.WithValue(context.Background(), "allowed", false)

	if !cond.Condition(ctxAllowed) {
		t.Error("condition should be true with allowed=true")
	}
	if cond.Condition(ctxBlocked) {
		t.Error("condition should be false with allowed=false")
	}

	_ = cond.Enabled()
	if callCount != 2 {
		t.Errorf("condition should have been called, count=%d", callCount)
	}
}

func TestFallbackOverlay(t *testing.T) {
	primary := &TLSMirrorOverlay{EnabledField: false}
	fallback := &DomainFrontOverlay{EnabledField: true}

	fb := NewFallbackOverlay(primary, fallback)

	if fb.Name() != "tlsmirror.fallback" {
		t.Errorf("expected name 'tlsmirror.fallback', got %q", fb.Name())
	}

	if !fb.Enabled() {
		t.Error("fallback should report enabled when fallback is enabled")
	}

	bothDisabled := NewFallbackOverlay(
		&TLSMirrorOverlay{EnabledField: false},
		&DomainFrontOverlay{EnabledField: false},
	)
	if bothDisabled.Enabled() {
		t.Error("fallback should report disabled when both are disabled")
	}
}

func TestDynamicOverlayChainApplyContext(t *testing.T) {
	chain := NewDynamicOverlayChain()
	chain.Add(&DomainFrontOverlay{EnabledField: true}, 0, false)
	chain.Add(&ECHOverlay{EnabledField: true}, 1, false)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx := context.Background()
	wrapped, err := chain.ApplyContext(ctx, a)
	if err != nil {
		t.Fatalf("ApplyContext: %v", err)
	}
	if wrapped == nil {
		t.Fatal("wrapped connection should not be nil")
	}
}

func TestDynamicOverlayChainApplyContextCanceled(t *testing.T) {
	chain := NewDynamicOverlayChain()
	chain.Add(&DomainFrontOverlay{EnabledField: true}, 0, false)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := chain.ApplyContext(ctx, a)
	if err == nil {
		t.Error("ApplyContext should fail with canceled context")
	}
}

func TestDynamicOverlayChainEnabled(t *testing.T) {
	chain := NewDynamicOverlayChain()
	if chain.Enabled() {
		t.Error("empty chain should not be enabled")
	}

	chain.Add(&DomainFrontOverlay{EnabledField: true}, 0, false)
	if !chain.Enabled() {
		t.Error("chain with overlays should be enabled")
	}
}

func TestDynamicOverlayChainName(t *testing.T) {
	chain := NewDynamicOverlayChain()
	if chain.Name() != "chain" {
		t.Errorf("expected name 'chain', got %q", chain.Name())
	}
}

func TestDynamicOverlayChainApplySkipsDisabled(t *testing.T) {
	chain := NewDynamicOverlayChain()
	chain.Add(&DomainFrontOverlay{EnabledField: false}, 0, false)
	chain.Add(&ECHOverlay{EnabledField: true}, 1, false)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	wrapped, err := chain.Apply(a)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if wrapped == nil {
		t.Fatal("wrapped should not be nil")
	}
}
