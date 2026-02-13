package carrier

import (
	"testing"
)

// MockCarrier is a mock implementation for testing
type MockCarrier struct {
	BaseCarrier
}

func NewMockCarrier(name string, caps Capability) *MockCarrier {
	return &MockCarrier{
		BaseCarrier: NewBaseCarrier(name, caps),
	}
}

func (m *MockCarrier) CreateDialer(config map[string]interface{}) (Dialer, error) {
	return nil, nil
}

func (m *MockCarrier) CreateListener(addr string, config map[string]interface{}) (Listener, error) {
	return nil, nil
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()

	if r == nil {
		t.Fatal("expected non-nil registry")
	}

	if len(r.List()) != 0 {
		t.Error("expected empty registry")
	}
}

func TestRegistryRegister(t *testing.T) {
	r := NewRegistry()
	c := NewMockCarrier("test", CapabilityReliable|CapabilityStream)

	err := r.Register(c)
	if err != nil {
		t.Errorf("failed to register: %v", err)
	}

	// Duplicate registration should fail
	err = r.Register(c)
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
}

func TestRegistryGet(t *testing.T) {
	r := NewRegistry()
	c := NewMockCarrier("test", CapabilityReliable)

	r.Register(c)

	// Get existing
	got, ok := r.Get("test")
	if !ok {
		t.Error("expected to find registered carrier")
	}
	if got.Name() != "test" {
		t.Errorf("expected name 'test', got '%s'", got.Name())
	}

	// Get non-existing
	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("expected not to find unregistered carrier")
	}
}

func TestRegistryUnregister(t *testing.T) {
	r := NewRegistry()
	c := NewMockCarrier("test", CapabilityReliable)

	r.Register(c)

	// Unregister
	r.Unregister("test")

	_, ok := r.Get("test")
	if ok {
		t.Error("expected carrier to be unregistered")
	}

	// Unregister non-existing should not panic
	r.Unregister("nonexistent")
}

func TestRegistryList(t *testing.T) {
	r := NewRegistry()

	c1 := NewMockCarrier("carrier1", CapabilityReliable)
	c2 := NewMockCarrier("carrier2", CapabilityDatagram)
	c3 := NewMockCarrier("carrier3", CapabilityStream)

	r.Register(c1)
	r.Register(c2)
	r.Register(c3)

	list := r.List()
	if len(list) != 3 {
		t.Errorf("expected 3 carriers, got %d", len(list))
	}

	// Check all carriers are in the list
	names := make(map[string]bool)
	for _, name := range list {
		names[name] = true
	}

	if !names["carrier1"] || !names["carrier2"] || !names["carrier3"] {
		t.Error("expected all carriers in list")
	}
}

func TestRegistryFindByCapability(t *testing.T) {
	r := NewRegistry()

	c1 := NewMockCarrier("reliable", CapabilityReliable|CapabilityStream)
	c2 := NewMockCarrier("datagram", CapabilityDatagram)
	c3 := NewMockCarrier("both", CapabilityReliable|CapabilityDatagram|CapabilityStream)

	r.Register(c1)
	r.Register(c2)
	r.Register(c3)

	// Find reliable carriers
	reliable := r.FindByCapability(CapabilityReliable)
	if len(reliable) != 2 {
		t.Errorf("expected 2 reliable carriers, got %d", len(reliable))
	}

	// Find datagram carriers
	datagram := r.FindByCapability(CapabilityDatagram)
	if len(datagram) != 2 {
		t.Errorf("expected 2 datagram carriers, got %d", len(datagram))
	}

	// Find carriers with both reliable and stream
	both := r.FindByCapability(CapabilityReliable, CapabilityStream)
	if len(both) != 2 {
		t.Errorf("expected 2 carriers with reliable+stream, got %d", len(both))
	}

	// Find with no capabilities (should return all)
	all := r.FindByCapability()
	if len(all) != 3 {
		t.Errorf("expected all 3 carriers, got %d", len(all))
	}

	// Find non-existent capability combination
	none := r.FindByCapability(CapabilityMultipath, CapabilityZeroRTT)
	if len(none) != 0 {
		t.Errorf("expected 0 carriers, got %d", len(none))
	}
}

func TestRegistryFindBest(t *testing.T) {
	r := NewRegistry()

	// Carrier with reliable only
	c1 := NewMockCarrier("basic", CapabilityReliable)

	// Carrier with reliable + congestion control
	c2 := NewMockCarrier("better", CapabilityReliable|CapabilityCongestionControl)

	// Carrier with all features
	c3 := NewMockCarrier("best", CapabilityReliable|CapabilityCongestionControl|CapabilityZeroRTT|CapabilityFlowControl)

	r.Register(c1)
	r.Register(c2)
	r.Register(c3)

	// Find best with all requirements
	best, err := r.FindBest(true, true, true)
	if err != nil {
		t.Errorf("failed to find best: %v", err)
	}
	if best.Name() != "best" {
		t.Errorf("expected 'best', got '%s'", best.Name())
	}

	// Find without 0-RTT preference
	noRTT, err := r.FindBest(true, true, false)
	if err != nil {
		t.Errorf("failed to find: %v", err)
	}
	// Should still prefer better carriers
	if noRTT.Name() != "better" && noRTT.Name() != "best" {
		t.Errorf("expected 'better' or 'best', got '%s'", noRTT.Name())
	}

	// Find with no congestion control requirement
	noCC, err := r.FindBest(true, false, false)
	if err != nil {
		t.Errorf("failed to find: %v", err)
	}
	// Should return any reliable carrier
	if !noCC.Capabilities().Has(CapabilityReliable) {
		t.Error("expected reliable carrier")
	}
}

func TestRegistryFindBestNoMatch(t *testing.T) {
	r := NewRegistry()

	c := NewMockCarrier("datagram", CapabilityDatagram)
	r.Register(c)

	// Try to find reliable carrier when only datagram exists
	_, err := r.FindBest(true, false, false)
	if err == nil {
		t.Error("expected error when no matching carrier found")
	}
}

func TestRegistryGetInfo(t *testing.T) {
	r := NewRegistry()
	c := NewMockCarrier("test", CapabilityReliable|CapabilityStream)
	c.SetInfo(Info{
		Name:         "test",
		Capabilities: CapabilityReliable | CapabilityStream,
		DefaultPort:  8080,
		MTU:          1400,
	})

	r.Register(c)

	info, err := r.GetInfo("test")
	if err != nil {
		t.Errorf("failed to get info: %v", err)
	}

	if info.DefaultPort != 8080 {
		t.Errorf("expected default port 8080, got %d", info.DefaultPort)
	}

	if info.MTU != 1400 {
		t.Errorf("expected MTU 1400, got %d", info.MTU)
	}

	// Non-existent carrier
	_, err = r.GetInfo("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent carrier")
	}
}

func TestRegistryCompareCapabilities(t *testing.T) {
	r := NewRegistry()

	c1 := NewMockCarrier("carrier1", CapabilityReliable|CapabilityStream|CapabilityCongestionControl)
	c2 := NewMockCarrier("carrier2", CapabilityReliable|CapabilityDatagram|CapabilityZeroRTT)

	r.Register(c1)
	r.Register(c2)

	only1, only2, both, err := r.CompareCapabilities("carrier1", "carrier2")
	if err != nil {
		t.Errorf("failed to compare: %v", err)
	}

	// Check that both have reliable
	hasReliable := false
	for _, cap := range both {
		if cap == CapabilityReliable {
			hasReliable = true
			break
		}
	}
	if !hasReliable {
		t.Error("expected both to have Reliable capability")
	}

	// Check only1 has Stream and CongestionControl
	hasStream := false
	hasCC := false
	for _, cap := range only1 {
		if cap == CapabilityStream {
			hasStream = true
		}
		if cap == CapabilityCongestionControl {
			hasCC = true
		}
	}
	if !hasStream {
		t.Error("expected only1 to have Stream capability")
	}
	if !hasCC {
		t.Error("expected only1 to have CongestionControl capability")
	}

	// Check only2 has Datagram and ZeroRTT
	hasDatagram := false
	hasZeroRTT := false
	for _, cap := range only2 {
		if cap == CapabilityDatagram {
			hasDatagram = true
		}
		if cap == CapabilityZeroRTT {
			hasZeroRTT = true
		}
	}
	if !hasDatagram {
		t.Error("expected only2 to have Datagram capability")
	}
	if !hasZeroRTT {
		t.Error("expected only2 to have ZeroRTT capability")
	}

	// Non-existent carrier
	_, _, _, err = r.CompareCapabilities("nonexistent", "carrier2")
	if err == nil {
		t.Error("expected error for non-existent carrier")
	}
}

func TestGlobalRegistry(t *testing.T) {
	// Test global functions
	c := NewMockCarrier("global-test", CapabilityReliable)

	// Register
	err := Register(c)
	if err != nil {
		t.Errorf("failed to register globally: %v", err)
	}

	// Get
	got, ok := Get("global-test")
	if !ok {
		t.Error("expected to find globally registered carrier")
	}
	if got.Name() != "global-test" {
		t.Errorf("expected 'global-test', got '%s'", got.Name())
	}

	// List
	list := List()
	found := false
	for _, name := range list {
		if name == "global-test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected global-test in global list")
	}

	// FindByCapability
	reliable := FindByCapability(CapabilityReliable)
	found = false
	for _, name := range reliable {
		if name == "global-test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected global-test in reliable carriers")
	}

	// Cleanup
	defaultRegistry.Unregister("global-test")
}

func TestRemoveString(t *testing.T) {
	tests := []struct {
		slice    []string
		s        string
		expected []string
	}{
		{[]string{"a", "b", "c"}, "b", []string{"a", "c"}},
		{[]string{"a", "b", "c"}, "a", []string{"b", "c"}},
		{[]string{"a", "b", "c"}, "c", []string{"a", "b"}},
		{[]string{"a", "b", "c"}, "d", []string{"a", "b", "c"}},
		{[]string{}, "a", []string{}},
		{[]string{"a"}, "a", []string{}},
	}

	for _, tt := range tests {
		result := removeString(tt.slice, tt.s)
		if len(result) != len(tt.expected) {
			t.Errorf("removeString(%v, %s) = %v, want %v", tt.slice, tt.s, result, tt.expected)
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("removeString(%v, %s) = %v, want %v", tt.slice, tt.s, result, tt.expected)
				break
			}
		}
	}
}

func TestCapabilityIndexing(t *testing.T) {
	r := NewRegistry()

	// Register carriers with various capabilities
	c1 := NewMockCarrier("all", CapabilityReliable|CapabilityOrdered|CapabilityStream|CapabilityCongestionControl)
	c2 := NewMockCarrier("minimal", CapabilityDatagram)

	r.Register(c1)
	r.Register(c2)

	// Test that carriers are indexed correctly
	reliable := r.FindByCapability(CapabilityReliable)
	if len(reliable) != 1 || reliable[0] != "all" {
		t.Error("expected only 'all' to have Reliable")
	}

	datagram := r.FindByCapability(CapabilityDatagram)
	if len(datagram) != 1 || datagram[0] != "minimal" {
		t.Error("expected only 'minimal' to have Datagram")
	}

	// Unregister and verify index is updated
	r.Unregister("all")

	reliable = r.FindByCapability(CapabilityReliable)
	if len(reliable) != 0 {
		t.Error("expected no reliable carriers after unregister")
	}
}
