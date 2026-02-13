// Package carrier provides the carrier abstraction for transport layer.
package carrier

import (
	"fmt"
	"sync"
)

// Registry manages carrier implementations and provides capability discovery
type Registry struct {
	carriers map[string]Carrier
	byCap    map[Capability][]string // capability -> carrier names
	mu       sync.RWMutex
}

// NewRegistry creates a new carrier registry
func NewRegistry() *Registry {
	return &Registry{
		carriers: make(map[string]Carrier),
		byCap:    make(map[Capability][]string),
	}
}

// Register registers a carrier implementation
func (r *Registry) Register(c Carrier) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := c.Name()
	if _, exists := r.carriers[name]; exists {
		return fmt.Errorf("carrier %s already registered", name)
	}

	r.carriers[name] = c

	// Index by capability
	caps := c.Capabilities()
	for i := uint64(0); i < 64; i++ {
		cap := Capability(1 << i)
		if caps.Has(cap) {
			r.byCap[cap] = append(r.byCap[cap], name)
		}
	}

	return nil
}

// Unregister removes a carrier from the registry
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	c, ok := r.carriers[name]
	if !ok {
		return
	}

	delete(r.carriers, name)

	// Remove from capability index
	caps := c.Capabilities()
	for i := uint64(0); i < 64; i++ {
		cap := Capability(1 << i)
		if caps.Has(cap) {
			r.byCap[cap] = removeString(r.byCap[cap], name)
		}
	}
}

// Get retrieves a carrier by name
func (r *Registry) Get(name string) (Carrier, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.carriers[name]
	return c, ok
}

// List returns all registered carrier names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.carriers))
	for name := range r.carriers {
		names = append(names, name)
	}
	return names
}

// FindByCapability returns carriers that support all the given capabilities
func (r *Registry) FindByCapability(caps ...Capability) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(caps) == 0 {
		return r.List()
	}

	// Start with carriers matching the first capability
	required := caps[0]
	candidates := make(map[string]bool)
	for _, name := range r.byCap[required] {
		candidates[name] = true
	}

	// Intersect with remaining capabilities
	for _, cap := range caps[1:] {
		valid := make(map[string]bool)
		for _, name := range r.byCap[cap] {
			if candidates[name] {
				valid[name] = true
			}
		}
		candidates = valid
		if len(candidates) == 0 {
			break
		}
	}

	result := make([]string, 0, len(candidates))
	for name := range candidates {
		result = append(result, name)
	}
	return result
}

// FindBest returns the best carrier for given requirements
// Priority: reliability > congestion control > 0-RTT
func (r *Registry) FindBest(requireReliable, requireCongestionControl, preferZeroRTT bool) (Carrier, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var requiredCaps Capability
	if requireReliable {
		requiredCaps |= CapabilityReliable
	}
	if requireCongestionControl {
		requiredCaps |= CapabilityCongestionControl
	}
	if preferZeroRTT {
		requiredCaps |= CapabilityZeroRTT
	}

	var best Carrier
	var bestScore int

	for _, c := range r.carriers {
		caps := c.Capabilities()

		// Check required capabilities
		if requireReliable && !caps.Has(CapabilityReliable) {
			continue
		}
		if requireCongestionControl && !caps.Has(CapabilityCongestionControl) {
			continue
		}

		// Score this carrier
		score := 0
		if caps.Has(CapabilityReliable) {
			score += 10
		}
		if caps.Has(CapabilityCongestionControl) {
			score += 5
		}
		if preferZeroRTT && caps.Has(CapabilityZeroRTT) {
			score += 3
		}
		if caps.Has(CapabilityFlowControl) {
			score += 2
		}
		if caps.Has(CapabilityMultipath) {
			score += 1
		}

		if score > bestScore {
			bestScore = score
			best = c
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no carrier found matching requirements")
	}

	return best, nil
}

// GetInfo returns information about a carrier
func (r *Registry) GetInfo(name string) (Info, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	c, ok := r.carriers[name]
	if !ok {
		return Info{}, fmt.Errorf("carrier %s not found", name)
	}

	return c.Info(), nil
}

// CompareCapabilities returns the difference between two carriers
func (r *Registry) CompareCapabilities(carrier1, carrier2 string) (only1, only2, both []Capability, err error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	c1, ok := r.carriers[carrier1]
	if !ok {
		return nil, nil, nil, fmt.Errorf("carrier %s not found", carrier1)
	}
	c2, ok := r.carriers[carrier2]
	if !ok {
		return nil, nil, nil, fmt.Errorf("carrier %s not found", carrier2)
	}

	caps1 := c1.Capabilities()
	caps2 := c2.Capabilities()

	for i := uint64(0); i < 64; i++ {
		cap := Capability(1 << i)
		has1 := caps1.Has(cap)
		has2 := caps2.Has(cap)

		if has1 && has2 {
			both = append(both, cap)
		} else if has1 {
			only1 = append(only1, cap)
		} else if has2 {
			only2 = append(only2, cap)
		}
	}

	return only1, only2, both, nil
}

// Global registry instance
var defaultRegistry = NewRegistry()

// Register registers a carrier in the default registry
func Register(c Carrier) error {
	return defaultRegistry.Register(c)
}

// Get retrieves a carrier from the default registry
func Get(name string) (Carrier, bool) {
	return defaultRegistry.Get(name)
}

// List returns all carriers from the default registry
func List() []string {
	return defaultRegistry.List()
}

// FindByCapability finds carriers by capability in the default registry
func FindByCapability(caps ...Capability) []string {
	return defaultRegistry.FindByCapability(caps...)
}

// FindBest finds the best carrier in the default registry
func FindBest(requireReliable, requireCongestionControl, preferZeroRTT bool) (Carrier, error) {
	return defaultRegistry.FindBest(requireReliable, requireCongestionControl, preferZeroRTT)
}

// removeString removes a string from a slice
func removeString(slice []string, s string) []string {
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}
