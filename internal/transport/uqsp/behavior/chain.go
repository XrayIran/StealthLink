package behavior

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

type ChainedOverlay struct {
	Overlay
	Priority     int
	EnabledField int32
	Required     bool
}

type DynamicOverlayChain struct {
	mu       sync.RWMutex
	overlays []*ChainedOverlay
	state    map[string]interface{}
}

func NewDynamicOverlayChain() *DynamicOverlayChain {
	return &DynamicOverlayChain{
		overlays: make([]*ChainedOverlay, 0),
		state:    make(map[string]interface{}),
	}
}

func (c *DynamicOverlayChain) Add(overlay Overlay, priority int, required bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	co := &ChainedOverlay{
		Overlay:      overlay,
		Priority:     priority,
		EnabledField: 1,
		Required:     required,
	}
	c.overlays = append(c.overlays, co)
	c.sortOverlaysLocked()
}

func (c *DynamicOverlayChain) Remove(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	filtered := make([]*ChainedOverlay, 0, len(c.overlays))
	for _, o := range c.overlays {
		if o.Name() != name {
			filtered = append(filtered, o)
		}
	}
	c.overlays = filtered
}

func (c *DynamicOverlayChain) Enable(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, o := range c.overlays {
		if o.Name() == name {
			atomic.StoreInt32(&o.EnabledField, 1)
			return nil
		}
	}
	return fmt.Errorf("overlay %q not found", name)
}

func (c *DynamicOverlayChain) Disable(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, o := range c.overlays {
		if o.Name() == name {
			if o.Required {
				return fmt.Errorf("cannot disable required overlay %q", name)
			}
			atomic.StoreInt32(&o.EnabledField, 0)
			return nil
		}
	}
	return fmt.Errorf("overlay %q not found", name)
}

func (c *DynamicOverlayChain) IsEnabled(name string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, o := range c.overlays {
		if o.Name() == name {
			return atomic.LoadInt32(&o.EnabledField) == 1
		}
	}
	return false
}

func (c *DynamicOverlayChain) SetPriority(name string, priority int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, o := range c.overlays {
		if o.Name() == name {
			o.Priority = priority
			c.sortOverlaysLocked()
			return nil
		}
	}
	return fmt.Errorf("overlay %q not found", name)
}

func (c *DynamicOverlayChain) sortOverlaysLocked() {
	n := len(c.overlays)
	for i := 0; i < n-1; i++ {
		for j := i + 1; j < n; j++ {
			if c.overlays[i].Priority > c.overlays[j].Priority {
				c.overlays[i], c.overlays[j] = c.overlays[j], c.overlays[i]
			}
		}
	}
}

func (c *DynamicOverlayChain) Apply(conn net.Conn) (net.Conn, error) {
	return c.ApplyContext(context.Background(), conn)
}

func (c *DynamicOverlayChain) ApplyContext(ctx context.Context, conn net.Conn) (net.Conn, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var err error
	for _, co := range c.overlays {
		if atomic.LoadInt32(&co.EnabledField) != 1 {
			continue
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		conn, err = co.Apply(conn)
		if err != nil {
			if co.Required {
				return nil, fmt.Errorf("required overlay %q failed: %w", co.Name(), err)
			}
			continue
		}
	}

	return conn, nil
}

func (c *DynamicOverlayChain) List() []OverlayInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info := make([]OverlayInfo, len(c.overlays))
	for i, o := range c.overlays {
		info[i] = OverlayInfo{
			Name:     o.Name(),
			Enabled:  atomic.LoadInt32(&o.EnabledField) == 1,
			Priority: o.Priority,
			Required: o.Required,
		}
	}
	return info
}

type OverlayInfo struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"`
	Required bool   `json:"required"`
}

func (c *DynamicOverlayChain) SetState(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state[key] = value
}

func (c *DynamicOverlayChain) GetState(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.state[key]
	return v, ok
}

type OverlayChainBuilder struct {
	chain *DynamicOverlayChain
}

func NewOverlayChainBuilder() *OverlayChainBuilder {
	return &OverlayChainBuilder{
		chain: NewDynamicOverlayChain(),
	}
}

func (b *OverlayChainBuilder) AddPreDial(overlay Overlay, required bool) *OverlayChainBuilder {
	b.chain.Add(overlay, 0, required)
	return b
}

func (b *OverlayChainBuilder) AddContextPreparer(overlay Overlay, required bool) *OverlayChainBuilder {
	b.chain.Add(overlay, 1, required)
	return b
}

func (b *OverlayChainBuilder) AddTransportMutator(overlay Overlay, required bool) *OverlayChainBuilder {
	b.chain.Add(overlay, 2, required)
	return b
}

func (b *OverlayChainBuilder) AddFlowOverlay(overlay Overlay, required bool) *OverlayChainBuilder {
	b.chain.Add(overlay, 3, required)
	return b
}

func (b *OverlayChainBuilder) AddPostProcessor(overlay Overlay, required bool) *OverlayChainBuilder {
	b.chain.Add(overlay, 4, required)
	return b
}

func (b *OverlayChainBuilder) Build() *DynamicOverlayChain {
	return b.chain
}

type ConditionalOverlay struct {
	Base      Overlay
	Condition func(ctx context.Context) bool
	name      string
}

func NewConditionalOverlay(base Overlay, condition func(ctx context.Context) bool) *ConditionalOverlay {
	return &ConditionalOverlay{
		Base:      base,
		Condition: condition,
		name:      base.Name() + ".conditional",
	}
}

func (o *ConditionalOverlay) Name() string {
	return o.name
}

func (o *ConditionalOverlay) Enabled() bool {
	return o.Base.Enabled()
}

func (o *ConditionalOverlay) Apply(conn net.Conn) (net.Conn, error) {
	return o.Base.Apply(conn)
}

func (o *ConditionalOverlay) ApplyIf(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if o.Condition(ctx) {
		return o.Base.Apply(conn)
	}
	return conn, nil
}

type FallbackOverlay struct {
	Primary  Overlay
	Fallback Overlay
	name     string
}

func NewFallbackOverlay(primary, fallback Overlay) *FallbackOverlay {
	return &FallbackOverlay{
		Primary:  primary,
		Fallback: fallback,
		name:     primary.Name() + ".fallback",
	}
}

func (o *FallbackOverlay) Name() string {
	return o.name
}

func (o *FallbackOverlay) Enabled() bool {
	return o.Primary.Enabled() || o.Fallback.Enabled()
}

func (o *FallbackOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if o.Primary.Enabled() {
		result, err := o.Primary.Apply(conn)
		if err == nil {
			return result, nil
		}
	}
	if o.Fallback.Enabled() {
		return o.Fallback.Apply(conn)
	}
	return conn, nil
}

func (c *DynamicOverlayChain) Enabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.overlays) > 0
}

func (c *DynamicOverlayChain) Name() string {
	return "chain"
}

var _ Overlay = (*DynamicOverlayChain)(nil)
var _ Overlay = (*ConditionalOverlay)(nil)
var _ Overlay = (*FallbackOverlay)(nil)
