package icmptun

import (
	"container/list"
	"sync"
	"time"
)

// LRUSessionMap provides an LRU cache for ICMP sessions with bounded memory
type LRUSessionMap struct {
	capacity int
	items    map[string]*list.Element
	order    *list.List
	mu       sync.RWMutex
}

type lruEntry struct {
	key     string
	value   interface{}
	touched time.Time
}

// NewLRUSessionMap creates a new LRU session map
func NewLRUSessionMap(capacity int) *LRUSessionMap {
	if capacity <= 0 {
		capacity = 1000
	}
	return &LRUSessionMap{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		order:    list.New(),
	}
}

// Get retrieves a value and moves it to front (most recently used)
func (c *LRUSessionMap) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		entry := elem.Value.(*lruEntry)
		entry.touched = time.Now()
		return entry.value, true
	}
	return nil, false
}

// Set adds or updates a value
func (c *LRUSessionMap) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		// Update existing
		c.order.MoveToFront(elem)
		entry := elem.Value.(*lruEntry)
		entry.value = value
		entry.touched = time.Now()
		return
	}

	// Add new
	entry := &lruEntry{key: key, value: value, touched: time.Now()}
	elem := c.order.PushFront(entry)
	c.items[key] = elem

	// Evict oldest if over capacity
	if c.order.Len() > c.capacity {
		c.evictOldest()
	}
}

// Delete removes a key
func (c *LRUSessionMap) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.Remove(elem)
		delete(c.items, key)
	}
}

// evictOldest removes the least recently used entry
func (c *LRUSessionMap) evictOldest() {
	elem := c.order.Back()
	if elem == nil {
		return
	}
	entry := elem.Value.(*lruEntry)
	delete(c.items, entry.key)
	c.order.Remove(elem)

	// Call eviction callback if the value supports it
	if evictable, ok := entry.value.(Evictable); ok {
		evictable.OnEvict()
	}
}

// Range iterates over all entries, calling fn for each. If fn returns false, iteration stops.
func (c *LRUSessionMap) Range(fn func(key string, value interface{}) bool) {
	c.mu.RLock()
	// Collect entries under read lock to avoid holding lock during callback
	entries := make([]lruEntry, 0, len(c.items))
	for e := c.order.Front(); e != nil; e = e.Next() {
		entries = append(entries, *e.Value.(*lruEntry))
	}
	c.mu.RUnlock()

	for _, entry := range entries {
		if !fn(entry.key, entry.value) {
			return
		}
	}
}

// Len returns the number of items
func (c *LRUSessionMap) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.order.Len()
}

// Capacity returns the capacity
func (c *LRUSessionMap) Capacity() int {
	return c.capacity
}

// Evictable is an interface for values that need cleanup on eviction
type Evictable interface {
	OnEvict()
}

// FairScheduler implements round-robin scheduling for fair packet processing
type FairScheduler struct {
	sessions   []SessionHandle
	current    int
	mu         sync.RWMutex
	onProcess  func(SessionHandle) bool
}

// SessionHandle represents a schedulable session
type SessionHandle interface {
	HasData() bool
	Process() error
	ID() string
	Weight() int
}

// NewFairScheduler creates a new fair scheduler
func NewFairScheduler(onProcess func(SessionHandle) bool) *FairScheduler {
	return &FairScheduler{
		sessions:  make([]SessionHandle, 0),
		onProcess: onProcess,
	}
}

// AddSession adds a session to the scheduler
func (s *FairScheduler) AddSession(session SessionHandle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = append(s.sessions, session)
}

// RemoveSession removes a session
func (s *FairScheduler) RemoveSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, sess := range s.sessions {
		if sess.ID() == id {
			// Remove by swapping with last
			s.sessions[i] = s.sessions[len(s.sessions)-1]
			s.sessions = s.sessions[:len(s.sessions)-1]
			if s.current >= i && s.current > 0 {
				s.current--
			}
			return
		}
	}
}

// Schedule runs one round of scheduling
func (s *FairScheduler) Schedule() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.sessions) == 0 {
		return 0
	}

	processed := 0
	sessionsCount := len(s.sessions)

	// Try to process from each session once per round
	for i := 0; i < sessionsCount; i++ {
		s.current = (s.current + 1) % sessionsCount
		session := s.sessions[s.current]

		if !session.HasData() {
			continue
		}

		// Process up to Weight packets from this session
		weight := session.Weight()
		if weight <= 0 {
			weight = 1
		}

		for j := 0; j < weight; j++ {
			if !session.HasData() {
				break
			}
			if s.onProcess != nil && !s.onProcess(session) {
				continue
			}
			if err := session.Process(); err != nil {
				continue
			}
			processed++
		}
	}

	return processed
}

// SessionCount returns the number of sessions
func (s *FairScheduler) SessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// MTUAdaptor handles per-session MTU adaptation
type MTUAdaptor struct {
	baseMTU    int
	minMTU     int
	maxMTU     int
	currentMTU int
	mu         sync.RWMutex
}

// NewMTUAdaptor creates a new MTU adaptor
func NewMTUAdaptor(baseMTU int) *MTUAdaptor {
	if baseMTU <= 0 {
		baseMTU = 1400
	}
	return &MTUAdaptor{
		baseMTU:    baseMTU,
		minMTU:     576,  // Minimum viable MTU
		maxMTU:     9000, // Jumbo frame max
		currentMTU: baseMTU,
	}
}

// GetMTU returns the current MTU
func (m *MTUAdaptor) GetMTU() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentMTU
}

// OnLoss should be called when packet loss is detected
func (m *MTUAdaptor) OnLoss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Reduce MTU by 10%, but not below min
	m.currentMTU = m.currentMTU * 9 / 10
	if m.currentMTU < m.minMTU {
		m.currentMTU = m.minMTU
	}
}

// OnSuccess should be called when packets flow successfully
func (m *MTUAdaptor) OnSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Slowly increase MTU back towards base
	newMTU := m.currentMTU * 101 / 100
	if newMTU > m.baseMTU {
		newMTU = m.baseMTU
	}
	if newMTU > m.maxMTU {
		newMTU = m.maxMTU
	}
	m.currentMTU = newMTU
	if m.currentMTU > m.maxMTU {
		m.currentMTU = m.maxMTU
	}
}

// SetBaseMTU updates the base MTU
func (m *MTUAdaptor) SetBaseMTU(mtu int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.baseMTU = mtu
	if m.currentMTU > mtu {
		m.currentMTU = mtu
	}
}

// ReplayWindow64 provides 64-bit replay protection
type ReplayWindow64 struct {
	window  uint64
	baseSeq uint32
	mu      sync.RWMutex
}

// NewReplayWindow64 creates a new 64-bit replay window
func NewReplayWindow64() *ReplayWindow64 {
	return &ReplayWindow64{}
}

// CheckAndAdd checks if a sequence number is new and adds it
func (w *ReplayWindow64) CheckAndAdd(seq uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Update base if this is a newer sequence
	if seq > w.baseSeq {
		diff := seq - w.baseSeq
		if diff >= 64 {
			// Shift completely out of window
			w.window = 0
		} else {
			w.window <<= diff
		}
		w.baseSeq = seq
	}

	// Check if within window
	if seq > w.baseSeq {
		// Future packet, should not happen if we're tracking base correctly
		return true
	}

	diff := w.baseSeq - seq
	if diff >= 64 {
		// Too old
		return false
	}

	bit := uint64(1) << diff
	if w.window&bit != 0 {
		// Already seen
		return false
	}

	w.window |= bit
	return true
}

// ReplayChecker wraps replay protection for a session
type ReplayChecker struct {
	window *ReplayWindow64
	mu     sync.Mutex
}

// NewReplayChecker creates a new replay checker
func NewReplayChecker() *ReplayChecker {
	return &ReplayChecker{
		window: NewReplayWindow64(),
	}
}

// Check checks a sequence number
func (r *ReplayChecker) Check(seq uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.window.CheckAndAdd(seq)
}
