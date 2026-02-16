// Package routing implements rule-based routing engine.
package routing

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport/graph"
)

// Engine is the routing engine that manages routes and applies rules
type Engine struct {
	ruleSet  *RuleSet
	routes   map[string]*Route
	routesMu sync.RWMutex

	// Health tracking
	healthStates map[string]*HealthState
	healthMu     sync.RWMutex

	// Metrics
	requestsTotal   atomic.Uint64
	requestsMatched atomic.Uint64
	requestsBlocked atomic.Uint64

	// DNS cache for domain resolution
	dnsCache   *DNSCache
	dnsCacheMu sync.RWMutex

	// Control
	ctx    context.Context
	cancel context.CancelFunc
}

// Route represents a network route to a destination
type Route struct {
	Name        string
	Transport   string
	Chain       []string
	Weight      int
	HealthCheck *HealthCheck
	Fallback    string

	// Runtime state
	healthy     atomic.Bool
	latency     atomic.Int64 // microseconds
	lastChecked time.Time
}

// HealthCheck configures health checking for a route
type HealthCheck struct {
	Method   string // tcp, http, icmp
	Target   string
	Interval time.Duration
	Timeout  time.Duration
	Rise     int // Successes to mark healthy
	Fall     int // Failures to mark unhealthy
}

// HealthState tracks the health state of a route
type HealthState struct {
	Successes   int
	Failures    int
	LastSuccess time.Time
	LastFailure time.Time
	Status      HealthStatus
}

// HealthStatus represents route health status
type HealthStatus int

const (
	HealthStatusUnknown HealthStatus = iota
	HealthStatusHealthy
	HealthStatusDegraded
	HealthStatusUnhealthy
)

// DNSCache caches DNS resolution results
type DNSCache struct {
	entries map[string]*dnsEntry
	ttl     time.Duration
}

type dnsEntry struct {
	ips       []net.IP
	timestamp time.Time
}

// NewEngine creates a new routing engine
func NewEngine() *Engine {
	ctx, cancel := context.WithCancel(context.Background())

	return &Engine{
		ruleSet:      NewRuleSet(),
		routes:       make(map[string]*Route),
		healthStates: make(map[string]*HealthState),
		dnsCache:     NewDNSCache(5 * time.Minute),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start starts the routing engine
func (e *Engine) Start() error {
	// Start health check loop
	go e.healthCheckLoop()

	// Start DNS cache cleanup
	go e.dnsCleanupLoop()

	return nil
}

// Stop stops the routing engine
func (e *Engine) Stop() {
	e.cancel()
}

// AddRule adds a routing rule
func (e *Engine) AddRule(rule *Rule) error {
	return e.ruleSet.AddRule(rule)
}

// RemoveRule removes a routing rule
func (e *Engine) RemoveRule(name string) {
	e.ruleSet.RemoveRule(name)
}

// AddRoute adds a route
func (e *Engine) AddRoute(route *Route) {
	e.routesMu.Lock()
	defer e.routesMu.Unlock()

	e.routes[route.Name] = route

	// Initialize health state
	e.healthMu.Lock()
	e.healthStates[route.Name] = &HealthState{
		Status: HealthStatusUnknown,
	}
	e.healthMu.Unlock()
}

// RemoveRoute removes a route
func (e *Engine) RemoveRoute(name string) {
	e.routesMu.Lock()
	defer e.routesMu.Unlock()

	delete(e.routes, name)

	e.healthMu.Lock()
	delete(e.healthStates, name)
	e.healthMu.Unlock()
}

// Route determines the route for a target
func (e *Engine) Route(target *Target) (*Route, *Action, error) {
	e.requestsTotal.Add(1)

	// Resolve domain if needed
	if target.IP == nil && target.Host != "" {
		ips, err := e.resolveDomain(target.Host)
		if err != nil {
			return nil, nil, err
		}
		if len(ips) > 0 {
			target.IP = ips[0]
		}
	}

	// Match rules
	rule, err := e.ruleSet.Match(target)
	if err != nil {
		return nil, nil, err
	}

	if rule == nil {
		// No match, use default
		return nil, &Action{Type: ActionTypeDirect}, nil
	}

	e.requestsMatched.Add(1)

	// Handle action
	switch rule.Action.Type {
	case ActionTypeBlock:
		e.requestsBlocked.Add(1)
		return nil, &rule.Action, nil

	case ActionTypeDirect:
		return nil, &rule.Action, nil

	case ActionTypeChain, ActionTypeProxy:
		// Find route
		route := e.getRoute(rule.Action.Chain)
		if route == nil {
			return nil, nil, fmt.Errorf("route not found: %s", rule.Action.Chain)
		}
		return route, &rule.Action, nil
	}

	return nil, nil, fmt.Errorf("unknown action type: %s", rule.Action.Type)
}

// RouteNoResolve determines the route for a target without performing DNS resolution.
//
// This is intended for policy-only decisions where DNS lookups would be undesirable
// (performance, privacy, offline environments). CIDR/IP matchers will only match
// when target.IP is already populated.
func (e *Engine) RouteNoResolve(target *Target) (*Route, *Action, error) {
	e.requestsTotal.Add(1)

	// Match rules without resolving domain names.
	rule, err := e.ruleSet.Match(target)
	if err != nil {
		return nil, nil, err
	}
	if rule == nil {
		return nil, &Action{Type: ActionTypeDirect}, nil
	}

	e.requestsMatched.Add(1)

	switch rule.Action.Type {
	case ActionTypeBlock:
		e.requestsBlocked.Add(1)
		return nil, &rule.Action, nil
	case ActionTypeDirect:
		return nil, &rule.Action, nil
	case ActionTypeChain, ActionTypeProxy:
		route := e.getRoute(rule.Action.Chain)
		// If no named route exists, still return the action. This allows using
		// Action.Chain/Action.Proxy as generic selectors (e.g., dialer policy).
		return route, &rule.Action, nil
	default:
		return nil, nil, fmt.Errorf("unknown action type: %s", rule.Action.Type)
	}
}

// getRoute gets a route by name
func (e *Engine) getRoute(name string) *Route {
	e.routesMu.RLock()
	defer e.routesMu.RUnlock()
	return e.routes[name]
}

// resolveDomain resolves a domain name to IPs with caching
func (e *Engine) resolveDomain(domain string) ([]net.IP, error) {
	// Check cache
	e.dnsCacheMu.RLock()
	entry, ok := e.dnsCache.entries[domain]
	e.dnsCacheMu.RUnlock()

	if ok && time.Since(entry.timestamp) < e.dnsCache.ttl {
		return entry.ips, nil
	}

	// Resolve
	ips, err := net.LookupIP(domain)
	if err != nil {
		// Return cached even if expired on error
		if ok {
			return entry.ips, nil
		}
		return nil, err
	}

	// Update cache
	e.dnsCacheMu.Lock()
	e.dnsCache.entries[domain] = &dnsEntry{
		ips:       ips,
		timestamp: time.Now(),
	}
	e.dnsCacheMu.Unlock()

	return ips, nil
}

// healthCheckLoop performs periodic health checks
func (e *Engine) healthCheckLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.runHealthChecks()
		}
	}
}

// runHealthChecks checks all routes with health checks configured
func (e *Engine) runHealthChecks() {
	e.routesMu.RLock()
	routes := make([]*Route, 0, len(e.routes))
	for _, r := range e.routes {
		if r.HealthCheck != nil {
			routes = append(routes, r)
		}
	}
	e.routesMu.RUnlock()

	for _, route := range routes {
		go e.checkRoute(route)
	}
}

// checkRoute performs a health check on a route
func (e *Engine) checkRoute(route *Route) {
	if route.HealthCheck == nil {
		return
	}

	hc := route.HealthCheck
	healthy := false

	switch hc.Method {
	case "tcp":
		conn, err := net.DialTimeout("tcp", hc.Target, hc.Timeout)
		if err == nil {
			conn.Close()
			healthy = true
		}

	case "http", "https":
		client := &http.Client{
			Timeout: hc.Timeout,
		}
		resp, err := client.Get(hc.Target)
		if err == nil {
			resp.Body.Close()
			healthy = resp.StatusCode < 500
		}

	case "icmp":
		// Would need raw socket permissions for real ICMP
		// For now, assume healthy if configured
		healthy = true
	}

	// Update health state
	e.healthMu.Lock()
	state, ok := e.healthStates[route.Name]
	if !ok {
		state = &HealthState{}
		e.healthStates[route.Name] = state
	}

	if healthy {
		state.Successes++
		state.Failures = 0
		state.LastSuccess = time.Now()
		if state.Successes >= hc.Rise {
			state.Status = HealthStatusHealthy
			route.healthy.Store(true)
		}
	} else {
		state.Failures++
		state.Successes = 0
		state.LastFailure = time.Now()
		if state.Failures >= hc.Fall {
			state.Status = HealthStatusUnhealthy
			route.healthy.Store(false)
		}
	}
	e.healthMu.Unlock()

	route.lastChecked = time.Now()
}

// dnsCleanupLoop periodically cleans up expired DNS cache entries
func (e *Engine) dnsCleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.cleanupDNSCache()
		}
	}
}

// cleanupDNSCache removes expired DNS cache entries
func (e *Engine) cleanupDNSCache() {
	e.dnsCacheMu.Lock()
	defer e.dnsCacheMu.Unlock()

	cutoff := time.Now().Add(-e.dnsCache.ttl)
	for domain, entry := range e.dnsCache.entries {
		if entry.timestamp.Before(cutoff) {
			delete(e.dnsCache.entries, domain)
		}
	}
}

// GetHealthState returns the health state of a route
func (e *Engine) GetHealthState(routeName string) (*HealthState, bool) {
	e.healthMu.RLock()
	defer e.healthMu.RUnlock()
	state, ok := e.healthStates[routeName]
	return state, ok
}

// GetStats returns routing statistics
func (e *Engine) GetStats() EngineStats {
	return EngineStats{
		RequestsTotal:   e.requestsTotal.Load(),
		RequestsMatched: e.requestsMatched.Load(),
		RequestsBlocked: e.requestsBlocked.Load(),
		RouteCount:      len(e.routes),
		RuleCount:       len(e.ruleSet.GetRules()),
	}
}

// EngineStats contains routing engine statistics
type EngineStats struct {
	RequestsTotal   uint64
	RequestsMatched uint64
	RequestsBlocked uint64
	RouteCount      int
	RuleCount       int
}

// NewDNSCache creates a new DNS cache
func NewDNSCache(ttl time.Duration) *DNSCache {
	return &DNSCache{
		entries: make(map[string]*dnsEntry),
		ttl:     ttl,
	}
}

// RoutingNode is a graph node for routing decisions
type RoutingNode struct {
	name   string
	engine *Engine
}

// NewRoutingNode creates a new routing graph node
func NewRoutingNode(name string, engine *Engine) *RoutingNode {
	return &RoutingNode{
		name:   name,
		engine: engine,
	}
}

// Type returns the node type
func (n *RoutingNode) Type() graph.NodeType {
	return graph.NodeTypeRouting
}

// Name returns the node name
func (n *RoutingNode) Name() string {
	return n.name
}

// Process processes a packet and makes routing decisions
func (n *RoutingNode) Process(ctx context.Context, pkt *graph.Packet) (*graph.Packet, error) {
	// Extract target from packet
	target := &Target{
		Host:     "",
		Port:     0,
		Protocol: "",
	}

	if host, ok := pkt.Metadata["host"].(string); ok {
		target.Host = host
	}
	if proto, ok := pkt.Metadata["protocol"].(string); ok {
		target.Protocol = proto
	}

	// Parse port
	if portStr, ok := pkt.Metadata["port"].(string); ok && portStr != "" {
		fmt.Sscanf(portStr, "%d", &target.Port)
	}

	// Get route
	route, action, err := n.engine.Route(target)
	if err != nil {
		return nil, err
	}

	// Add routing decision to packet metadata
	pkt.Metadata["route"] = ""
	if route != nil {
		pkt.Metadata["route"] = route.Name
	}
	pkt.Metadata["action"] = string(action.Type)

	return pkt, nil
}

// Placeholder methods for RoutingNode (full implementation would be in graph.Node interface)
func (n *RoutingNode) Next() []string        { return nil }
func (n *RoutingNode) SetNext(next []string) {}
func (n *RoutingNode) AddNext(name string)   {}

// TargetFromAddr creates a Target from a network address
func TargetFromAddr(addr net.Addr) *Target {
	target := &Target{}

	switch a := addr.(type) {
	case *net.TCPAddr:
		target.IP = a.IP
		target.Port = a.Port
		target.Protocol = "tcp"
	case *net.UDPAddr:
		target.IP = a.IP
		target.Port = a.Port
		target.Protocol = "udp"
	default:
		// Try to parse from string
		host, port, _ := net.SplitHostPort(addr.String())
		target.Host = host
		fmt.Sscanf(port, "%d", &target.Port)
	}

	return target
}

// IsPrivateIP checks if an IP is in a private range
func IsPrivateIP(ip net.IP) bool {
	privateRanges := []*net.IPNet{
		{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
		{IP: net.ParseIP("127.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("169.254.0.0"), Mask: net.CIDRMask(16, 32)},
	}

	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}

	return false
}
