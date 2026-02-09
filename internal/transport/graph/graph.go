// Package graph provides a graph-based execution engine for the transport layer.
package graph

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Graph represents a directed acyclic graph of transport nodes
type Graph struct {
	// name is the unique identifier for this graph
	name string
	// nodes maps node names to node instances
	nodes map[string]Node
	// entryPoints are the starting nodes of the graph
	entryPoints []string
	// exitPoints are the terminal nodes of the graph
	exitPoints []string
	// mu protects the graph structure
	mu sync.RWMutex
	// state tracks per-connection state
	state *sync.Map
	// metrics tracks graph execution metrics
	metrics *Metrics
}

// Metrics tracks execution statistics
type Metrics struct {
	PacketsProcessed  uint64
	PacketsDropped    uint64
	Errors            uint64
	ActiveConnections uint64
	mu                sync.RWMutex
}

// Config holds graph configuration
type Config struct {
	// Name is the graph identifier
	Name string
	// EntryPoints are the starting node names
	EntryPoints []string
	// ExitPoints are the terminal node names
	ExitPoints []string
	// MaxDepth prevents infinite loops
	MaxDepth int
	// ExecutionTimeout limits single packet processing time
	ExecutionTimeout time.Duration
}

// NewGraph creates a new empty graph
func NewGraph(cfg *Config) *Graph {
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 100
	}
	if cfg.ExecutionTimeout == 0 {
		cfg.ExecutionTimeout = 30 * time.Second
	}
	return &Graph{
		name:        cfg.Name,
		nodes:       make(map[string]Node),
		entryPoints: cfg.EntryPoints,
		exitPoints:  cfg.ExitPoints,
		state:       &sync.Map{},
		metrics:     &Metrics{},
	}
}

// Name returns the graph name
func (g *Graph) Name() string {
	return g.name
}

// AddNode adds a node to the graph
func (g *Graph) AddNode(node Node) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodes[node.Name()]; exists {
		return fmt.Errorf("node %s already exists", node.Name())
	}

	g.nodes[node.Name()] = node
	return nil
}

// GetNode retrieves a node by name
func (g *Graph) GetNode(name string) (Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	node, ok := g.nodes[name]
	return node, ok
}

// RemoveNode removes a node from the graph
func (g *Graph) RemoveNode(name string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodes[name]; !exists {
		return fmt.Errorf("node %s not found", name)
	}

	// Check if any nodes reference this one
	for nodeName, node := range g.nodes {
		for _, next := range node.Next() {
			if next == name {
				return fmt.Errorf("node %s is referenced by %s", name, nodeName)
			}
		}
	}

	delete(g.nodes, name)
	return nil
}

// Connect creates an edge between two nodes
func (g *Graph) Connect(from, to string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	fromNode, ok := g.nodes[from]
	if !ok {
		return fmt.Errorf("source node %s not found", from)
	}
	if _, ok := g.nodes[to]; !ok {
		return fmt.Errorf("target node %s not found", to)
	}

	// Check for cycles before adding edge
	if g.wouldCreateCycle(from, to) {
		return fmt.Errorf("connecting %s -> %s would create a cycle", from, to)
	}

	fromNode.AddNext(to)
	return nil
}

// wouldCreateCycle checks if adding an edge would create a cycle
func (g *Graph) wouldCreateCycle(from, to string) bool {
	// Simple DFS from 'to' to see if we can reach 'from'
	visited := make(map[string]bool)
	var dfs func(string) bool
	dfs = func(node string) bool {
		if node == from {
			return true
		}
		if visited[node] {
			return false
		}
		visited[node] = true
		n, ok := g.nodes[node]
		if !ok {
			return false
		}
		for _, next := range n.Next() {
			if dfs(next) {
				return true
			}
		}
		return false
	}
	return dfs(to)
}

// Validate checks the graph for structural issues
func (g *Graph) Validate() error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Check for orphan nodes (not reachable from entry points)
	reachable := g.findReachableNodes()

	// Check for entry points
	if len(g.entryPoints) == 0 {
		return errors.New("no entry points defined")
	}

	for _, entry := range g.entryPoints {
		if _, ok := g.nodes[entry]; !ok {
			return fmt.Errorf("entry point %s not found", entry)
		}
	}

	// Check for exit points
	if len(g.exitPoints) == 0 {
		return errors.New("no exit points defined")
	}

	for _, exit := range g.exitPoints {
		if _, ok := g.nodes[exit]; !ok {
			return fmt.Errorf("exit point %s not found", exit)
		}
	}

	// Check for orphan nodes
	var orphans []string
	for name := range g.nodes {
		if !reachable[name] {
			orphans = append(orphans, name)
		}
	}
	if len(orphans) > 0 {
		return fmt.Errorf("orphan nodes detected: %v", orphans)
	}

	// Check for unreachable exit points
	for _, exit := range g.exitPoints {
		if !reachable[exit] {
			return fmt.Errorf("exit point %s is not reachable from any entry point", exit)
		}
	}

	// Check for cycles using DFS
	if cycle := g.detectCycle(); cycle != nil {
		return fmt.Errorf("cycle detected: %v", cycle)
	}

	return nil
}

// findReachableNodes finds all nodes reachable from entry points
func (g *Graph) findReachableNodes() map[string]bool {
	reachable := make(map[string]bool)
	var visit func(string)
	visit = func(name string) {
		if reachable[name] {
			return
		}
		reachable[name] = true
		if node, ok := g.nodes[name]; ok {
			for _, next := range node.Next() {
				visit(next)
			}
		}
	}
	for _, entry := range g.entryPoints {
		visit(entry)
	}
	return reachable
}

// detectCycle detects cycles in the graph using DFS
func (g *Graph) detectCycle() []string {
	// 0 = unvisited, 1 = visiting, 2 = visited
	state := make(map[string]int)
	var path []string

	var dfs func(string) []string
	dfs = func(node string) []string {
		state[node] = 1 // visiting
		path = append(path, node)

		n, ok := g.nodes[node]
		if ok {
			for _, next := range n.Next() {
				if state[next] == 1 {
					// Found cycle - extract cycle from path
					for i, v := range path {
						if v == next {
							return append(path[i:], next)
						}
					}
					return []string{next, node}
				}
				if state[next] == 0 {
					if cycle := dfs(next); cycle != nil {
						return cycle
					}
				}
			}
		}

		path = path[:len(path)-1]
		state[node] = 2 // visited
		return nil
	}

	for name := range g.nodes {
		if state[name] == 0 {
			if cycle := dfs(name); cycle != nil {
				return cycle
			}
		}
	}
	return nil
}

// ExecutionContext holds the context for graph execution
type ExecutionContext struct {
	// ConnID is the unique connection identifier
	ConnID string
	// Depth tracks recursion depth to prevent infinite loops
	Depth int
	// MaxDepth limits recursion
	MaxDepth int
	// Visited tracks visited nodes for this packet
	Visited map[string]bool
	// Path records the execution path
	Path []string
}

// NewExecutionContext creates a new execution context
func NewExecutionContext(connID string, maxDepth int) *ExecutionContext {
	return &ExecutionContext{
		ConnID:   connID,
		Depth:    0,
		MaxDepth: maxDepth,
		Visited:  make(map[string]bool),
		Path:     make([]string, 0),
	}
}

// Execute runs a packet through the graph starting from entry points
func (g *Graph) Execute(ctx context.Context, pkt *Packet) ([]*Packet, error) {
	return g.ExecuteFrom(ctx, pkt, g.entryPoints)
}

// ExecuteFrom runs a packet through the graph starting from specific nodes
func (g *Graph) ExecuteFrom(ctx context.Context, pkt *Packet, startNodes []string) ([]*Packet, error) {
	if err := g.Validate(); err != nil {
		return nil, fmt.Errorf("graph validation failed: %w", err)
	}

	connID, _ := pkt.GetMetadata("conn_id")
	if connID == nil {
		connID = fmt.Sprintf("%d", time.Now().UnixNano())
		pkt.SetMetadata("conn_id", connID)
	}

	execCtx := NewExecutionContext(connID.(string), 100)
	var results []*Packet

	for _, start := range startNodes {
		node, ok := g.GetNode(start)
		if !ok {
			continue
		}
		packets, err := g.executeNode(ctx, node, pkt.Clone(), execCtx)
		if err != nil {
			g.metrics.mu.Lock()
			g.metrics.Errors++
			g.metrics.mu.Unlock()
			continue
		}
		results = append(results, packets...)
	}

	g.metrics.mu.Lock()
	g.metrics.PacketsProcessed += uint64(len(results))
	g.metrics.mu.Unlock()

	return results, nil
}

// executeNode executes a single node and recursively processes next nodes
func (g *Graph) executeNode(ctx context.Context, node Node, pkt *Packet, execCtx *ExecutionContext) ([]*Packet, error) {
	if execCtx.Depth >= execCtx.MaxDepth {
		return nil, errors.New("max execution depth exceeded")
	}

	if execCtx.Visited[node.Name()] {
		return nil, fmt.Errorf("node %s already visited (cycle detected)", node.Name())
	}

	execCtx.Depth++
	execCtx.Visited[node.Name()] = true
	execCtx.Path = append(execCtx.Path, node.Name())

	// Process the packet
	processed, err := node.Process(ctx, pkt)
	if err != nil {
		g.metrics.mu.Lock()
		g.metrics.Errors++
		g.metrics.mu.Unlock()
		return nil, err
	}

	if processed == nil {
		g.metrics.mu.Lock()
		g.metrics.PacketsDropped++
		g.metrics.mu.Unlock()
		return nil, nil
	}

	nextNodes := node.Next()
	if len(nextNodes) == 0 {
		// Terminal node
		return []*Packet{processed}, nil
	}

	var results []*Packet
	for _, nextName := range nextNodes {
		nextNode, ok := g.GetNode(nextName)
		if !ok {
			continue
		}
		packets, err := g.executeNode(ctx, nextNode, processed.Clone(), execCtx)
		if err != nil {
			continue
		}
		results = append(results, packets...)
	}

	return results, nil
}

// GetMetrics returns current metrics
func (g *Graph) GetMetrics() Metrics {
	g.metrics.mu.RLock()
	defer g.metrics.mu.RUnlock()
	return Metrics{
		PacketsProcessed:  g.metrics.PacketsProcessed,
		PacketsDropped:    g.metrics.PacketsDropped,
		Errors:            g.metrics.Errors,
		ActiveConnections: g.metrics.ActiveConnections,
	}
}

// ResetMetrics resets all metrics to zero
func (g *Graph) ResetMetrics() {
	g.metrics.mu.Lock()
	defer g.metrics.mu.Unlock()
	g.metrics.PacketsProcessed = 0
	g.metrics.PacketsDropped = 0
	g.metrics.Errors = 0
}

// Topology returns the graph structure as an adjacency list
func (g *Graph) Topology() map[string][]string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	topology := make(map[string][]string, len(g.nodes))
	for name, node := range g.nodes {
		topology[name] = node.Next()
	}
	return topology
}

// DOT generates a Graphviz DOT representation of the graph
func (g *Graph) DOT() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("digraph ")
	sb.WriteString(g.name)
	sb.WriteString(" {\n")

	// Node definitions with types
	for name, node := range g.nodes {
		sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\\n(%s)\"]\n", name, name, node.Type()))
	}

	sb.WriteString("\n")

	// Edges
	for name, node := range g.nodes {
		for _, next := range node.Next() {
			sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\"\n", name, next))
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

// Builder provides a fluent API for constructing graphs
type Builder struct {
	graph   *Graph
	current Node
	err     error
}

// NewBuilder creates a new graph builder
func NewBuilder(name string) *Builder {
	return &Builder{
		graph: NewGraph(&Config{
			Name: name,
		}),
	}
}

// WithEntry adds an entry point
func (b *Builder) WithEntry(name string) *Builder {
	if b.err != nil {
		return b
	}
	b.graph.entryPoints = append(b.graph.entryPoints, name)
	return b
}

// WithExit adds an exit point
func (b *Builder) WithExit(name string) *Builder {
	if b.err != nil {
		return b
	}
	b.graph.exitPoints = append(b.graph.exitPoints, name)
	return b
}

// AddNode adds a node to the graph
func (b *Builder) AddNode(node Node) *Builder {
	if b.err != nil {
		return b
	}
	if err := b.graph.AddNode(node); err != nil {
		b.err = err
		return b
	}
	b.current = node
	return b
}

// Then connects the current node to the next
func (b *Builder) Then(nextName string) *Builder {
	if b.err != nil {
		return b
	}
	if b.current == nil {
		b.err = errors.New("no current node to connect from")
		return b
	}
	if err := b.graph.Connect(b.current.Name(), nextName); err != nil {
		b.err = err
		return b
	}
	return b
}

// Build validates and returns the graph
func (b *Builder) Build() (*Graph, error) {
	if b.err != nil {
		return nil, b.err
	}
	if err := b.graph.Validate(); err != nil {
		return nil, err
	}
	return b.graph, nil
}
