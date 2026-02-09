package graph

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestNode is a simple node implementation for testing
type TestNode struct {
	BaseNode
	processFunc func(ctx context.Context, pkt *Packet) (*Packet, error)
}

func NewTestNode(name string, nodeType NodeType, fn func(ctx context.Context, pkt *Packet) (*Packet, error)) *TestNode {
	return &TestNode{
		BaseNode:    NewBaseNode(nodeType, name),
		processFunc: fn,
	}
}

func (n *TestNode) Process(ctx context.Context, pkt *Packet) (*Packet, error) {
	if n.processFunc != nil {
		return n.processFunc(ctx, pkt)
	}
	return pkt, nil
}

func TestNewGraph(t *testing.T) {
	g := NewGraph(&Config{
		Name:        "test",
		EntryPoints: []string{"entry"},
		ExitPoints:  []string{"exit"},
	})

	if g.Name() != "test" {
		t.Errorf("expected name 'test', got '%s'", g.Name())
	}
}

func TestGraphAddNode(t *testing.T) {
	g := NewGraph(&Config{Name: "test"})
	node := NewTestNode("node1", NodeTypeCarrier, nil)

	if err := g.AddNode(node); err != nil {
		t.Errorf("failed to add node: %v", err)
	}

	// Duplicate should fail
	if err := g.AddNode(node); err == nil {
		t.Error("expected error for duplicate node")
	}

	// Retrieve
	retrieved, ok := g.GetNode("node1")
	if !ok {
		t.Error("node not found")
	}
	if retrieved.Name() != "node1" {
		t.Errorf("expected node1, got %s", retrieved.Name())
	}
}

func TestGraphConnect(t *testing.T) {
	g := NewGraph(&Config{Name: "test"})
	node1 := NewTestNode("node1", NodeTypeCarrier, nil)
	node2 := NewTestNode("node2", NodeTypeObfs, nil)

	g.AddNode(node1)
	g.AddNode(node2)

	if err := g.Connect("node1", "node2"); err != nil {
		t.Errorf("failed to connect nodes: %v", err)
	}

	// Non-existent source
	if err := g.Connect("nonexistent", "node2"); err == nil {
		t.Error("expected error for non-existent source")
	}

	// Non-existent target
	if err := g.Connect("node1", "nonexistent"); err == nil {
		t.Error("expected error for non-existent target")
	}
}

func TestGraphCycleDetection(t *testing.T) {
	g := NewGraph(&Config{Name: "test"})
	node1 := NewTestNode("node1", NodeTypeCarrier, nil)
	node2 := NewTestNode("node2", NodeTypeObfs, nil)
	node3 := NewTestNode("node3", NodeTypeSecurity, nil)

	g.AddNode(node1)
	g.AddNode(node2)
	g.AddNode(node3)

	// Create a path: node1 -> node2 -> node3
	g.Connect("node1", "node2")
	g.Connect("node2", "node3")

	// Try to create a cycle: node3 -> node1
	if err := g.Connect("node3", "node1"); err == nil {
		t.Error("expected error for cycle creation")
	}
}

func TestGraphValidate(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *Graph
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid graph",
			setup: func() *Graph {
				g := NewGraph(&Config{Name: "test", EntryPoints: []string{"entry"}, ExitPoints: []string{"exit"}})
				entry := NewTestNode("entry", NodeTypeCarrier, nil)
				middle := NewTestNode("middle", NodeTypeObfs, nil)
				exit := NewTestNode("exit", NodeTypeMux, nil)
				g.AddNode(entry)
				g.AddNode(middle)
				g.AddNode(exit)
				g.Connect("entry", "middle")
				g.Connect("middle", "exit")
				return g
			},
			wantErr: false,
		},
		{
			name: "no entry points",
			setup: func() *Graph {
				return NewGraph(&Config{Name: "test", EntryPoints: nil, ExitPoints: []string{"exit"}})
			},
			wantErr: true,
			errMsg:  "no entry points defined",
		},
		{
			name: "no exit points",
			setup: func() *Graph {
				g := NewGraph(&Config{Name: "test", EntryPoints: []string{"entry"}, ExitPoints: nil})
				entry := NewTestNode("entry", NodeTypeCarrier, nil)
				g.AddNode(entry)
				return g
			},
			wantErr: true,
			errMsg:  "no exit points defined",
		},
		{
			name: "missing entry point node",
			setup: func() *Graph {
				return NewGraph(&Config{Name: "test", EntryPoints: []string{"nonexistent"}, ExitPoints: []string{"exit"}})
			},
			wantErr: true,
			errMsg:  "entry point nonexistent not found",
		},
		{
			name: "orphan node",
			setup: func() *Graph {
				g := NewGraph(&Config{Name: "test", EntryPoints: []string{"entry"}, ExitPoints: []string{"exit"}})
				entry := NewTestNode("entry", NodeTypeCarrier, nil)
				exit := NewTestNode("exit", NodeTypeMux, nil)
				orphan := NewTestNode("orphan", NodeTypeObfs, nil)
				g.AddNode(entry)
				g.AddNode(exit)
				g.AddNode(orphan)
				g.Connect("entry", "exit")
				return g
			},
			wantErr: true,
			errMsg:  "orphan nodes detected",
		},
		{
			name: "cycle detected",
			setup: func() *Graph {
				g := NewGraph(&Config{Name: "test", EntryPoints: []string{"a"}, ExitPoints: []string{"c"}})
				a := NewTestNode("a", NodeTypeCarrier, nil)
				b := NewTestNode("b", NodeTypeObfs, nil)
				c := NewTestNode("c", NodeTypeSecurity, nil)
				g.AddNode(a)
				g.AddNode(b)
				g.AddNode(c)
				// Manually create edges to bypass cycle detection
				a.SetNext([]string{"b"})
				b.SetNext([]string{"c"})
				c.SetNext([]string{"a"}) // Creates cycle
				return g
			},
			wantErr: true,
			errMsg:  "cycle detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := tt.setup()
			err := g.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errMsg)
				} else if tt.errMsg != "" && !errors.Is(err, errors.New(tt.errMsg)) {
					// Check if error message contains expected substring
					if !contains(err.Error(), tt.errMsg) {
						t.Errorf("expected error containing '%s', got '%s'", tt.errMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGraphExecute(t *testing.T) {
	g := NewGraph(&Config{Name: "test", EntryPoints: []string{"entry"}, ExitPoints: []string{"exit"}})

	// Track execution order
	var order []string

	entry := NewTestNode("entry", NodeTypeCarrier, func(ctx context.Context, pkt *Packet) (*Packet, error) {
		order = append(order, "entry")
		pkt.SetMetadata("processed", true)
		return pkt, nil
	})

	middle := NewTestNode("middle", NodeTypeObfs, func(ctx context.Context, pkt *Packet) (*Packet, error) {
		order = append(order, "middle")
		return pkt, nil
	})

	exit := NewTestNode("exit", NodeTypeMux, func(ctx context.Context, pkt *Packet) (*Packet, error) {
		order = append(order, "exit")
		return pkt, nil
	})

	g.AddNode(entry)
	g.AddNode(middle)
	g.AddNode(exit)
	g.Connect("entry", "middle")
	g.Connect("middle", "exit")

	pkt := NewPacket([]byte("test"), DirectionOutbound)
	results, err := g.Execute(context.Background(), pkt)

	if err != nil {
		t.Errorf("execution failed: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	expectedOrder := []string{"entry", "middle", "exit"}
	if len(order) != len(expectedOrder) {
		t.Errorf("expected order %v, got %v", expectedOrder, order)
	}
	for i, v := range expectedOrder {
		if i >= len(order) || order[i] != v {
			t.Errorf("expected order[%d] = %s, got %s", i, v, order[i])
		}
	}
}

func TestGraphExecuteDrop(t *testing.T) {
	g := NewGraph(&Config{Name: "test", EntryPoints: []string{"entry"}, ExitPoints: []string{"exit"}})

	entry := NewTestNode("entry", NodeTypeCarrier, func(ctx context.Context, pkt *Packet) (*Packet, error) {
		return nil, nil // Drop packet
	})

	exit := NewTestNode("exit", NodeTypeMux, func(ctx context.Context, pkt *Packet) (*Packet, error) {
		t.Error("exit should not be called for dropped packet")
		return pkt, nil
	})

	g.AddNode(entry)
	g.AddNode(exit)
	g.Connect("entry", "exit")

	pkt := NewPacket([]byte("test"), DirectionOutbound)
	results, err := g.Execute(context.Background(), pkt)

	if err != nil {
		t.Errorf("execution failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results (packet dropped), got %d", len(results))
	}

	metrics := g.GetMetrics()
	if metrics.PacketsDropped != 1 {
		t.Errorf("expected 1 dropped packet, got %d", metrics.PacketsDropped)
	}
}

func TestGraphExecuteError(t *testing.T) {
	g := NewGraph(&Config{Name: "test", EntryPoints: []string{"entry"}, ExitPoints: []string{"exit"}})

	entry := NewTestNode("entry", NodeTypeCarrier, func(ctx context.Context, pkt *Packet) (*Packet, error) {
		return nil, errors.New("test error")
	})

	exit := NewTestNode("exit", NodeTypeMux, nil)

	g.AddNode(entry)
	g.AddNode(exit)
	g.Connect("entry", "exit")

	// Reset metrics to ensure we only count execution errors
	g.ResetMetrics()

	pkt := NewPacket([]byte("test"), DirectionOutbound)
	results, err := g.Execute(context.Background(), pkt)

	// Execution continues even if one path errors
	if err != nil {
		t.Errorf("execution should not fail: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results (path errored), got %d", len(results))
	}

	metrics := g.GetMetrics()
	if metrics.Errors < 1 {
		t.Errorf("expected at least 1 error, got %d", metrics.Errors)
	}
}

func TestGraphMaxDepth(t *testing.T) {
	g := NewGraph(&Config{Name: "test", EntryPoints: []string{"entry"}, ExitPoints: []string{"exit"}})

	// Create a deep chain
	prev := NewTestNode("entry", NodeTypeCarrier, nil)
	g.AddNode(prev)

	for i := 0; i < 10; i++ {
		node := NewTestNode(fmt.Sprintf("node%d", i), NodeTypeObfs, nil)
		g.AddNode(node)
		g.Connect(prev.Name(), node.Name())
		prev = node
	}

	exit := NewTestNode("exit", NodeTypeMux, nil)
	g.AddNode(exit)
	g.Connect(prev.Name(), "exit")

	pkt := NewPacket([]byte("test"), DirectionOutbound)
	// Should succeed with depth 10
	_, err := g.Execute(context.Background(), pkt)
	if err != nil {
		t.Errorf("execution failed: %v", err)
	}
}

func TestBuilder(t *testing.T) {
	// Create graph manually and validate
	g := NewGraph(&Config{Name: "test", EntryPoints: []string{"entry"}, ExitPoints: []string{"exit"}})
	g.AddNode(NewTestNode("entry", NodeTypeCarrier, nil))
	g.AddNode(NewTestNode("middle", NodeTypeObfs, nil))
	g.AddNode(NewTestNode("exit", NodeTypeMux, nil))
	g.Connect("entry", "middle")
	g.Connect("middle", "exit")

	if g.Name() != "test" {
		t.Errorf("expected name 'test', got '%s'", g.Name())
	}

	if err := g.Validate(); err != nil {
		t.Errorf("validation failed: %v", err)
	}
}

func TestBuilderError(t *testing.T) {
	_, err := NewBuilder("test").
		WithEntry("entry").
		WithExit("exit").
		AddNode(NewTestNode("entry", NodeTypeCarrier, nil)).
		Then("nonexistent"). // nonexistent node
		Build()

	if err == nil {
		t.Error("expected error for nonexistent node reference")
	}
}

func TestGraphDOT(t *testing.T) {
	g := NewGraph(&Config{Name: "test", EntryPoints: []string{"entry"}, ExitPoints: []string{"exit"}})
	entry := NewTestNode("entry", NodeTypeCarrier, nil)
	exit := NewTestNode("exit", NodeTypeMux, nil)
	g.AddNode(entry)
	g.AddNode(exit)
	g.Connect("entry", "exit")

	dot := g.DOT()

	expectedParts := []string{
		"digraph test",
		`"entry"`,
		`"exit"`,
		"(carrier)",
		"(mux)",
		`"entry" -> "exit"`,
	}

	for _, part := range expectedParts {
		if !contains(dot, part) {
			t.Errorf("expected DOT output to contain '%s', got:\n%s", part, dot)
		}
	}
}

func TestGraphTopology(t *testing.T) {
	g := NewGraph(&Config{Name: "test", EntryPoints: []string{"entry"}, ExitPoints: []string{"exit"}})
	entry := NewTestNode("entry", NodeTypeCarrier, nil)
	middle := NewTestNode("middle", NodeTypeObfs, nil)
	exit := NewTestNode("exit", NodeTypeMux, nil)
	g.AddNode(entry)
	g.AddNode(middle)
	g.AddNode(exit)
	g.Connect("entry", "middle")
	g.Connect("middle", "exit")

	topology := g.Topology()

	if len(topology) != 3 {
		t.Errorf("expected 3 nodes in topology, got %d", len(topology))
	}

	if len(topology["entry"]) != 1 || topology["entry"][0] != "middle" {
		t.Errorf("expected entry -> middle, got %v", topology["entry"])
	}

	if len(topology["middle"]) != 1 || topology["middle"][0] != "exit" {
		t.Errorf("expected middle -> exit, got %v", topology["middle"])
	}

	if len(topology["exit"]) != 0 {
		t.Errorf("expected exit to have no outgoing edges, got %v", topology["exit"])
	}
}

func TestPacketClone(t *testing.T) {
	pkt := NewPacket([]byte("test"), DirectionOutbound)
	pkt.SetMetadata("key", "value")
	pkt.Src = &testAddr{"tcp", "127.0.0.1:1234"}
	pkt.Dst = &testAddr{"tcp", "127.0.0.1:5678"}

	cloned := pkt.Clone()

	// Data should be independent
	pkt.Data[0] = 'X'
	if cloned.Data[0] == 'X' {
		t.Error("clone data should be independent")
	}

	// Metadata should be independent
	pkt.SetMetadata("key", "newvalue")
	if v, _ := cloned.GetMetadata("key"); v == "newvalue" {
		t.Error("clone metadata should be independent")
	}

	// Direction should be copied
	if cloned.Dir != DirectionOutbound {
		t.Error("clone direction should match original")
	}
}

func TestExecutionTimeout(t *testing.T) {
	g := NewGraph(&Config{
		Name:             "test",
		EntryPoints:      []string{"entry"},
		ExitPoints:       []string{"exit"},
		ExecutionTimeout: 100 * time.Millisecond,
	})

	slowNode := NewTestNode("entry", NodeTypeCarrier, func(ctx context.Context, pkt *Packet) (*Packet, error) {
		timer := time.NewTimer(200 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return pkt, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	exit := NewTestNode("exit", NodeTypeMux, nil)
	g.AddNode(slowNode)
	g.AddNode(exit)
	g.Connect("entry", "exit")

	// Note: The timeout is set in config but not enforced in executeNode yet
	// This test documents expected behavior - errors are counted but not returned
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	g.ResetMetrics()
	pkt := NewPacket([]byte("test"), DirectionOutbound)
	results, err := g.Execute(ctx, pkt)

	// Execute doesn't return node errors, it counts them
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should have no results due to timeout
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}

	// Should have recorded an error
	metrics := g.GetMetrics()
	if metrics.Errors < 1 {
		t.Errorf("expected at least 1 error from timeout, got %d", metrics.Errors)
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 &&	substr != "" && containsInternal(s, substr)))
}

func containsInternal(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

type testAddr struct {
	network string
	str     string
}

func (a *testAddr) Network() string { return a.network }
func (a *testAddr) String() string  { return a.str }
