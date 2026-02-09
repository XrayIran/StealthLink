package graph

import (
	"context"
	"testing"
)

func TestNewPacket(t *testing.T) {
	data := []byte("test data")
	pkt := NewPacket(data, DirectionOutbound)

	if string(pkt.Data) != string(data) {
		t.Errorf("expected data '%s', got '%s'", data, pkt.Data)
	}

	if pkt.Dir != DirectionOutbound {
		t.Errorf("expected direction outbound, got %s", pkt.Dir)
	}

	if pkt.Metadata == nil {
		t.Error("expected metadata to be initialized")
	}

	if pkt.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

func TestPacketMetadata(t *testing.T) {
	pkt := NewPacket([]byte("test"), DirectionOutbound)

	// Set and get
	pkt.SetMetadata("key1", "value1")
	val, ok := pkt.GetMetadata("key1")
	if !ok {
		t.Error("expected to find key1")
	}
	if val != "value1" {
		t.Errorf("expected 'value1', got '%v'", val)
	}

	// Non-existent key
	_, ok = pkt.GetMetadata("nonexistent")
	if ok {
		t.Error("expected nonexistent key to not be found")
	}
}

func TestBaseNode(t *testing.T) {
	node := NewBaseNode(NodeTypeCarrier, "test-node")

	if node.Type() != NodeTypeCarrier {
		t.Errorf("expected type %s, got %s", NodeTypeCarrier, node.Type())
	}

	if node.Name() != "test-node" {
		t.Errorf("expected name 'test-node', got '%s'", node.Name())
	}

	if len(node.Next()) != 0 {
		t.Errorf("expected no next nodes, got %d", len(node.Next()))
	}
}

func TestBaseNodeSetNext(t *testing.T) {
	node := NewBaseNode(NodeTypeObfs, "obfs-node")

	next := []string{"next1", "next2"}
	node.SetNext(next)

	if len(node.Next()) != 2 {
		t.Errorf("expected 2 next nodes, got %d", len(node.Next()))
	}

	// Verify independence
	next[0] = "modified"
	if node.Next()[0] == "modified" {
		t.Error("SetNext should copy the slice")
	}
}

func TestBaseNodeAddNext(t *testing.T) {
	node := NewBaseNode(NodeTypeSecurity, "security-node")

	node.AddNext("next1")
	node.AddNext("next2")
	node.AddNext("next1") // Duplicate should be ignored

	next := node.Next()
	if len(next) != 2 {
		t.Errorf("expected 2 unique next nodes, got %d", len(next))
	}

	found := make(map[string]bool)
	for _, n := range next {
		found[n] = true
	}

	if !found["next1"] || !found["next2"] {
		t.Error("expected both next1 and next2")
	}
}

func TestConnectionState(t *testing.T) {
	state := NewConnectionState("conn-123")

	if state.ID != "conn-123" {
		t.Errorf("expected ID 'conn-123', got '%s'", state.ID)
	}

	if state.Created.IsZero() {
		t.Error("expected Created to be set")
	}

	if state.LastActivity.IsZero() {
		t.Error("expected LastActivity to be set")
	}

	// Test node state
	state.SetNodeState("node1", "state1")
	val, ok := state.GetNodeState("node1")
	if !ok || val != "state1" {
		t.Error("expected to retrieve node state")
	}

	// Test touch
	oldActivity := state.LastActivity
	state.Touch()
	if !state.LastActivity.After(oldActivity) {
		t.Error("expected LastActivity to be updated")
	}
}

func TestNodeRegistry(t *testing.T) {
	registry := NewNodeRegistry()

	// Create a simple factory
	factory := func(config map[string]interface{}) (Node, error) {
		name := "default"
		if n, ok := config["name"].(string); ok {
			name = n
		}
		return NewTestNode(name, NodeTypeCarrier, nil), nil
	}

	// Register
	registry.Register(NodeTypeCarrier, "test", factory)

	// Create
	node, err := registry.Create(NodeTypeCarrier, "test", map[string]interface{}{"name": "my-node"})
	if err != nil {
		t.Errorf("failed to create node: %v", err)
	}

	if node.Name() != "my-node" {
		t.Errorf("expected name 'my-node', got '%s'", node.Name())
	}

	// List
	carriers := registry.List(NodeTypeCarrier)
	if len(carriers) != 1 || carriers[0] != "test" {
		t.Errorf("expected ['test'], got %v", carriers)
	}

	// Unknown type
	_, err = registry.Create(NodeTypeProtocol, "unknown", nil)
	if err == nil {
		t.Error("expected error for unknown type")
	}

	// Unknown node
	_, err = registry.Create(NodeTypeCarrier, "unknown", nil)
	if err == nil {
		t.Error("expected error for unknown node")
	}
}

func TestNodeTypeConstants(t *testing.T) {
	tests := []struct {
		nodeType NodeType
		expected string
	}{
		{NodeTypeCarrier, "carrier"},
		{NodeTypeObfs, "obfs"},
		{NodeTypeSecurity, "security"},
		{NodeTypeRouting, "routing"},
		{NodeTypeProtocol, "protocol"},
		{NodeTypeMux, "mux"},
	}

	for _, tt := range tests {
		if string(tt.nodeType) != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.nodeType)
		}
	}
}

func TestDirectionConstants(t *testing.T) {
	if DirectionOutbound != "outbound" {
		t.Errorf("expected 'outbound', got '%s'", DirectionOutbound)
	}

	if DirectionInbound != "inbound" {
		t.Errorf("expected 'inbound', got '%s'", DirectionInbound)
	}
}

// TestStatefulNode is a node that maintains state
type TestStatefulNode struct {
	BaseNode
	initCalled bool
}

func (n *TestStatefulNode) Process(ctx context.Context, pkt *Packet) (*Packet, error) {
	return pkt, nil
}

func TestStatefulNodeInterface(t *testing.T) {
	// Test that stateful nodes can be implemented
	node := &TestStatefulNode{
		BaseNode: NewBaseNode(NodeTypeCarrier, "stateful"),
	}

	// Verify it implements Node interface
	var _ Node = node

	if node.Type() != NodeTypeCarrier {
		t.Error("type mismatch")
	}

	if node.Name() != "stateful" {
		t.Error("name mismatch")
	}
}

func TestPacketWithNilMetadata(t *testing.T) {
	pkt := &Packet{
		Data: []byte("test"),
		Dir:  DirectionOutbound,
	}

	// Should handle nil metadata gracefully
	val, ok := pkt.GetMetadata("key")
	if ok {
		t.Error("expected no value for nil metadata")
	}
	if val != nil {
		t.Error("expected nil value")
	}

	// SetMetadata should initialize metadata
	pkt.SetMetadata("key", "value")
	if pkt.Metadata == nil {
		t.Error("expected metadata to be initialized")
	}

	val, ok = pkt.GetMetadata("key")
	if !ok || val != "value" {
		t.Error("expected to get value after SetMetadata")
	}
}

func TestExecutionContext(t *testing.T) {
	ctx := NewExecutionContext("conn-123", 50)

	if ctx.ConnID != "conn-123" {
		t.Errorf("expected ConnID 'conn-123', got '%s'", ctx.ConnID)
	}

	if ctx.MaxDepth != 50 {
		t.Errorf("expected MaxDepth 50, got %d", ctx.MaxDepth)
	}

	if ctx.Depth != 0 {
		t.Errorf("expected initial Depth 0, got %d", ctx.Depth)
	}

	if ctx.Visited == nil {
		t.Error("expected Visited to be initialized")
	}

	if ctx.Path == nil {
		t.Error("expected Path to be initialized")
	}

	// Simulate visiting nodes
	ctx.Visited["node1"] = true
	ctx.Path = append(ctx.Path, "node1")

	if !ctx.Visited["node1"] {
		t.Error("expected node1 to be marked as visited")
	}

	if len(ctx.Path) != 1 || ctx.Path[0] != "node1" {
		t.Error("expected path to contain node1")
	}
}
