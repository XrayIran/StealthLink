// Package graph provides a graph-based execution engine for the transport layer.
// It enables flexible composition of carriers, obfuscation, security, and protocol nodes.
package graph

import (
	"context"
	"net"
	"time"
)

// NodeType represents the category of a node in the transport graph
type NodeType string

const (
	// NodeTypeCarrier represents transport carriers (tcp, quic, kcp, etc.)
	NodeTypeCarrier NodeType = "carrier"
	// NodeTypeObfs represents obfuscation layers (TLS, reality, shadowtls, etc.)
	NodeTypeObfs NodeType = "obfs"
	// NodeTypeSecurity represents security components (guard, anti-replay)
	NodeTypeSecurity NodeType = "security"
	// NodeTypeRouting represents routing decision nodes
	NodeTypeRouting NodeType = "routing"
	// NodeTypeProtocol represents protocol stacks (AnyConnect, TrustTunnel, Psiphon)
	NodeTypeProtocol NodeType = "protocol"
	// NodeTypeMux represents multiplexing layers (smux, quic streams)
	NodeTypeMux NodeType = "mux"
)

// Direction represents the flow direction through a node
type Direction string

const (
	// DirectionOutbound represents client-to-server flow
	DirectionOutbound Direction = "outbound"
	// DirectionInbound represents server-to-client flow
	DirectionInbound Direction = "inbound"
)

// Packet represents a unit of data flowing through the graph
type Packet struct {
	// Data is the payload
	Data []byte
	// Metadata carries additional information
	Metadata map[string]interface{}
	// Timestamp of packet creation/processing
	Timestamp time.Time
	// Source address
	Src net.Addr
	// Destination address
	Dst net.Addr
	// Direction of flow
	Dir Direction
	// Error if processing failed
	Error error
}

// NewPacket creates a new packet with the given data
func NewPacket(data []byte, dir Direction) *Packet {
	return &Packet{
		Data:      data,
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
		Dir:       dir,
	}
}

// Clone creates a deep copy of the packet
func (p *Packet) Clone() *Packet {
	data := make([]byte, len(p.Data))
	copy(data, p.Data)
	metadata := make(map[string]interface{}, len(p.Metadata))
	for k, v := range p.Metadata {
		metadata[k] = v
	}
	return &Packet{
		Data:      data,
		Metadata:  metadata,
		Timestamp: p.Timestamp,
		Src:       p.Src,
		Dst:       p.Dst,
		Dir:       p.Dir,
		Error:     p.Error,
	}
}

// SetMetadata sets a metadata value
func (p *Packet) SetMetadata(key string, value interface{}) {
	if p.Metadata == nil {
		p.Metadata = make(map[string]interface{})
	}
	p.Metadata[key] = value
}

// GetMetadata retrieves a metadata value
func (p *Packet) GetMetadata(key string) (interface{}, bool) {
	if p.Metadata == nil {
		return nil, false
	}
	v, ok := p.Metadata[key]
	return v, ok
}

// Node represents a single node in the transport graph
// Each node processes packets and passes them to next nodes
type Node interface {
	// Type returns the node type category
	Type() NodeType
	// Name returns the unique node name
	Name() string
	// Process processes a packet and returns the processed packet
	// Returns nil if the packet should be dropped
	Process(ctx context.Context, pkt *Packet) (*Packet, error)
	// Next returns the names of the next nodes in the graph
	Next() []string
	// SetNext sets the next node names
	SetNext(next []string)
	// AddNext adds a next node name
	AddNext(name string)
}

// BaseNode provides common functionality for all node types
type BaseNode struct {
	nodeType NodeType
	name     string
	next     []string
}

// NewBaseNode creates a new base node
func NewBaseNode(nodeType NodeType, name string) BaseNode {
	return BaseNode{
		nodeType: nodeType,
		name:     name,
		next:     make([]string, 0),
	}
}

// Type returns the node type
func (n *BaseNode) Type() NodeType {
	return n.nodeType
}

// Name returns the node name
func (n *BaseNode) Name() string {
	return n.name
}

// Next returns the next node names
func (n *BaseNode) Next() []string {
	return n.next
}

// SetNext sets the next node names (makes a copy)
func (n *BaseNode) SetNext(next []string) {
	n.next = make([]string, len(next))
	copy(n.next, next)
}

// AddNext adds a next node name
func (n *BaseNode) AddNext(name string) {
	for _, existing := range n.next {
		if existing == name {
			return
		}
	}
	n.next = append(n.next, name)
}

// ConnectionState represents the state of a connection through the graph
type ConnectionState struct {
	// ID is the unique connection identifier
	ID string
	// Created is when the connection was established
	Created time.Time
	// LastActivity is the last time data flowed
	LastActivity time.Time
	// NodeState holds per-node state
	NodeState map[string]interface{}
	// Metadata holds connection-level metadata
	Metadata map[string]interface{}
}

// NewConnectionState creates a new connection state
func NewConnectionState(id string) *ConnectionState {
	now := time.Now()
	return &ConnectionState{
		ID:           id,
		Created:      now,
		LastActivity: now,
		NodeState:    make(map[string]interface{}),
		Metadata:     make(map[string]interface{}),
	}
}

// GetNodeState retrieves state for a specific node
func (s *ConnectionState) GetNodeState(nodeName string) (interface{}, bool) {
	v, ok := s.NodeState[nodeName]
	return v, ok
}

// SetNodeState sets state for a specific node
func (s *ConnectionState) SetNodeState(nodeName string, state interface{}) {
	s.NodeState[nodeName] = state
}

// Touch updates the last activity timestamp
func (s *ConnectionState) Touch() {
	s.LastActivity = time.Now()
}

// StatefulNode is a node that maintains per-connection state
type StatefulNode interface {
	Node
	// InitState initializes state for a new connection
	InitState(connID string) interface{}
	// ProcessWithState processes a packet with connection state
	ProcessWithState(ctx context.Context, pkt *Packet, state interface{}) (*Packet, interface{}, error)
}

// NodeRegistry manages node implementations
type NodeRegistry struct {
	factories map[NodeType]map[string]NodeFactory
}

// NodeFactory creates a new node instance
type NodeFactory func(config map[string]interface{}) (Node, error)

// NewNodeRegistry creates a new node registry
func NewNodeRegistry() *NodeRegistry {
	return &NodeRegistry{
		factories: make(map[NodeType]map[string]NodeFactory),
	}
}

// Register registers a node factory
func (r *NodeRegistry) Register(nodeType NodeType, name string, factory NodeFactory) {
	if r.factories[nodeType] == nil {
		r.factories[nodeType] = make(map[string]NodeFactory)
	}
	r.factories[nodeType][name] = factory
}

// Create creates a new node instance
func (r *NodeRegistry) Create(nodeType NodeType, name string, config map[string]interface{}) (Node, error) {
	factories, ok := r.factories[nodeType]
	if !ok {
		return nil, &ErrUnknownNodeType{Type: nodeType}
	}
	factory, ok := factories[name]
	if !ok {
		return nil, &ErrUnknownNode{Name: name, Type: nodeType}
	}
	return factory(config)
}

// List returns all registered nodes of a given type
func (r *NodeRegistry) List(nodeType NodeType) []string {
	factories, ok := r.factories[nodeType]
	if !ok {
		return nil
	}
	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
	}
	return names
}

// ErrUnknownNodeType is returned when a node type is not registered
type ErrUnknownNodeType struct {
	Type NodeType
}

func (e *ErrUnknownNodeType) Error() string {
	return "unknown node type: " + string(e.Type)
}

// ErrUnknownNode is returned when a node is not registered
type ErrUnknownNode struct {
	Name string
	Type NodeType
}

func (e *ErrUnknownNode) Error() string {
	return "unknown node: " + e.Name + " of type " + string(e.Type)
}
