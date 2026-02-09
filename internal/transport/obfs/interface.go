package obfs

import (
	"fmt"
	"net"
)

// Type represents the type of obfuscator
type Type string

const (
	// TypeNone disables obfuscation
	TypeNone Type = "none"
	// TypeSalamander uses BLAKE2b XOR (Hysteria-style)
	TypeSalamander Type = "salamander"
	// TypeXor uses simple XOR obfuscation
	TypeXor Type = "xor"
	// TypeNoize uses protocol mimicry
	TypeNoize Type = "noize"
	// TypePadding uses padding strategies
	TypePadding Type = "padding"
	// TypeAWG uses AmneziaWG junk injection
	TypeAWG Type = "awg"
)

// Obfuscator is the unified interface for all obfuscation methods
type Obfuscator interface {
	// WrapConn wraps a net.Conn with obfuscation
	WrapConn(conn net.Conn) (net.Conn, error)

	// WrapPacketConn wraps a net.PacketConn with obfuscation
	WrapPacketConn(conn net.PacketConn) (net.PacketConn, error)

	// GenerateJunk generates junk/padding data
	GenerateJunk() []byte

	// Type returns the obfuscator type
	Type() Type
}

// Chain allows multiple obfuscators to be chained together
type Chain struct {
	obfuscators []Obfuscator
}

// NewChain creates a new obfuscation chain
func NewChain(obfuscators ...Obfuscator) *Chain {
	return &Chain{
		obfuscators: obfuscators,
	}
}

// Add adds an obfuscator to the chain
func (c *Chain) Add(obf Obfuscator) {
	c.obfuscators = append(c.obfuscators, obf)
}

// WrapConn wraps a connection with all obfuscators in the chain
func (c *Chain) WrapConn(conn net.Conn) (net.Conn, error) {
	for _, obf := range c.obfuscators {
		var err error
		conn, err = obf.WrapConn(conn)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

// WrapPacketConn wraps a packet connection with all obfuscators in the chain
func (c *Chain) WrapPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	for _, obf := range c.obfuscators {
		var err error
		conn, err = obf.WrapPacketConn(conn)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

// GenerateJunk generates junk data from the last obfuscator that supports it
func (c *Chain) GenerateJunk() []byte {
	// Try obfuscators in reverse order (outermost first)
	for i := len(c.obfuscators) - 1; i >= 0; i-- {
		junk := c.obfuscators[i].GenerateJunk()
		if len(junk) > 0 {
			return junk
		}
	}
	return nil
}

// Type returns the chain type
func (c *Chain) Type() Type {
	return Type("chain")
}

// Ensure Chain implements Obfuscator
var _ Obfuscator = (*Chain)(nil)

// UnifiedConfig configures all obfuscation types
type UnifiedConfig struct {
	// Chain of obfuscators to apply
	Chain []ObfuscatorConfig `yaml:"chain"`

	// Individual obfuscator configs (for single obfuscation)
	Type    Type              `yaml:"type"`
	Key     string            `yaml:"key"`
	Params  map[string]string `yaml:"params"`
}

// ObfuscatorConfig configures a single obfuscator in a chain
type ObfuscatorConfig struct {
	Type   Type              `yaml:"type"`
	Key    string            `yaml:"key"`
	Params map[string]string `yaml:"params"`
}

// NewObfuscatorFromConfig creates an obfuscator from unified config
func NewObfuscatorFromConfig(cfg UnifiedConfig) (Obfuscator, error) {
	// If chain is specified, create a chain
	if len(cfg.Chain) > 0 {
		chain := NewChain()
		for _, obfCfg := range cfg.Chain {
			obf, err := createObfuscator(obfCfg.Type, obfCfg.Key, obfCfg.Params)
			if err != nil {
				return nil, err
			}
			if obf != nil {
				chain.Add(obf)
			}
		}
		return chain, nil
	}

	// Single obfuscator
	return createObfuscator(cfg.Type, cfg.Key, cfg.Params)
}

// createObfuscator creates a single obfuscator
func createObfuscator(obfType Type, key string, params map[string]string) (Obfuscator, error) {
	switch obfType {
	case TypeNone, "":
		return &NoneObfuscator{}, nil
	case TypeSalamander:
		return NewSalamanderObfuscator(key)
	case TypeXor:
		return NewXorObfuscatorUnified(key), nil
	case TypeNoize:
		return NewNoizeObfuscator(params)
	case TypePadding:
		return NewPaddingObfuscator(params)
	case TypeAWG:
		return NewAWGObfuscator(params)
	default:
		return nil, fmt.Errorf("unknown obfuscation type: %s", obfType)
	}
}

// NoneObfuscator is a no-op obfuscator
type NoneObfuscator struct{}

// WrapConn returns the connection unchanged
func (n *NoneObfuscator) WrapConn(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

// WrapPacketConn returns the packet connection unchanged
func (n *NoneObfuscator) WrapPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	return conn, nil
}

// GenerateJunk returns nil
func (n *NoneObfuscator) GenerateJunk() []byte {
	return nil
}

// Type returns TypeNone
func (n *NoneObfuscator) Type() Type {
	return TypeNone
}

// Ensure NoneObfuscator implements Obfuscator
var _ Obfuscator = (*NoneObfuscator)(nil)

// UnifiedSalamanderObfuscator wraps the existing salamander implementation
type UnifiedSalamanderObfuscator struct {
	key string
}

// NewSalamanderObfuscator creates a new Salamander obfuscator
func NewSalamanderObfuscator(key string) (Obfuscator, error) {
	if key == "" {
		return nil, fmt.Errorf("salamander key is required")
	}
	return &UnifiedSalamanderObfuscator{key: key}, nil
}

// WrapConn wraps a connection with Salamander obfuscation
func (s *UnifiedSalamanderObfuscator) WrapConn(conn net.Conn) (net.Conn, error) {
	return NewSalamanderConn(conn, s.key)
}

// WrapPacketConn wraps a packet connection with Salamander obfuscation
func (s *UnifiedSalamanderObfuscator) WrapPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	return NewSalamanderPacketConn(conn, s.key)
}

// GenerateJunk returns nil (Salamander doesn't generate junk)
func (s *UnifiedSalamanderObfuscator) GenerateJunk() []byte {
	return nil
}

// Type returns TypeSalamander
func (s *UnifiedSalamanderObfuscator) Type() Type {
	return TypeSalamander
}

// Ensure UnifiedSalamanderObfuscator implements Obfuscator
var _ Obfuscator = (*UnifiedSalamanderObfuscator)(nil)

// XorObfuscatorUnified wraps the existing XOR implementation
type XorObfuscatorUnified struct {
	key string
}

// NewXorObfuscatorUnified creates a new XOR obfuscator
func NewXorObfuscatorUnified(key string) Obfuscator {
	return &XorObfuscatorUnified{key: key}
}

// WrapConn wraps a connection with XOR obfuscation
func (x *XorObfuscatorUnified) WrapConn(conn net.Conn) (net.Conn, error) {
	return NewXorConn(conn, x.key)
}

// WrapPacketConn wraps a packet connection with XOR obfuscation
func (x *XorObfuscatorUnified) WrapPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	return NewXorPacketConn(conn, x.key)
}

// GenerateJunk returns nil (XOR doesn't generate junk)
func (x *XorObfuscatorUnified) GenerateJunk() []byte {
	return nil
}

// Type returns TypeXor
func (x *XorObfuscatorUnified) Type() Type {
	return TypeXor
}

// Ensure XorObfuscatorUnified implements Obfuscator
var _ Obfuscator = (*XorObfuscatorUnified)(nil)
