package padding

import (
	"math/rand"
)

// HandshakePaddingConfig configures random padding for handshakes.
// Based on Hysteria's padding technique.
type HandshakePaddingConfig struct {
	Enabled   bool `yaml:"enabled"`    // Enable handshake padding
	AuthMin   int  `yaml:"auth_min"`   // Min padding for auth handshake (default: 256)
	AuthMax   int  `yaml:"auth_max"`   // Max padding for auth handshake (default: 2048)
	DataMin   int  `yaml:"data_min"`   // Min padding for data frames (default: 64)
	DataMax   int  `yaml:"data_max"`   // Max padding for data frames (default: 1024)
}

// ApplyDefaults sets default values.
func (c *HandshakePaddingConfig) ApplyDefaults() {
	if c.AuthMin <= 0 {
		c.AuthMin = 256
	}
	if c.AuthMax <= 0 {
		c.AuthMax = 2048
	}
	if c.AuthMax < c.AuthMin {
		c.AuthMax = c.AuthMin
	}
	if c.DataMin <= 0 {
		c.DataMin = 64
	}
	if c.DataMax <= 0 {
		c.DataMax = 1024
	}
	if c.DataMax < c.DataMin {
		c.DataMax = c.DataMin
	}
}

// AuthPadding returns random padding size for authentication handshake.
func (c *HandshakePaddingConfig) AuthPadding() int {
	if !c.Enabled {
		return 0
	}
	c.ApplyDefaults()
	if c.AuthMin == c.AuthMax {
		return c.AuthMin
	}
	return c.AuthMin + rand.Intn(c.AuthMax-c.AuthMin+1)
}

// DataPadding returns random padding size for data frames.
func (c *HandshakePaddingConfig) DataPadding() int {
	if !c.Enabled {
		return 0
	}
	c.ApplyDefaults()
	if c.DataMin == c.DataMax {
		return c.DataMin
	}
	return c.DataMin + rand.Intn(c.DataMax-c.DataMin+1)
}

// GenerateAuthPadding generates padding bytes for authentication.
func (c *HandshakePaddingConfig) GenerateAuthPadding() []byte {
	size := c.AuthPadding()
	if size <= 0 {
		return nil
	}
	return generateRandom(size)
}

// GenerateDataPadding generates padding bytes for data frames.
func (c *HandshakePaddingConfig) GenerateDataPadding() []byte {
	size := c.DataPadding()
	if size <= 0 {
		return nil
	}
	return generateRandom(size)
}

// FramePadding provides frame-level padding for protocols.
type FramePadding struct {
	Min      int
	Max      int
	Enabled  bool
}

// NewFramePadding creates frame padding with the given range.
func NewFramePadding(min, max int) *FramePadding {
	return &FramePadding{
		Min:     min,
		Max:     max,
		Enabled: min > 0 || max > 0,
	}
}

// Size returns a random padding size.
func (f *FramePadding) Size() int {
	if !f.Enabled {
		return 0
	}
	if f.Min >= f.Max {
		return f.Min
	}
	return f.Min + rand.Intn(f.Max-f.Min+1)
}

// Generate creates random padding bytes.
func (f *FramePadding) Generate() []byte {
	size := f.Size()
	if size <= 0 {
		return nil
	}
	return generateRandom(size)
}

// PaddedFrame represents a frame with optional padding.
type PaddedFrame struct {
	Data    []byte
	Padding []byte
}

// TotalSize returns the total size including padding.
func (p *PaddedFrame) TotalSize() int {
	return len(p.Data) + len(p.Padding)
}

// Serialize combines data and padding into a single buffer.
func (p *PaddedFrame) Serialize() []byte {
	if len(p.Padding) == 0 {
		return p.Data
	}
	result := make([]byte, p.TotalSize())
	copy(result, p.Data)
	copy(result[len(p.Data):], p.Padding)
	return result
}
