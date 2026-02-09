package quicmux

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

// Padder adds random padding to packets.
type Padder struct {
	min int
	max int
}

// NewPadder creates a new padder with min and max padding sizes.
func NewPadder(min, max int) *Padder {
	if min < 0 {
		min = 0
	}
	if max < min {
		max = min
	}
	return &Padder{min: min, max: max}
}

// Pad adds random padding to data and returns the padded data.
func (p *Padder) Pad(data []byte) []byte {
	if p.min == 0 && p.max == 0 {
		return data
	}

	// Determine padding size
	paddingSize := p.min
	if p.max > p.min {
		paddingSize += randInt(p.max - p.min)
	}

	// Create padded packet: [2 bytes data length][data][padding]
	result := make([]byte, 2+len(data)+paddingSize)
	binary.BigEndian.PutUint16(result, uint16(len(data)))
	copy(result[2:], data)

	// Fill padding with random data
	if paddingSize > 0 {
		io.ReadFull(rand.Reader, result[2+len(data):])
	}

	return result
}

// Unpad removes padding from data.
func (p *Padder) Unpad(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, io.ErrShortBuffer
	}

	dataLen := binary.BigEndian.Uint16(data)
	if int(dataLen) > len(data)-2 {
		return nil, io.ErrShortBuffer
	}

	return data[2 : 2+dataLen], nil
}

// randInt returns a random integer in [0, max).
func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	var buf [4]byte
	io.ReadFull(rand.Reader, buf[:])
	return int(binary.BigEndian.Uint32(buf[:])) % max
}

// RandomPadding generates random padding of the specified size.
func RandomPadding(size int) []byte {
	if size <= 0 {
		return nil
	}
	padding := make([]byte, size)
	io.ReadFull(rand.Reader, padding)
	return padding
}

// PadToMinimum pads data to at least minSize bytes.
func PadToMinimum(data []byte, minSize int) []byte {
	if len(data) >= minSize {
		return data
	}

	padded := make([]byte, minSize)
	copy(padded, data)
	io.ReadFull(rand.Reader, padded[len(data):])
	return padded
}
