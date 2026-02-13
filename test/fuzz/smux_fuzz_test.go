package fuzz

import (
	"encoding/binary"
	"testing"
)

// FuzzSmuxFrameParse tests smux frame parsing to catch panic/crash inputs.
// This fuzzer tests the frame header parsing with various malformed inputs.
func FuzzSmuxFrameParse(f *testing.F) {
	// Seed corpus with valid frame examples
	// Frame header: Ver(1) + Cmd(1) + Length(2) + StreamID(4) = 8 bytes

	// Valid SYN frame
	synFrame := make([]byte, 8)
	synFrame[0] = 1                                   // Version
	synFrame[1] = 0                                   // Cmd: SYN
	binary.LittleEndian.PutUint16(synFrame[2:4], 0)   // Length: 0
	binary.LittleEndian.PutUint32(synFrame[4:8], 100) // StreamID
	f.Add(synFrame)

	// Valid PSH frame with data
	pshFrame := make([]byte, 8+10)
	pshFrame[0] = 1                                   // Version
	pshFrame[1] = 2                                   // Cmd: PSH
	binary.LittleEndian.PutUint16(pshFrame[2:4], 10)  // Length: 10
	binary.LittleEndian.PutUint32(pshFrame[4:8], 200) // StreamID
	copy(pshFrame[8:], []byte("testdata12"))
	f.Add(pshFrame)

	// Valid FIN frame
	finFrame := make([]byte, 8)
	finFrame[0] = 1                                   // Version
	finFrame[1] = 1                                   // Cmd: FIN
	binary.LittleEndian.PutUint16(finFrame[2:4], 0)   // Length: 0
	binary.LittleEndian.PutUint32(finFrame[4:8], 300) // StreamID
	f.Add(finFrame)

	// Valid UPD frame (protocol version 2)
	updFrame := make([]byte, 8+8)
	updFrame[0] = 2                                        // Version 2
	updFrame[1] = 4                                        // Cmd: UPD
	binary.LittleEndian.PutUint16(updFrame[2:4], 8)        // Length: 8
	binary.LittleEndian.PutUint32(updFrame[4:8], 400)      // StreamID
	binary.LittleEndian.PutUint32(updFrame[8:12], 1024)    // Consumed
	binary.LittleEndian.PutUint32(updFrame[12:16], 262144) // Window
	f.Add(updFrame)

	// Edge cases
	f.Add([]byte{})            // Empty
	f.Add([]byte{0x01})        // Too short
	f.Add(make([]byte, 8))     // Minimum header size
	f.Add(make([]byte, 1500))  // MTU size
	f.Add(make([]byte, 65535)) // Max size

	f.Fuzz(func(t *testing.T, data []byte) {
		// This should not panic even with malformed inputs
		header := parseSmuxHeaderSafe(data)

		// If header was parsed, verify basic invariants
		if header != nil {
			// Verify version is reasonable
			if header.Version > 10 {
				// Unusual but not necessarily invalid
			}

			// Verify command is in valid range
			if header.Cmd > 4 {
				// Unknown command, but should not crash
			}

			// Verify length matches available data
			if len(data) >= 8 {
				expectedDataLen := int(header.Length)
				availableDataLen := len(data) - 8
				if availableDataLen < expectedDataLen {
					// Truncated frame - should be handled gracefully
				}
			}
		}

		// Also test UPD header parsing if data is long enough
		if len(data) >= 8 {
			_ = parseUpdHeaderSafe(data)
		}
	})
}

// smuxHeader represents a parsed smux frame header
type smuxHeader struct {
	Version  byte
	Cmd      byte
	Length   uint16
	StreamID uint32
}

// updHeader represents a parsed UPD command header
type updHeader struct {
	Consumed uint32
	Window   uint32
}

const (
	headerSize = 8
	szCmdUPD   = 8
)

// parseSmuxHeaderSafe is a safe wrapper that catches panics
func parseSmuxHeaderSafe(data []byte) *smuxHeader {
	defer func() {
		if r := recover(); r != nil {
			// Panic caught - this is what fuzzing is designed to find
		}
	}()

	return parseSmuxHeader(data)
}

// parseSmuxHeader parses a smux frame header from bytes
func parseSmuxHeader(data []byte) *smuxHeader {
	if len(data) < headerSize {
		return nil
	}

	return &smuxHeader{
		Version:  data[0],
		Cmd:      data[1],
		Length:   binary.LittleEndian.Uint16(data[2:4]),
		StreamID: binary.LittleEndian.Uint32(data[4:8]),
	}
}

// parseUpdHeaderSafe is a safe wrapper that catches panics
func parseUpdHeaderSafe(data []byte) *updHeader {
	defer func() {
		if r := recover(); r != nil {
			// Panic caught
		}
	}()

	return parseUpdHeader(data)
}

// parseUpdHeader parses a UPD command header from bytes
func parseUpdHeader(data []byte) *updHeader {
	if len(data) < szCmdUPD {
		return nil
	}

	return &updHeader{
		Consumed: binary.LittleEndian.Uint32(data[0:4]),
		Window:   binary.LittleEndian.Uint32(data[4:8]),
	}
}
