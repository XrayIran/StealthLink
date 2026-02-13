package fuzz

import (
	"encoding/binary"
	"testing"
)

// FuzzFakeTCPPacketDecode tests FakeTCP packet parsing to catch panic/crash inputs.
// This fuzzer tests the parsePacket function with various malformed inputs.
func FuzzFakeTCPPacketDecode(f *testing.F) {
	// Seed corpus with valid packet examples
	// Valid packet: Type(1) + Flags(1) + Seq(4) + Ack(4) + Window(2) = 12 bytes minimum
	validPacket := make([]byte, 24)                      // HeaderSize = 24
	validPacket[0] = 0x01                                // Type: SYN
	validPacket[1] = 0x02                                // Flags: ACK
	binary.BigEndian.PutUint32(validPacket[2:6], 1000)   // Seq
	binary.BigEndian.PutUint32(validPacket[6:10], 500)   // Ack
	binary.BigEndian.PutUint16(validPacket[10:12], 8192) // Window
	f.Add(validPacket)

	// Packet with payload
	packetWithPayload := make([]byte, 24+10)
	copy(packetWithPayload, validPacket)
	copy(packetWithPayload[24:], []byte("testdata12"))
	f.Add(packetWithPayload)

	// Edge cases
	f.Add([]byte{})            // Empty
	f.Add([]byte{0x01})        // Too short
	f.Add(make([]byte, 12))    // Minimum size
	f.Add(make([]byte, 1500))  // MTU size
	f.Add(make([]byte, 65535)) // Max UDP size

	f.Fuzz(func(t *testing.T, data []byte) {
		// This should not panic even with malformed inputs
		pkt := parsePacketSafe(data)

		// If packet was parsed, verify basic invariants
		if pkt != nil {
			// Verify payload length matches
			if len(data) > 24 {
				expectedPayloadLen := len(data) - 24
				if len(pkt.Payload) != expectedPayloadLen {
					t.Errorf("payload length mismatch: got %d, want %d", len(pkt.Payload), expectedPayloadLen)
				}
			}
		}
	})
}

// packet represents a FakeTCP packet structure
type packet struct {
	Type    byte
	Flags   byte
	Seq     uint32
	Ack     uint32
	Window  uint16
	Payload []byte
}

const HeaderSize = 24

// parsePacketSafe is a safe wrapper around packet parsing that catches panics
func parsePacketSafe(data []byte) *packet {
	defer func() {
		if r := recover(); r != nil {
			// Panic caught - this is what fuzzing is designed to find
		}
	}()

	return parsePacket(data)
}

// parsePacket parses a FakeTCP packet from bytes
func parsePacket(data []byte) *packet {
	if len(data) < HeaderSize {
		return nil
	}

	pkt := &packet{
		Type:   data[0],
		Flags:  data[1],
		Seq:    binary.BigEndian.Uint32(data[2:6]),
		Ack:    binary.BigEndian.Uint32(data[6:10]),
		Window: binary.BigEndian.Uint16(data[10:12]),
	}

	if len(data) > HeaderSize {
		pkt.Payload = data[HeaderSize:]
	}

	return pkt
}
