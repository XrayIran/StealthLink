package generators

import (
	"pgregory.net/rapid"
)

// PacketType generates random packet types for StealthLink frames.
// Valid types: DATA=0x01, CONTROL=0x02, COVER=0x03
func PacketType() *rapid.Generator[byte] {
	return rapid.SampledFrom([]byte{0x01, 0x02, 0x03})
}

// PacketFlags generates random packet flags for StealthLink frames.
// Valid flags: RELIABLE=0x01, ENCRYPTED=0x02, COMPRESSED=0x04
func PacketFlags() *rapid.Generator[uint16] {
	return rapid.Uint16Range(0, 0x07) // Max combination of all flags
}

// Payload generates random packet payloads.
// Size range: 0-1400 bytes (typical MTU constraint)
func Payload() *rapid.Generator[[]byte] {
	return rapid.SliceOfN(rapid.Byte(), 0, 1400)
}

// PaddingLength generates random padding lengths.
// Range: 0-900 bytes (typical padding range)
func PaddingLength() *rapid.Generator[uint16] {
	return rapid.Uint16Range(0, 900)
}

// FakeTCPSequence generates random TCP sequence numbers for FakeTCP.
func FakeTCPSequence() *rapid.Generator[uint32] {
	return rapid.Uint32()
}

// FakeTCPAck generates random TCP acknowledgment numbers for FakeTCP.
func FakeTCPAck() *rapid.Generator[uint32] {
	return rapid.Uint32()
}

// FakeTCPWindow generates random TCP window sizes for FakeTCP.
func FakeTCPWindow() *rapid.Generator[uint16] {
	return rapid.Uint16()
}
