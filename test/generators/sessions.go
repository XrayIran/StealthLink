package generators

import (
	"pgregory.net/rapid"
)

// SessionID generates random session IDs for XHTTP testing.
// Session IDs are base64url-encoded strings with max length 128 bytes.
func SessionID() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9_-]{1,128}`)
}

// SequenceNumber generates random sequence numbers for XHTTP testing.
func SequenceNumber() *rapid.Generator[uint64] {
	return rapid.Uint64()
}

// ConnectionID generates random connection IDs for StealthLink frames.
func ConnectionID() *rapid.Generator[uint32] {
	return rapid.Uint32()
}

// StreamID generates random stream IDs for StealthLink frames.
func StreamID() *rapid.Generator[uint32] {
	return rapid.Uint32()
}
