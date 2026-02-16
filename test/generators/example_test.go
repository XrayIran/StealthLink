package generators_test

import (
	"testing"

	"stealthlink/test/generators"

	"pgregory.net/rapid"
)

// TestProperty_SessionIDFormat verifies that generated session IDs are valid.
// **Validates: Requirements 1.1, 1.11**
//
// Property: All generated session IDs must be valid base64url strings with length <= 128 bytes.
func TestProperty_SessionIDFormat(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sessionID := generators.SessionID().Draw(t, "sessionID")

		// Property: Session ID must not be empty
		if len(sessionID) == 0 {
			t.Fatalf("session ID must not be empty")
		}

		// Property: Session ID must not exceed 128 bytes
		if len(sessionID) > 128 {
			t.Fatalf("session ID length %d exceeds maximum 128 bytes", len(sessionID))
		}

		// Property: Session ID must only contain base64url characters
		for _, c := range sessionID {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') || c == '_' || c == '-') {
				t.Fatalf("session ID contains invalid character: %c", c)
			}
		}
	})
}

// TestProperty_PacketTypeValidity verifies that generated packet types are valid.
// **Validates: Design Section 2.2 (StealthLink Frame Format)**
//
// Property: All generated packet types must be one of: DATA=0x01, CONTROL=0x02, COVER=0x03.
func TestProperty_PacketTypeValidity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pktType := generators.PacketType().Draw(t, "packetType")

		// Property: Packet type must be one of the valid types
		validTypes := map[byte]bool{0x01: true, 0x02: true, 0x03: true}
		if !validTypes[pktType] {
			t.Fatalf("invalid packet type: 0x%02x", pktType)
		}
	})
}

// TestProperty_PayloadSizeConstraint verifies that generated payloads respect MTU constraints.
// **Validates: Design Section 2.1 (MTU Strategy)**
//
// Property: All generated payloads must not exceed 1400 bytes (typical MTU constraint).
func TestProperty_PayloadSizeConstraint(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		payload := generators.Payload().Draw(t, "payload")

		// Property: Payload must not exceed 1400 bytes
		if len(payload) > 1400 {
			t.Fatalf("payload size %d exceeds maximum 1400 bytes", len(payload))
		}
	})
}

// TestProperty_ModeValidity verifies that generated modes are valid.
// **Validates: Design Section 2.3 (Mode Profiles)**
//
// Property: All generated modes must be one of: 4a, 4b, 4c, 4d, 4e.
func TestProperty_ModeValidity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mode := generators.Mode().Draw(t, "mode")

		// Property: Mode must be one of the valid modes
		validModes := map[string]bool{
			"HTTP+": true, "TCP+": true, "TLS+": true, "UDP+": true, "TLS": true,
		}
		if !validModes[mode] {
			t.Fatalf("invalid mode: %s", mode)
		}
	})
}

// TestProperty_BatchSizeRange verifies that generated batch sizes are within valid range.
// **Validates: Requirements 3.9**
//
// Property: All generated batch sizes must be in range [1, 64].
func TestProperty_BatchSizeRange(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		batchSize := generators.BatchSize().Draw(t, "batchSize")

		// Property: Batch size must be at least 1
		if batchSize < 1 {
			t.Fatalf("batch size %d is less than minimum 1", batchSize)
		}

		// Property: Batch size must not exceed 64
		if batchSize > 64 {
			t.Fatalf("batch size %d exceeds maximum 64", batchSize)
		}
	})
}

// TestProperty_UtilizationRange verifies that generated utilization values are valid.
// **Validates: Requirements 12.4**
//
// Property: All generated utilization values must be in range [0.0, 1.0].
func TestProperty_UtilizationRange(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		utilization := generators.Utilization().Draw(t, "utilization")

		// Property: Utilization must be non-negative
		if utilization < 0.0 {
			t.Fatalf("utilization %f is negative", utilization)
		}

		// Property: Utilization must not exceed 1.0
		if utilization > 1.0 {
			t.Fatalf("utilization %f exceeds maximum 1.0", utilization)
		}
	})
}
