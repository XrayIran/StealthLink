package generators

import (
	"pgregory.net/rapid"
)

// Mode generates random StealthLink mode identifiers.
// Valid modes: 4a, 4b, 4c, 4d, 4e
func Mode() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{"HTTP+", "TCP+", "TLS+", "UDP+", "TLS"})
}

// Placement generates random XHTTP placement types.
// Valid placements: path, query, header, cookie
func Placement() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{"path", "query", "header", "cookie"})
}

// AEADMode generates random AEAD encryption modes for FakeTCP.
// Valid modes: off, chacha20poly1305, aesgcm
func AEADMode() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{"off", "chacha20poly1305", "aesgcm"})
}

// PaddingScheme generates random padding schemes for AnyTLS.
// Valid schemes: random, fixed, burst, adaptive
func PaddingScheme() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{"random", "fixed", "burst", "adaptive"})
}

// BatchSize generates random batch sizes for batch I/O.
// Range: 1-64 (as specified in requirements)
func BatchSize() *rapid.Generator[int] {
	return rapid.IntRange(1, 64)
}

// PoolSize generates random connection pool sizes.
// Range: 2-32 (min to max pool size)
func PoolSize() *rapid.Generator[int] {
	return rapid.IntRange(2, 32)
}

// Utilization generates random connection pool utilization values.
// Range: 0.0-1.0
func Utilization() *rapid.Generator[float64] {
	return rapid.Float64Range(0.0, 1.0)
}

// PoolMode generates random connection pool modes.
// Valid modes: normal, aggressive
func PoolMode() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{"normal", "aggressive"})
}

// CryptoKey generates random cryptographic keys.
// Size: 32 bytes (for ChaCha20-Poly1305)
func CryptoKey() *rapid.Generator[[]byte] {
	return rapid.SliceOfN(rapid.Byte(), 32, 32)
}

// CryptoKey16 generates random 16-byte cryptographic keys.
// Size: 16 bytes (for AES-128-GCM)
func CryptoKey16() *rapid.Generator[[]byte] {
	return rapid.SliceOfN(rapid.Byte(), 16, 16)
}

// SharedSecret generates random shared secrets for key derivation.
// Size: 1-256 bytes
func SharedSecret() *rapid.Generator[[]byte] {
	return rapid.SliceOfN(rapid.Byte(), 1, 256)
}
