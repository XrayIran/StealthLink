package h2mux

import (
	"stealthlink/internal/transport/padding"
)

// padBody returns a slice of n random bytes between min and max inclusive.
// Deprecated: Use padding.XPaddingConfig instead.
func padBody(min, max int) []byte {
	cfg := padding.XPaddingConfig{
		Enabled: true,
		Min:     min,
		Max:     max,
		Method:  padding.MethodRandom,
	}
	return cfg.Generate()
}

// padHeaderValue returns a base64-encoded padding value.
// Deprecated: Use padding.XPaddingConfig.GenerateString() instead.
func padHeaderValue(min, max int) string {
	cfg := padding.XPaddingConfig{
		Enabled: true,
		Min:     min,
		Max:     max,
		Method:  padding.MethodRandom,
	}
	return cfg.GenerateString()
}

// newPaddingConfig creates an XPaddingConfig from min/max values.
func newPaddingConfig(min, max int, method padding.XPaddingMethod) *padding.XPaddingConfig {
	if method == "" {
		method = padding.MethodRandom
	}
	return &padding.XPaddingConfig{
		Enabled:   max > 0,
		Min:       min,
		Max:       max,
		Method:    method,
		Placement: padding.PlaceHeader,
	}
}

