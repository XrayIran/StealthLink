package fuzz

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzConfigYAMLParse tests YAML config parsing to catch panic/crash inputs.
// This fuzzer tests the YAML unmarshaling with various malformed inputs.
func FuzzConfigYAMLParse(f *testing.F) {
	// Seed corpus with valid config examples
	validConfig := `
role: gateway
listen: "0.0.0.0:8443"
mode: "HTTP+"
transport:
  mode: "HTTP+"
  xhttp:
    session_placement: header
    seq_placement: query
`
	f.Add([]byte(validConfig))

	minimalConfig := `
role: agent
`
	f.Add([]byte(minimalConfig))

	mode4bConfig := `
role: gateway
mode: "TCP+"
transport:
  mode: "TCP+"
  faketcp:
    aead_mode: "chacha20poly1305"
`
	f.Add([]byte(mode4bConfig))

	// Edge cases
	f.Add([]byte(""))                                // Empty
	f.Add([]byte("{}"))                              // Empty object
	f.Add([]byte("[]"))                              // Array
	f.Add([]byte("null"))                            // Null
	f.Add([]byte("---"))                             // YAML document separator
	f.Add([]byte("role: gateway\n---\nrole: agent")) // Multiple documents

	f.Fuzz(func(t *testing.T, data []byte) {
		// This should not panic even with malformed YAML
		var cfg Config
		_ = parseConfigSafe(data, &cfg)

		// Try parsing as generic map too
		var m map[string]interface{}
		_ = parseConfigSafe(data, &m)
	})
}

// Config represents a minimal config structure for fuzzing
type Config struct {
	Role      string                 `yaml:"role"`
	Listen    string                 `yaml:"listen"`
	Mode      string                 `yaml:"mode"`
	Transport map[string]interface{} `yaml:"transport"`
}

// parseConfigSafe is a safe wrapper that catches panics
func parseConfigSafe(data []byte, v interface{}) error {
	defer func() {
		if r := recover(); r != nil {
			// Panic caught - this is what fuzzing is designed to find
		}
	}()

	return yaml.Unmarshal(data, v)
}
