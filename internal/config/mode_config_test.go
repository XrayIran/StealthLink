package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetActiveMode tests the mode resolution logic.
func TestGetActiveMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		variant  string
		expected string
	}{
		{
			name:     "transport.mode takes precedence",
			mode:     "4b",
			variant:  "4a",
			expected: "4b",
		},
		{
			name:     "variant used when mode not set",
			mode:     "",
			variant:  "4c",
			expected: "4c",
		},
		{
			name:     "default to 4a when neither set",
			mode:     "",
			variant:  "",
			expected: "4a",
		},
		{
			name:     "transport.mode only",
			mode:     "4d",
			variant:  "",
			expected: "4d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Variant: tt.variant,
				Transport: Transport{
					Mode: tt.mode,
				},
			}
			assert.Equal(t, tt.expected, cfg.GetActiveMode())
		})
	}
}

// TestValidateMode tests mode validation.
func TestValidateMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		config  Transport
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid mode 4a",
			mode:    "4a",
			config:  Transport{Mode: "4a", Mode4a: DefaultMode4aConfig()},
			wantErr: false,
		},
		{
			name:    "valid mode 4b with shared secret",
			mode:    "4b",
			config:  Transport{Mode: "4b", Mode4b: Mode4bConfig{SharedSecret: "test", AEADMode: "chacha20poly1305", BatchSize: 32, TCPFingerprint: "linux"}},
			wantErr: false,
		},
		{
			name:    "valid mode 4c",
			mode:    "4c",
			config:  Transport{Mode: "4c", Mode4c: DefaultMode4cConfig()},
			wantErr: false,
		},
		{
			name:    "valid mode 4d",
			mode:    "4d",
			config:  Transport{Mode: "4d", Mode4d: DefaultMode4dConfig()},
			wantErr: false,
		},
		{
			name:    "valid mode 4e",
			mode:    "4e",
			config:  Transport{Mode: "4e", Mode4e: DefaultMode4eConfig()},
			wantErr: false,
		},
		{
			name:    "invalid mode",
			mode:    "invalid",
			config:  Transport{Mode: "invalid"},
			wantErr: true,
			errMsg:  "transport.mode must be one of: 4a, 4b, 4c, 4d, 4e",
		},
		{
			name:    "empty mode defaults to 4a",
			mode:    "",
			config:  Transport{Mode: "", Mode4a: DefaultMode4aConfig()},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Transport: tt.config,
			}
			err := cfg.ValidateMode()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateMode4a tests Mode 4a validation.
func TestValidateMode4a(t *testing.T) {
	tests := []struct {
		name    string
		config  Mode4aConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid default config",
			config:  DefaultMode4aConfig(),
			wantErr: false,
		},
		{
			name: "invalid session placement",
			config: Mode4aConfig{
				SessionPlacement:  "invalid",
				SessionKey:        "X-Session-ID",
				SequencePlacement: "header",
				SequenceKey:       "X-Seq",
				CMaxReuseTimes:    32,
				HMaxRequestTimes:  100,
				HMaxReusableSecs:  3600,
				DrainTimeout:      30 * time.Second,
			},
			wantErr: true,
			errMsg:  "session_placement must be one of: path, query, header, cookie",
		},
		{
			name: "invalid sequence placement",
			config: Mode4aConfig{
				SessionPlacement:  "header",
				SessionKey:        "X-Session-ID",
				SequencePlacement: "invalid",
				SequenceKey:       "X-Seq",
				CMaxReuseTimes:    32,
				HMaxRequestTimes:  100,
				HMaxReusableSecs:  3600,
				DrainTimeout:      30 * time.Second,
			},
			wantErr: true,
			errMsg:  "sequence_placement must be one of: path, query, header, cookie",
		},
		{
			name: "key collision",
			config: Mode4aConfig{
				SessionPlacement:  "header",
				SessionKey:        "X-ID",
				SequencePlacement: "header",
				SequenceKey:       "X-ID",
				CMaxReuseTimes:    32,
				HMaxRequestTimes:  100,
				HMaxReusableSecs:  3600,
				DrainTimeout:      30 * time.Second,
			},
			wantErr: true,
			errMsg:  "session_key and sequence_key cannot be the same",
		},
		{
			name: "same key different placement is valid",
			config: Mode4aConfig{
				SessionPlacement:  "header",
				SessionKey:        "id",
				SequencePlacement: "query",
				SequenceKey:       "id",
				CMaxReuseTimes:    32,
				HMaxRequestTimes:  100,
				HMaxReusableSecs:  3600,
				DrainTimeout:      30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "fronting enabled without fronting domain",
			config: Mode4aConfig{
				SessionPlacement:  "header",
				SessionKey:        "X-Session-ID",
				SequencePlacement: "header",
				SequenceKey:       "X-Seq",
				FrontingEnabled:   true,
				FrontingDomain:    "",
				TargetDomain:      "example.com",
				CMaxReuseTimes:    32,
				HMaxRequestTimes:  100,
				HMaxReusableSecs:  3600,
				DrainTimeout:      30 * time.Second,
			},
			wantErr: true,
			errMsg:  "fronting_domain is required when fronting_enabled is true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Transport: Transport{
					Mode:   "4a",
					Mode4a: tt.config,
				},
			}
			err := cfg.validateMode4a()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateMode4b tests Mode 4b validation.
func TestValidateMode4b(t *testing.T) {
	tests := []struct {
		name    string
		config  Mode4bConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with shared secret",
			config: Mode4bConfig{
				SharedSecret:   "test-secret",
				AEADMode:       "chacha20poly1305",
				BatchSize:      32,
				TCPFingerprint: "linux",
			},
			wantErr: false,
		},
		{
			name: "invalid aead mode",
			config: Mode4bConfig{
				AEADMode:       "invalid",
				BatchSize:      32,
				TCPFingerprint: "linux",
			},
			wantErr: true,
			errMsg:  "aead_mode must be one of: off, chacha20poly1305, aesgcm",
		},
		{
			name: "aead enabled without shared secret",
			config: Mode4bConfig{
				AEADMode:       "chacha20poly1305",
				SharedSecret:   "",
				BatchSize:      32,
				TCPFingerprint: "linux",
			},
			wantErr: true,
			errMsg:  "shared_secret is required when aead_mode is not 'off'",
		},
		{
			name: "invalid batch size too large",
			config: Mode4bConfig{
				AEADMode:       "off",
				BatchIOEnabled: true,
				BatchSize:      65,
				TCPFingerprint: "linux",
			},
			wantErr: true,
			errMsg:  "batch_size must be between 1 and 64",
		},
		{
			name: "invalid tcp fingerprint",
			config: Mode4bConfig{
				AEADMode:       "off",
				BatchSize:      32,
				TCPFingerprint: "invalid",
			},
			wantErr: true,
			errMsg:  "tcp_fingerprint must be one of: linux, windows, macos",
		},
		{
			name: "fragment enabled without size",
			config: Mode4bConfig{
				AEADMode:        "off",
				BatchSize:       32,
				TCPFingerprint:  "linux",
				FragmentEnabled: true,
				FragmentSize:    0,
			},
			wantErr: true,
			errMsg:  "fragment_size must be >= 1 when fragment_enabled is true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Transport: Transport{
					Mode:   "4b",
					Mode4b: tt.config,
				},
			}
			err := cfg.validateMode4b()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateMode4c tests Mode 4c validation.
func TestValidateMode4c(t *testing.T) {
	tests := []struct {
		name    string
		config  Mode4cConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid default config",
			config:  DefaultMode4cConfig(),
			wantErr: false,
		},
		{
			name: "invalid tls mode",
			config: Mode4cConfig{
				TLSMode:           "invalid",
				REALITYEnabled:    true,
				SpiderX:           "https://example.com",
				SpiderConcurrency: 4,
				SpiderTimeout:     10,
				MaxDepth:          3,
				MaxTotalFetches:   20,
				PerHostCap:        5,
			},
			wantErr: true,
			errMsg:  "tls_mode must be one of: reality, anytls",
		},
		{
			name: "invalid padding scheme",
			config: Mode4cConfig{
				TLSMode:            "anytls",
				AnyTLSEnabled:      true,
				PaddingScheme:      "invalid",
				PaddingMin:         100,
				PaddingMax:         900,
				IdleSessionTimeout: 300,
				SpiderX:            "https://example.com",
				REALITYEnabled:     false,
			},
			wantErr: true,
			errMsg:  "padding_scheme must be one of: random, fixed, burst, adaptive",
		},
		{
			name: "padding max less than min",
			config: Mode4cConfig{
				TLSMode:            "anytls",
				AnyTLSEnabled:      true,
				PaddingScheme:      "random",
				PaddingMin:         900,
				PaddingMax:         100,
				IdleSessionTimeout: 300,
				SpiderX:            "https://example.com",
				REALITYEnabled:     false,
			},
			wantErr: true,
			errMsg:  "padding_max must be >= padding_min",
		},
		{
			name: "neither reality nor anytls enabled",
			config: Mode4cConfig{
				TLSMode:        "reality",
				REALITYEnabled: false,
				AnyTLSEnabled:  false,
			},
			wantErr: true,
			errMsg:  "either reality_enabled or anytls_enabled must be true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Transport: Transport{
					Mode:   "4c",
					Mode4c: tt.config,
				},
			}
			err := cfg.validateMode4c()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateMode4d tests Mode 4d validation.
func TestValidateMode4d(t *testing.T) {
	tests := []struct {
		name    string
		config  Mode4dConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid default config",
			config:  DefaultMode4dConfig(),
			wantErr: false,
		},
		{
			name: "invalid data shards too small",
			config: Mode4dConfig{
				FECEnabled:   true,
				DataShards:   2,
				ParityShards: 3,
			},
			wantErr: true,
			errMsg:  "data_shards must be between 3 and 20",
		},
		{
			name: "invalid data shards too large",
			config: Mode4dConfig{
				FECEnabled:   true,
				DataShards:   21,
				ParityShards: 3,
			},
			wantErr: true,
			errMsg:  "data_shards must be between 3 and 20",
		},
		{
			name: "invalid batch size",
			config: Mode4dConfig{
				BatchIOEnabled: true,
				BatchSize:      100,
				DataShards:     10,
				ParityShards:   3,
			},
			wantErr: true,
			errMsg:  "batch_size must be between 1 and 64",
		},
		{
			name: "junk packets enabled without rate",
			config: Mode4dConfig{
				JunkPacketsEnabled: true,
				JunkPacketRate:     0,
				DataShards:         10,
				ParityShards:       3,
			},
			wantErr: true,
			errMsg:  "junk_packet_rate must be >= 1 when junk_packets_enabled is true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Transport: Transport{
					Mode:   "4d",
					Mode4d: tt.config,
				},
			}
			err := cfg.validateMode4d()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateMode4e tests Mode 4e validation.
func TestValidateMode4e(t *testing.T) {
	tests := []struct {
		name    string
		config  Mode4eConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid default config",
			config:  DefaultMode4eConfig(),
			wantErr: false,
		},
		{
			name: "invalid http version",
			config: Mode4eConfig{
				HTTPVersion: "http1",
			},
			wantErr: true,
			errMsg:  "http_version must be one of: http2, http3",
		},
		{
			name: "invalid icmp mux mode",
			config: Mode4eConfig{
				HTTPVersion:    "http2",
				ICMPMuxEnabled: true,
				ICMPMuxMode:    "invalid",
				CSTPPath:       "/tunnel",
			},
			wantErr: true,
			errMsg:  "icmp_mux_mode must be one of: echo, timestamp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Transport: Transport{
					Mode:   "4e",
					Mode4e: tt.config,
				},
			}
			err := cfg.validateMode4e()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGetModeConfig tests the mode-specific config getters with defaults.
func TestGetModeConfig(t *testing.T) {
	t.Run("GetMode4aConfig applies defaults", func(t *testing.T) {
		cfg := &Config{
			Transport: Transport{
				Mode: "4a",
				Mode4a: Mode4aConfig{
					SessionPlacement: "query",
					// Other fields left empty to test defaults
				},
			},
		}

		mode4a := cfg.GetMode4aConfig()
		assert.Equal(t, "query", mode4a.SessionPlacement)
		assert.Equal(t, "X-Session-ID", mode4a.SessionKey) // default
		assert.Equal(t, 32, mode4a.CMaxReuseTimes)         // default
	})

	t.Run("GetMode4bConfig applies defaults", func(t *testing.T) {
		cfg := &Config{
			Transport: Transport{
				Mode: "4b",
				Mode4b: Mode4bConfig{
					SharedSecret: "test-secret",
					// Other fields left empty to test defaults
				},
			},
		}

		mode4b := cfg.GetMode4bConfig()
		assert.Equal(t, "test-secret", mode4b.SharedSecret)
		assert.Equal(t, "chacha20poly1305", mode4b.AEADMode) // default
		assert.Equal(t, 32, mode4b.BatchSize)                // default
	})

	t.Run("GetMode4cConfig applies defaults", func(t *testing.T) {
		cfg := &Config{
			Transport: Transport{
				Mode: "4c",
				Mode4c: Mode4cConfig{
					REALITYEnabled: true,
					// Other fields left empty to test defaults
				},
			},
		}

		mode4c := cfg.GetMode4cConfig()
		assert.True(t, mode4c.REALITYEnabled)
		assert.Equal(t, "reality", mode4c.TLSMode)                 // default
		assert.Equal(t, "https://www.example.com", mode4c.SpiderX) // default
		assert.Equal(t, 4, mode4c.SpiderConcurrency)               // default
	})

	t.Run("GetMode4dConfig applies defaults", func(t *testing.T) {
		cfg := &Config{
			Transport: Transport{
				Mode: "4d",
				Mode4d: Mode4dConfig{
					BrutalEnabled: true,
					// Other fields left empty to test defaults
				},
			},
		}

		mode4d := cfg.GetMode4dConfig()
		assert.True(t, mode4d.BrutalEnabled)
		assert.Equal(t, 100, mode4d.BrutalBandwidth) // default
		assert.Equal(t, 10, mode4d.DataShards)       // default
		assert.Equal(t, 3, mode4d.ParityShards)      // default
	})

	t.Run("GetMode4eConfig applies defaults", func(t *testing.T) {
		cfg := &Config{
			Transport: Transport{
				Mode: "4e",
				Mode4e: Mode4eConfig{
					CSTPEnabled: true,
					// Other fields left empty to test defaults
				},
			},
		}

		mode4e := cfg.GetMode4eConfig()
		assert.True(t, mode4e.CSTPEnabled)
		assert.Equal(t, "http2", mode4e.HTTPVersion) // default
		assert.Equal(t, "/tunnel", mode4e.CSTPPath)  // default
		assert.Equal(t, "echo", mode4e.ICMPMuxMode)  // default
	})
}
