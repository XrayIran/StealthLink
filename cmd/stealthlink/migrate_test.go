package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMigrateLegacyConfigAndValidate(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "legacy.yaml")
	out := filepath.Join(tmp, "migrated.yaml")

	legacy := `server: "203.0.113.10"
port: 443
password: "secret"
method: "aes-256-gcm"
transport:
  tcp:
    nodelay: true
  quic:
    alpn: ["h3"]
  kcp:
    key: "kcp-key"
  rawtcp:
    interface: "eth0"
`
	if err := os.WriteFile(in, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	m := NewMigrator(in, out)
	if err := m.Migrate(); err != nil {
		t.Fatalf("Migrate() error: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read migrated config: %v", err)
	}

	var got V2Config
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal migrated config: %v", err)
	}

	if got.Version != VersionV2 {
		t.Fatalf("version = %q, want %q", got.Version, VersionV2)
	}
	if !got.Transport.Stealth.Enabled {
		t.Fatal("stealth should be enabled in migrated config")
	}
	if !got.Transport.Stealth.Graph.Enabled {
		t.Fatal("graph should be enabled in migrated config")
	}
	if len(got.Transport.Stealth.Carriers) != 3 {
		t.Fatalf("carrier count = %d, want 3 (tcp/quic/kcp)", len(got.Transport.Stealth.Carriers))
	}

	m2 := NewMigrator(out, out)
	if err := m2.Validate(); err != nil {
		t.Fatalf("Validate() on migrated config error: %v", err)
	}
}

func TestDetectVersionForCurrentExamples(t *testing.T) {
	cases := []string{
		"examples/uqsp-mode-4a.yaml",
		"examples/uqsp-mode-4b.yaml",
		"examples/uqsp-mode-4c.yaml",
		"examples/uqsp-mode-4d.yaml",
		"examples/uqsp-mode-4e.yaml",
	}

	m := NewMigrator("", "")
	for _, rel := range cases {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", rel))
			if err != nil {
				t.Fatalf("read example: %v", err)
			}

			// Current runtime examples are UQSP-native and intentionally not the
			// legacy migrator schema. DetectVersion should not mislabel them as v2.
			if got := m.DetectVersion(data); got != VersionLegacy {
				t.Fatalf("DetectVersion() = %q, want %q for %s", got, VersionLegacy, rel)
			}
		})
	}
}
