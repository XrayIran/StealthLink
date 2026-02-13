// Package main provides configuration migration CLI for StealthLink.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Set via -ldflags at build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

// Version represents the configuration schema version
type Version string

const (
	VersionLegacy Version = "legacy"
	VersionV1     Version = "v1"
	VersionV2     Version = "v2"
)

// LegacyConfig represents the legacy configuration format
type LegacyConfig struct {
	Server    string                 `yaml:"server,omitempty" json:"server,omitempty"`
	Port      int                    `yaml:"port,omitempty" json:"port,omitempty"`
	Password  string                 `yaml:"password,omitempty" json:"password,omitempty"`
	Method    string                 `yaml:"method,omitempty" json:"method,omitempty"`
	Transport map[string]interface{} `yaml:"transport,omitempty" json:"transport,omitempty"`
}

// V2Config represents the new consolidated configuration
type V2Config struct {
	Version   Version     `yaml:"version" json:"version"`
	Transport Transport   `yaml:"transport" json:"transport"`
	Security  Security    `yaml:"security" json:"security"`
	Routing   Routing     `yaml:"routing" json:"routing"`
}

// Transport configuration
type Transport struct {
	Stealth StealthConfig `yaml:"stealth" json:"stealth"`
}

// StealthConfig represents the unified stealth configuration
type StealthConfig struct {
	Enabled   bool        `yaml:"enabled" json:"enabled"`
	Graph     GraphConfig `yaml:"graph" json:"graph"`
	Carriers  []Carrier   `yaml:"carriers" json:"carriers"`
}

// GraphConfig represents the graph execution configuration
type GraphConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	Nodes        []Node   `yaml:"nodes" json:"nodes"`
	EntryPoints  []string `yaml:"entry_points" json:"entry_points"`
	ExitPoints   []string `yaml:"exit_points" json:"exit_points"`
}

// Node represents a graph node
type Node struct {
	Name   string            `yaml:"name" json:"name"`
	Type   string            `yaml:"type" json:"type"`
	Config map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
	Next   []string          `yaml:"next,omitempty" json:"next,omitempty"`
}

// Carrier represents a transport carrier
type Carrier struct {
	Name        string                 `yaml:"name" json:"name"`
	Type        string                 `yaml:"type" json:"type"`
	Config      map[string]interface{} `yaml:"config" json:"config"`
	Capabilities []string              `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

// Security configuration
type Security struct {
	ReplayProtection ReplayConfig `yaml:"replay_protection" json:"replay_protection"`
}

// ReplayConfig represents replay protection configuration
type ReplayConfig struct {
	Type   string `yaml:"type" json:"type"`
	Window int    `yaml:"window,omitempty" json:"window,omitempty"`
}

// Routing configuration
type Routing struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Rules   []Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// Rule represents a routing rule
type Rule struct {
	Name     string   `yaml:"name" json:"name"`
	Priority int      `yaml:"priority" json:"priority"`
	Matchers []string `yaml:"matchers" json:"matchers"`
	Action   string   `yaml:"action" json:"action"`
}

// Migrator handles configuration migration
type Migrator struct {
	inputPath  string
	outputPath string
}

// NewMigrator creates a new migrator
func NewMigrator(input, output string) *Migrator {
	return &Migrator{
		inputPath:  input,
		outputPath: output,
	}
}

// DetectVersion detects the configuration version
func (m *Migrator) DetectVersion(data []byte) Version {
	// Try to parse as V2 first
	var v2 V2Config
	if err := yaml.Unmarshal(data, &v2); err == nil {
		if v2.Version == VersionV2 || v2.Version == VersionV1 {
			return v2.Version
		}
	}

	// Try JSON
	if err := json.Unmarshal(data, &v2); err == nil {
		if v2.Version == VersionV2 || v2.Version == VersionV1 {
			return v2.Version
		}
	}

	return VersionLegacy
}

// Migrate migrates configuration to V2
func (m *Migrator) Migrate() error {
	// Read input
	data, err := os.ReadFile(m.inputPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	// Detect version
	version := m.DetectVersion(data)
	fmt.Printf("Detected config version: %s\n", version)

	if version == VersionV2 {
		fmt.Println("Config already at latest version")
		return m.copyIfNeeded(data)
	}

	// Parse legacy config
	var legacy LegacyConfig
	if err := yaml.Unmarshal(data, &legacy); err != nil {
		if err := json.Unmarshal(data, &legacy); err != nil {
			return fmt.Errorf("parse legacy config: %w", err)
		}
	}

	// Migrate to V2
	v2 := m.migrateLegacy(&legacy)

	// Write output
	output, err := yaml.Marshal(v2)
	if err != nil {
		return fmt.Errorf("marshal V2 config: %w", err)
	}

	// Add header
	header := "# StealthLink Configuration (v2)\n# Migrated from legacy format\n\n"
	output = append([]byte(header), output...)

	if err := os.WriteFile(m.outputPath, output, 0600); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Printf("Migrated config written to: %s\n", m.outputPath)
	return nil
}

// migrateLegacy migrates legacy config to V2
func (m *Migrator) migrateLegacy(legacy *LegacyConfig) *V2Config {
	v2 := &V2Config{
		Version: VersionV2,
		Transport: Transport{
			Stealth: StealthConfig{
				Enabled: true,
				Graph: GraphConfig{
					Enabled:     true,
					EntryPoints: []string{"entry"},
					ExitPoints:  []string{"exit"},
					Nodes: []Node{
						{
							Name: "entry",
							Type: "entry",
							Next: []string{"carrier"},
						},
						{
							Name: "carrier",
							Type: "carrier",
							Config: map[string]interface{}{
								"type": detectCarrierType(legacy.Transport),
							},
							Next: []string{"security"},
						},
						{
							Name: "security",
							Type: "security",
							Next: []string{"exit"},
						},
						{
							Name: "exit",
							Type: "exit",
						},
					},
				},
				Carriers: m.migrateCarriers(legacy.Transport),
			},
		},
		Security: Security{
			ReplayProtection: ReplayConfig{
				Type:   "hybrid",
				Window: 64,
			},
		},
		Routing: Routing{
			Enabled: false,
			Rules:   []Rule{},
		},
	}

	return v2
}

// migrateCarriers migrates carrier configuration
func (m *Migrator) migrateCarriers(transport map[string]interface{}) []Carrier {
	var carriers []Carrier

	if transport == nil {
		return carriers
	}

	// Check for known carrier types
	if tcp, ok := transport["tcp"].(map[string]interface{}); ok {
		carriers = append(carriers, Carrier{
			Name:   "tcp",
			Type:   "tcp",
			Config: tcp,
		})
	}

	if quic, ok := transport["quic"].(map[string]interface{}); ok {
		carriers = append(carriers, Carrier{
			Name:   "quic",
			Type:   "quic",
			Config: quic,
		})
	}

	if kcp, ok := transport["kcp"].(map[string]interface{}); ok {
		carriers = append(carriers, Carrier{
			Name:   "kcp",
			Type:   "kcp",
			Config: kcp,
		})
	}

	return carriers
}

// copyIfNeeded copies the file if output path differs from input
func (m *Migrator) copyIfNeeded(data []byte) error {
	if m.inputPath == m.outputPath {
		return nil
	}
	return os.WriteFile(m.outputPath, data, 0600)
}

// Validate validates a V2 configuration
func (m *Migrator) Validate() error {
	data, err := os.ReadFile(m.inputPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var v2 V2Config
	if err := yaml.Unmarshal(data, &v2); err != nil {
		if err := json.Unmarshal(data, &v2); err != nil {
			return fmt.Errorf("parse config: %w", err)
		}
	}

	if v2.Version != VersionV2 {
		return fmt.Errorf("config version is not v2: %s", v2.Version)
	}

	// Validate graph
	if v2.Transport.Stealth.Graph.Enabled {
		if err := m.validateGraph(&v2.Transport.Stealth.Graph); err != nil {
			return fmt.Errorf("graph validation: %w", err)
		}
	}

	// Validate carriers
	if len(v2.Transport.Stealth.Carriers) == 0 {
		return fmt.Errorf("no carriers defined")
	}

	fmt.Println("Configuration is valid (v2)")
	return nil
}

// validateGraph validates the graph configuration
func (m *Migrator) validateGraph(graph *GraphConfig) error {
	nodeMap := make(map[string]*Node)
	for i := range graph.Nodes {
		node := &graph.Nodes[i]
		if node.Name == "" {
			return fmt.Errorf("node at index %d has no name", i)
		}
		if _, exists := nodeMap[node.Name]; exists {
			return fmt.Errorf("duplicate node name: %s", node.Name)
		}
		nodeMap[node.Name] = node
	}

	// Check entry points exist
	for _, entry := range graph.EntryPoints {
		if _, ok := nodeMap[entry]; !ok {
			return fmt.Errorf("entry point not found: %s", entry)
		}
	}

	// Check exit points exist
	for _, exit := range graph.ExitPoints {
		if _, ok := nodeMap[exit]; !ok {
			return fmt.Errorf("exit point not found: %s", exit)
		}
	}

	// Check for cycles (simplified)
	visited := make(map[string]bool)
	recStack := make(map[string]bool)
	for _, node := range nodeMap {
		if !visited[node.Name] {
			if m.hasCycle(node, nodeMap, visited, recStack) {
				return fmt.Errorf("graph contains cycle")
			}
		}
	}

	return nil
}

// hasCycle detects cycles using DFS
func (m *Migrator) hasCycle(node *Node, nodes map[string]*Node, visited, recStack map[string]bool) bool {
	visited[node.Name] = true
	recStack[node.Name] = true

	for _, nextName := range node.Next {
		if next, ok := nodes[nextName]; ok {
			if !visited[nextName] {
				if m.hasCycle(next, nodes, visited, recStack) {
					return true
				}
			} else if recStack[nextName] {
				return true
			}
		}
	}

	recStack[node.Name] = false
	return false
}

// detectCarrierType detects the carrier type from legacy config
func detectCarrierType(transport map[string]interface{}) string {
	if transport == nil {
		return "tcp"
	}

	if _, ok := transport["quic"]; ok {
		return "quic"
	}
	if _, ok := transport["kcp"]; ok {
		return "kcp"
	}
	if _, ok := transport["rawtcp"]; ok {
		return "rawtcp"
	}

	return "tcp"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: stealthlink <command> [options]")
		fmt.Println("Commands:")
		fmt.Println("  version                   - Print version and exit")
		fmt.Println("  migrate <input> [output]  - Migrate config to v2")
		fmt.Println("  validate <config>         - Validate v2 config")
		fmt.Println("  detect <config>           - Detect config version")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "version":
		fmt.Printf("stealthlink %s (commit=%s built=%s)\n", version, commit, buildTime)
		return

	case "migrate":
		if len(os.Args) < 3 {
			fmt.Println("Usage: migrate migrate <input> [output]")
			os.Exit(1)
		}
		input := os.Args[2]
		output := input
		if len(os.Args) >= 4 {
			output = os.Args[3]
		} else {
			// Add .v2 suffix
			ext := filepath.Ext(input)
			output = strings.TrimSuffix(input, ext) + ".v2" + ext
		}

		m := NewMigrator(input, output)
		if err := m.Migrate(); err != nil {
			fmt.Fprintf(os.Stderr, "Migration failed: %v\n", err)
			os.Exit(1)
		}

	case "validate":
		if len(os.Args) < 3 {
			fmt.Println("Usage: migrate validate <config>")
			os.Exit(1)
		}
		input := os.Args[2]

		m := NewMigrator(input, input)
		if err := m.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Validation failed: %v\n", err)
			os.Exit(1)
		}

	case "detect":
		if len(os.Args) < 3 {
			fmt.Println("Usage: migrate detect <config>")
			os.Exit(1)
		}
		input := os.Args[2]

		data, err := os.ReadFile(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
			os.Exit(1)
		}

		m := NewMigrator(input, input)
		version := m.DetectVersion(data)
		fmt.Printf("Detected version: %s\n", version)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		os.Exit(1)
	}
}
