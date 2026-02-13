package rawtcp

import (
	"strings"
	"testing"
)

func TestBuildBPFFilterProfiles(t *testing.T) {
	cfg := &packetConfig{port: 443}

	tests := []struct {
		name    string
		profile string
		want    []string
		unwant  []string
	}{
		{
			name:    "basic",
			profile: "basic",
			want: []string{
				"tcp and dst port 443",
			},
		},
		{
			name:    "strict",
			profile: "strict",
			want: []string{
				"tcp and dst port 443",
				"tcp-push|tcp-ack",
			},
		},
		{
			name:    "stealth",
			profile: "stealth",
			want: []string{
				"tcp and dst port 443",
				"tcp-push|tcp-ack",
				"tcp-rst",
				"tcp-syn",
			},
			unwant: []string{
				"src port 443",
				"src port 80",
				"src port 8080",
				"src port 8443",
			},
		},
		{
			name:    "unknown falls back to basic",
			profile: "unknown",
			want: []string{
				"tcp and dst port 443",
			},
			unwant: []string{
				"tcp-push|tcp-ack",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg.bpfProfile = tc.profile
			got := buildBPFFilter(cfg)
			for _, s := range tc.want {
				if !strings.Contains(got, s) {
					t.Fatalf("filter=%q missing %q", got, s)
				}
			}
			for _, s := range tc.unwant {
				if strings.Contains(got, s) {
					t.Fatalf("filter=%q should not contain %q", got, s)
				}
			}
		})
	}
}
