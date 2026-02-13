// Package uqsp — per-variant profile auto-tuning.
// ApplyVariantProfile normalizes config defaults based on the detected variant
// (4a–4e) so that each variant gets sensible overlay, congestion, and carrier
// settings without requiring the operator to configure every knob manually.
package uqsp

import (
	"log"
	"time"

	"stealthlink/internal/config"
)

// ApplyVariantProfile applies per-variant config defaults and optimizations.
// Call this before BuildVariantForRole so developers only need to set
// transport.type=uqsp and transport.uqsp.variant=N; the profile fills in
// reasonable defaults for overlays, carriers, congestion, and security.
func ApplyVariantProfile(cfg *config.Config) {
	variant := DetectVariant(cfg)
	switch variant {
	case VariantXHTTP_TLS:
		applyProfile4a(cfg)
	case VariantRawTCP:
		applyProfile4b(cfg)
	case VariantTLSMirror:
		applyProfile4c(cfg)
	case VariantUDP:
		applyProfile4d(cfg)
	case VariantTrust:
		applyProfile4e(cfg)
	}

	// Backward/interop-friendly mapping: allow AnyTLS password to live under behaviors.anytls.
	// Carrier implementations need the password to establish sessions.
	if cfg != nil && cfg.Transport.UQSP.Carrier.Type == "anytls" {
		if cfg.Transport.UQSP.Carrier.AnyTLS.Password == "" && cfg.Transport.UQSP.Behaviors.AnyTLS.Password != "" {
			cfg.Transport.UQSP.Carrier.AnyTLS.Password = cfg.Transport.UQSP.Behaviors.AnyTLS.Password
		}
	}
}

// 4a: XHTTP/TLS — CDN-friendly, anti-DPI baseline
func applyProfile4a(cfg *config.Config) {
	u := &cfg.Transport.UQSP

	// Default carrier: xhttp (SplitHTTP for CDN traversal)
	if u.Carrier.Type == "" {
		u.Carrier.Type = "xhttp"
	}

	// ECH enabled by default for 4a (Encrypted Client Hello)
	if !u.Behaviors.ECH.Enabled && u.Behaviors.ECH.PublicName != "" {
		u.Behaviors.ECH.Enabled = true
	}

	// GFW-resistant TLS fragmentation enabled by default
	if !u.Behaviors.TLSFrag.Enabled {
		u.Behaviors.TLSFrag.Enabled = true
		if u.Behaviors.TLSFrag.Strategy == "" {
			u.Behaviors.TLSFrag.Strategy = "sni_split"
		}
		if u.Behaviors.TLSFrag.ChunkSize == 0 {
			u.Behaviors.TLSFrag.ChunkSize = 40
		}
	}

	// Vision flow auto-detect enabled by default for clean TLS relay
	if !u.Behaviors.Vision.Enabled {
		u.Behaviors.Vision.Enabled = true
		u.Behaviors.Vision.FlowAutoDetect = true
		if u.Behaviors.Vision.BufferSize == 0 {
			u.Behaviors.Vision.BufferSize = 8192
		}
	}

	// Congestion: BBR adaptive by default
	if u.Congestion.Algorithm == "" {
		u.Congestion.Algorithm = "bbr"
	}

	// XMux Rotation limits (Requirement 2.1-2.4)
	if u.Carrier.XHTTP.XMux.Enabled {
		if u.Carrier.XHTTP.XMux.CMaxReuseTimes == 0 {
			u.Carrier.XHTTP.XMux.CMaxReuseTimes = 32
		}
		if u.Carrier.XHTTP.XMux.HMaxRequestTimes == 0 {
			u.Carrier.XHTTP.XMux.HMaxRequestTimes = 100
		}
		if u.Carrier.XHTTP.XMux.HMaxReusableSecs == 0 {
			u.Carrier.XHTTP.XMux.HMaxReusableSecs = 3600
		}
		if u.Carrier.XHTTP.XMux.DrainTimeout == "" {
			u.Carrier.XHTTP.XMux.DrainTimeout = "30s"
		}
	}

	log.Printf("variant 4a profile applied: carrier=%s ech=%t tls_frag=%t vision=%t",
		u.Carrier.Type, u.Behaviors.ECH.Enabled, u.Behaviors.TLSFrag.Enabled, u.Behaviors.Vision.Enabled)
}

// 4b: RawTCP — obfs4/noize for heavily censored environments
func applyProfile4b(cfg *config.Config) {
	u := &cfg.Transport.UQSP

	// Default carrier: rawtcp
	if u.Carrier.Type == "" {
		u.Carrier.Type = "rawtcp"
	}

	// obfs4 enabled by default if node_id or seed is present
	if !u.Behaviors.Obfs4.Enabled {
		if u.Behaviors.Obfs4.NodeID != "" || u.Behaviors.Obfs4.Seed != "" {
			u.Behaviors.Obfs4.Enabled = true
		}
	}

	// Derive default IAT mode: paranoid (2) for max anti-fingerprinting
	if u.Behaviors.Obfs4.Enabled && u.Behaviors.Obfs4.IATMode == 0 {
		u.Behaviors.Obfs4.IATMode = 2
	}

	// Noize obfuscation enabled by default with adaptive profile
	if u.Obfuscation.Profile == "" {
		u.Obfuscation.Profile = "adaptive"
		u.Obfuscation.MorphingEnabled = true
	}

	// AWG junk padding provides additional fingerprint resistance
	if !u.Behaviors.AWG.Enabled {
		u.Behaviors.AWG.Enabled = true
		if u.Behaviors.AWG.JunkInterval == 0 {
			u.Behaviors.AWG.JunkInterval = 3 * time.Second
		}
	}

	log.Printf("variant 4b profile applied: carrier=%s obfs4=%t iat=%d awg=%t",
		u.Carrier.Type, u.Behaviors.Obfs4.Enabled, u.Behaviors.Obfs4.IATMode, u.Behaviors.AWG.Enabled)
}

// 4c: TLSMirror — lookalike TLS with Reality/ShadowTLS/Mirror overlays
func applyProfile4c(cfg *config.Config) {
	u := &cfg.Transport.UQSP

	// Default carrier: xhttp for CDN compatibility
	if u.Carrier.Type == "" {
		u.Carrier.Type = "xhttp"
	}

	// If no lookalike overlay is explicitly set, enable TLSMirror as default
	hasLookalike := u.Behaviors.Reality.Enabled ||
		u.Behaviors.ShadowTLS.Enabled ||
		u.Behaviors.TLSMirror.Enabled ||
		u.Behaviors.AnyTLS.Enabled
	if !hasLookalike {
		// Prefer AnyTLS when password is available; otherwise keep TLSMirror fallback.
		if u.Behaviors.AnyTLS.Password != "" {
			u.Behaviors.AnyTLS.Enabled = true
		} else {
			u.Behaviors.TLSMirror.Enabled = true
		}
	}

	// Validate Reality keys are present when Reality is enabled
	if u.Behaviors.Reality.Enabled {
		if u.Behaviors.Reality.PrivateKey == "" && u.Behaviors.Reality.ServerPublicKey == "" {
			log.Printf("WARNING: variant 4c Reality overlay enabled but no keys configured")
		}
		if len(u.Behaviors.Reality.ServerNames) == 0 && u.Behaviors.Reality.Dest != "" {
			u.Behaviors.Reality.ServerNames = []string{u.Behaviors.Reality.Dest}
		}
	}

	// Validate ShadowTLS password
	if u.Behaviors.ShadowTLS.Enabled {
		if u.Behaviors.ShadowTLS.Version == 0 {
			u.Behaviors.ShadowTLS.Version = 3 // default to latest version
		}
		if u.Behaviors.ShadowTLS.Password == "" {
			log.Printf("WARNING: variant 4c ShadowTLS overlay enabled but no password configured")
		}
	}

	// PQ signature overlay for 4c when pq_kem is enabled
	if u.Security.PQKEM {
		log.Printf("variant 4c: PQKEM enabled, post-quantum signature overlay active")
	}

	// XMux Rotation limits (Requirement 2.1-2.4)
	if u.Carrier.XHTTP.XMux.Enabled {
		if u.Carrier.XHTTP.XMux.CMaxReuseTimes == 0 {
			u.Carrier.XHTTP.XMux.CMaxReuseTimes = 32
		}
		if u.Carrier.XHTTP.XMux.HMaxRequestTimes == 0 {
			u.Carrier.XHTTP.XMux.HMaxRequestTimes = 100
		}
		if u.Carrier.XHTTP.XMux.HMaxReusableSecs == 0 {
			u.Carrier.XHTTP.XMux.HMaxReusableSecs = 3600
		}
		if u.Carrier.XHTTP.XMux.DrainTimeout == "" {
			u.Carrier.XHTTP.XMux.DrainTimeout = "30s"
		}
	}

	log.Printf("variant 4c profile applied: carrier=%s reality=%t shadowtls=%t tlsmirror=%t anytls=%t pq=%t",
		u.Carrier.Type, u.Behaviors.Reality.Enabled, u.Behaviors.ShadowTLS.Enabled,
		u.Behaviors.TLSMirror.Enabled, u.Behaviors.AnyTLS.Enabled, u.Security.PQKEM)
}

// 4d: UDP/QUIC — native datagram support, high-throughput
func applyProfile4d(cfg *config.Config) {
	u := &cfg.Transport.UQSP

	// Default carrier: native QUIC
	if u.Carrier.Type == "" {
		u.Carrier.Type = "quic"
	}

	// Enable connect-udp and connect-ip capsules by default
	if !u.Capsules.ConnectUDP {
		u.Capsules.ConnectUDP = true
	}
	if !u.Capsules.ConnectIP {
		u.Capsules.ConnectIP = true
	}

	// Datagram relay: native by default for lowest latency
	if u.Datagrams.RelayMode == "" {
		u.Datagrams.RelayMode = "native"
	}

	// Congestion: brutal by default for 4d (throughput-optimized)
	if u.Congestion.Algorithm == "" {
		u.Congestion.Algorithm = "brutal"
		u.Congestion.Pacing = "aggressive"
	}
	if u.Congestion.Algorithm == "brutal" && u.Congestion.BandwidthMbps == 0 {
		u.Congestion.BandwidthMbps = 200
	}

	// Salamander obfuscation for UDP
	if u.Obfuscation.Profile == "" && u.Obfuscation.SalamanderKey != "" {
		u.Obfuscation.Profile = "salamander"
	}

	log.Printf("variant 4d profile applied: carrier=%s capsules_udp=%t capsules_ip=%t cc=%s/%s bw=%dMbps",
		u.Carrier.Type, u.Capsules.ConnectUDP, u.Capsules.ConnectIP,
		u.Congestion.Algorithm, u.Congestion.Pacing, u.Congestion.BandwidthMbps)
}

// 4e: Trust — maximum stealth behind CDN with CSTP keepalive
func applyProfile4e(cfg *config.Config) {
	u := &cfg.Transport.UQSP

	// Default carrier: trusttunnel (in-core HTTP/2+HTTP/3 tunnel)
	if u.Carrier.Type == "" {
		u.Carrier.Type = "trusttunnel"
	}

	// CSTP framing enabled by default for 4e
	if !u.Behaviors.CSTP.Enabled {
		u.Behaviors.CSTP.Enabled = true
		if u.Behaviors.CSTP.DPDInterval == 0 {
			u.Behaviors.CSTP.DPDInterval = 15 * time.Second
		}
		if u.Behaviors.CSTP.MTU == 0 {
			u.Behaviors.CSTP.MTU = 1360
		}
	}
	// AnyTLS is an optional TLS-profile hardening layer in 4e.
	if !u.Behaviors.AnyTLS.Enabled && u.Behaviors.AnyTLS.Password != "" {
		u.Behaviors.AnyTLS.Enabled = true
	}
	if u.Behaviors.AnyTLS.Enabled && u.Behaviors.AnyTLS.PaddingMax == 0 {
		u.Behaviors.AnyTLS.PaddingMin = 8
		u.Behaviors.AnyTLS.PaddingMax = 64
	}

	// TLS fragmentation for CDN/GFW traversal
	if !u.Behaviors.TLSFrag.Enabled {
		u.Behaviors.TLSFrag.Enabled = true
		if u.Behaviors.TLSFrag.Strategy == "" {
			u.Behaviors.TLSFrag.Strategy = "sni_split"
		}
		if u.Behaviors.TLSFrag.ChunkSize == 0 {
			u.Behaviors.TLSFrag.ChunkSize = 40
		}
	}

	// Reverse mode + WARP are the default template for 4e
	if !u.Reverse.Enabled && cfg.WARP.Enabled {
		log.Printf("variant 4e: WARP enabled, consider enabling reverse mode for full-stealth")
	}

	log.Printf("variant 4e profile applied: carrier=%s cstp=%t tls_frag=%t anytls=%t reverse=%t warp=%t",
		u.Carrier.Type, u.Behaviors.CSTP.Enabled, u.Behaviors.TLSFrag.Enabled,
		u.Behaviors.AnyTLS.Enabled, u.Reverse.Enabled, cfg.WARP.Enabled)
}
