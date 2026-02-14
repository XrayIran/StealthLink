package uqsp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/crypto/pqsig"
	"stealthlink/internal/transport/kcpbase"
	"stealthlink/internal/transport/noize"
	"stealthlink/internal/transport/obfs"
	"stealthlink/internal/transport/underlay"
	"stealthlink/internal/transport/uqsp/behavior"
	"stealthlink/internal/transport/uqsp/carrier"
	"stealthlink/internal/warp"

	"github.com/xtaci/smux"
)

type VariantBuilder struct {
	cfg       *config.Config
	tlsCfg    *tls.Config
	smuxCfg   *smux.Config
	authToken string
}

func NewVariantBuilder(cfg *config.Config, tlsCfg *tls.Config, smuxCfg *smux.Config, authToken string) *VariantBuilder {
	return &VariantBuilder{
		cfg:       cfg,
		tlsCfg:    tlsCfg,
		smuxCfg:   smuxCfg,
		authToken: authToken,
	}
}

func (b *VariantBuilder) Build(variant ProtocolVariant) (*UnifiedProtocol, error) {
	switch variant {
	case VariantXHTTP_TLS:
		return b.BuildVariantXHTTPTLS()
	case VariantRawTCP:
		return b.BuildVariantRawTCP()
	case VariantTLSMirror:
		return b.BuildVariantTLSMirror()
	case VariantUDP:
		return b.BuildVariantUDP()
	case VariantTrust:
		return b.BuildVariantTrust()
	default:
		return nil, fmt.Errorf("unknown variant: %d", variant)
	}
}

func (b *VariantBuilder) BuildVariantXHTTPTLS() (*UnifiedProtocol, error) {
	variantCfg := VariantConfig{
		Variant:       VariantXHTTP_TLS,
		TLSConfig:     b.tlsCfg,
		EnableWARP:    b.warpEnabledForVariant(VariantXHTTP_TLS),
		WARPConfig:    b.copyWARPConfig(),
		EnableReverse: b.reverseEnabledForVariant(VariantXHTTP_TLS),
		ReverseMode:   b.buildReverseMode(VariantXHTTP_TLS),
		Behaviors:     []behavior.Overlay{},
	}

	carrierType := b.cfg.Transport.UQSP.Carrier.Type
	if carrierType == "" {
		carrierType = "xhttp"
	}

	if carrierType != "xhttp" && carrierType != "quic" {
		carrierType = "xhttp"
	}

	carrierCfg := b.cfg.Transport.UQSP.Carrier
	if carrierCfg.Type == "" {
		carrierCfg.Type = carrierType
	}

	c, err := carrier.SelectCarrier(carrierCfg, b.tlsCfg, b.smuxCfg, b.authToken)
	if err != nil {
		if carrierType == "quic" || carrierType == "" {
			variantCfg.Carrier = buildVariantQUICCarrier(b.tlsCfg)
		} else {
			return nil, fmt.Errorf("select carrier: %w", err)
		}
	} else {
		if c == nil {
			if carrierType == "quic" {
				variantCfg.Carrier = buildVariantQUICCarrier(b.tlsCfg)
			} else {
				return nil, fmt.Errorf("carrier %q resolved to nil", carrierType)
			}
		} else {
			variantCfg.Carrier = c
		}
	}

	behaviorsCfg := b.cfg.Transport.UQSP.Behaviors

	if behaviorsCfg.ECH.Enabled {
		echOverlay := behavior.NewECHOverlay(behaviorsCfg.ECH)
		variantCfg.Behaviors = append(variantCfg.Behaviors, echOverlay)
	}

	// 4a baseline includes TLS-level anti-DPI resistance.
	variantCfg.Behaviors = append(variantCfg.Behaviors, behavior.NewGFWResistTLSOverlay())

	if behaviorsCfg.DomainFront.Enabled {
		dfOverlay := &behavior.DomainFrontOverlay{
			EnabledField:       behaviorsCfg.DomainFront.Enabled,
			FrontDomain:        behaviorsCfg.DomainFront.FrontDomain,
			RealHost:           behaviorsCfg.DomainFront.RealHost,
			RotateIPs:          behaviorsCfg.DomainFront.RotateIPs,
			CustomIPs:          behaviorsCfg.DomainFront.CustomIPs,
			PreserveHostHeader: behaviorsCfg.DomainFront.PreserveHostHeader,
		}
		variantCfg.Behaviors = append(variantCfg.Behaviors, dfOverlay)
	}

	if behaviorsCfg.Vision.Enabled {
		visionOverlay := &behavior.VisionOverlay{
			EnabledField:     behaviorsCfg.Vision.Enabled,
			FlowAutoDetect:   behaviorsCfg.Vision.FlowAutoDetect,
			AllowInsecure:    behaviorsCfg.Vision.AllowInsecure,
			BufferSize:       behaviorsCfg.Vision.BufferSize,
			DetectionTimeout: behaviorsCfg.Vision.DetectionTimeout,
		}
		variantCfg.Behaviors = append(variantCfg.Behaviors, visionOverlay)
	}

	if behaviorsCfg.TLSFrag.Enabled {
		tlsfragOverlay := &behavior.TLSFragOverlay{
			EnabledField: behaviorsCfg.TLSFrag.Enabled,
			Strategy:     behaviorsCfg.TLSFrag.Strategy,
			ChunkSize:    behaviorsCfg.TLSFrag.ChunkSize,
			MinDelay:     behaviorsCfg.TLSFrag.MinDelay,
			MaxDelay:     behaviorsCfg.TLSFrag.MaxDelay,
			Randomize:    behaviorsCfg.TLSFrag.Randomize,
		}
		variantCfg.Behaviors = append(variantCfg.Behaviors, tlsfragOverlay)
	}

	b.wireQPPAndViolatedTCP(&variantCfg)

	return NewUnifiedProtocol(variantCfg)
}

func (b *VariantBuilder) wireQPPAndViolatedTCP(variantCfg *VariantConfig) {
	behaviorsCfg := b.cfg.Transport.UQSP.Behaviors

	if behaviorsCfg.QPP.Enabled && behaviorsCfg.QPP.Key != "" {
		qppOverlay := behavior.NewQPPOverlay(behaviorsCfg.QPP)
		variantCfg.Behaviors = append(variantCfg.Behaviors, qppOverlay)
	}

	if behaviorsCfg.ViolatedTCP.Enabled {
		violatedTCPOverlay := behavior.NewViolatedTCPOverlay(behaviorsCfg.ViolatedTCP)
		variantCfg.Behaviors = append(variantCfg.Behaviors, violatedTCPOverlay)
	}
}

func (b *VariantBuilder) BuildVariantRawTCP() (*UnifiedProtocol, error) {
	variantCfg := VariantConfig{
		Variant:       VariantRawTCP,
		TLSConfig:     nil,
		EnableWARP:    b.warpEnabledForVariant(VariantRawTCP),
		WARPConfig:    b.copyWARPConfig(),
		EnableReverse: b.reverseEnabledForVariant(VariantRawTCP),
		ReverseMode:   b.buildReverseMode(VariantRawTCP),
		Behaviors:     []behavior.Overlay{},
	}

	carrierType := b.cfg.Transport.UQSP.Carrier.Type
	if carrierType == "" {
		carrierType = "rawtcp"
	}

	carrierCfg := b.cfg.Transport.UQSP.Carrier
	if carrierCfg.Type == "" {
		carrierCfg.Type = carrierType
	}
	c, err := carrier.SelectCarrier(carrierCfg, b.tlsCfg, b.smuxCfg, b.authToken)
	if err != nil {
		return nil, fmt.Errorf("select carrier: %w", err)
	}
	if c == nil {
		return nil, fmt.Errorf("carrier %q resolved to nil", carrierType)
	}
	variantCfg.Carrier = c

	behaviorsCfg := b.cfg.Transport.UQSP.Behaviors

	if behaviorsCfg.Obfs4.Enabled {
		obfs4Overlay := &behavior.Obfs4Overlay{
			EnabledField: behaviorsCfg.Obfs4.Enabled,
			NodeID:       behaviorsCfg.Obfs4.NodeID,
			PublicKey:    behaviorsCfg.Obfs4.PublicKey,
			PrivateKey:   behaviorsCfg.Obfs4.PrivateKey,
			Seed:         behaviorsCfg.Obfs4.Seed,
			IATMode:      behaviorsCfg.Obfs4.IATMode,
		}
		variantCfg.Behaviors = append(variantCfg.Behaviors, obfs4Overlay)
	}

	obfsCfg := b.cfg.Transport.UQSP.Obfuscation
	if obfsCfg.Profile != "none" {
		noizeOverlay := &NoizeOverlay{
			EnabledField:    obfsCfg.Profile != "none",
			PaddingMin:      obfsCfg.PaddingMin,
			PaddingMax:      obfsCfg.PaddingMax,
			TimingJitterMs:  obfsCfg.TimingJitterMs,
			MorphingEnabled: obfsCfg.MorphingEnabled,
		}
		variantCfg.Behaviors = append(variantCfg.Behaviors, noizeOverlay)
	}
	// 4b baseline includes TCP-level anti-DPI resistance.
	variantCfg.Behaviors = append(variantCfg.Behaviors, behavior.NewGFWResistTCPOverlay())

	if behaviorsCfg.AWG.Enabled {
		awgOverlay := behavior.NewAWGOverlay(behaviorsCfg.AWG)
		variantCfg.Behaviors = append(variantCfg.Behaviors, awgOverlay)
	}

	b.wireQPPAndViolatedTCP(&variantCfg)

	return NewUnifiedProtocol(variantCfg)
}

func (b *VariantBuilder) BuildVariantTLSMirror() (*UnifiedProtocol, error) {
	variantCfg := VariantConfig{
		Variant:       VariantTLSMirror,
		TLSConfig:     b.tlsCfg,
		EnableWARP:    b.warpEnabledForVariant(VariantTLSMirror),
		WARPConfig:    b.copyWARPConfig(),
		EnableReverse: b.reverseEnabledForVariant(VariantTLSMirror),
		ReverseMode:   b.buildReverseMode(VariantTLSMirror),
		Behaviors:     []behavior.Overlay{},
	}

	carrierType := b.cfg.Transport.UQSP.Carrier.Type
	if carrierType == "" {
		carrierType = "xhttp"
	}

	carrierCfg := b.cfg.Transport.UQSP.Carrier
	if carrierCfg.Type == "" {
		carrierCfg.Type = carrierType
	}
	c, err := carrier.SelectCarrier(carrierCfg, b.tlsCfg, b.smuxCfg, b.authToken)
	if err != nil {
		if carrierType == "quic" || carrierType == "" {
			variantCfg.Carrier = buildVariantQUICCarrier(b.tlsCfg)
		} else {
			return nil, fmt.Errorf("select carrier: %w", err)
		}
	} else {
		if c == nil {
			if carrierType == "quic" {
				variantCfg.Carrier = buildVariantQUICCarrier(b.tlsCfg)
			} else {
				return nil, fmt.Errorf("carrier %q resolved to nil", carrierType)
			}
		} else {
			variantCfg.Carrier = c
		}
	}

	behaviorsCfg := b.cfg.Transport.UQSP.Behaviors

	lookalikeCount := 0
	if behaviorsCfg.Reality.Enabled {
		realityOverlay := behavior.NewRealityOverlay(behaviorsCfg.Reality)
		variantCfg.Behaviors = append(variantCfg.Behaviors, realityOverlay)
		lookalikeCount++
	}
	if behaviorsCfg.ShadowTLS.Enabled {
		shadowOverlay := behavior.NewShadowTLSOverlay(behaviorsCfg.ShadowTLS)
		variantCfg.Behaviors = append(variantCfg.Behaviors, shadowOverlay)
		lookalikeCount++
	}
	if behaviorsCfg.TLSMirror.Enabled {
		mirrorOverlay := behavior.NewTLSMirrorOverlay(behaviorsCfg.TLSMirror)
		variantCfg.Behaviors = append(variantCfg.Behaviors, mirrorOverlay)
		lookalikeCount++
	}
	if behaviorsCfg.AnyTLS.Enabled {
		anyTLSOverlay := behavior.NewAnyTLSOverlay(behaviorsCfg.AnyTLS)
		variantCfg.Behaviors = append(variantCfg.Behaviors, anyTLSOverlay)
		lookalikeCount++
	}
	// If none is explicitly selected, default to TLSMirror to keep 4c semantics.
	if lookalikeCount == 0 {
		variantCfg.Behaviors = append(variantCfg.Behaviors, &behavior.TLSMirrorOverlay{
			EnabledField:       true,
			ControlChannel:     behaviorsCfg.TLSMirror.ControlChannel,
			EnrollmentRequired: behaviorsCfg.TLSMirror.EnrollmentRequired,
		})
	}

	if behaviorsCfg.Vision.Enabled {
		visionOverlay := &behavior.VisionOverlay{
			EnabledField:     behaviorsCfg.Vision.Enabled,
			FlowAutoDetect:   behaviorsCfg.Vision.FlowAutoDetect,
			AllowInsecure:    behaviorsCfg.Vision.AllowInsecure,
			BufferSize:       behaviorsCfg.Vision.BufferSize,
			DetectionTimeout: behaviorsCfg.Vision.DetectionTimeout,
		}
		variantCfg.Behaviors = append(variantCfg.Behaviors, visionOverlay)
	}

	if b.cfg.Transport.UQSP.Security.PQKEM {
		variantCfg.Behaviors = append(variantCfg.Behaviors, NewPQSigOverlayWithEnforce(b.cfg.Transport.UQSP.Security.PQEnforce))
	}

	b.wireQPPAndViolatedTCP(&variantCfg)

	return NewUnifiedProtocol(variantCfg)
}

func (b *VariantBuilder) BuildVariantUDP() (*UnifiedProtocol, error) {
	variantCfg := VariantConfig{
		Variant:       VariantUDP,
		TLSConfig:     b.tlsCfg,
		EnableWARP:    b.warpEnabledForVariant(VariantUDP),
		WARPConfig:    b.copyWARPConfig(),
		EnableReverse: b.reverseEnabledForVariant(VariantUDP),
		ReverseMode:   b.buildReverseMode(VariantUDP),
		Behaviors:     []behavior.Overlay{},
	}

	carrierType := b.cfg.Transport.UQSP.Carrier.Type
	if carrierType == "" {
		carrierType = "quic"
	}

	carrierCfg := b.cfg.Transport.UQSP.Carrier
	if carrierCfg.Type == "" {
		carrierCfg.Type = carrierType
	}
	c, err := carrier.SelectCarrier(carrierCfg, b.tlsCfg, b.smuxCfg, b.authToken)
	if err != nil {
		if carrierType == "quic" || carrierType == "" {
			variantCfg.Carrier = buildVariantQUICCarrier(b.tlsCfg)
		} else {
			return nil, fmt.Errorf("select carrier: %w", err)
		}
	} else {
		if c == nil {
			if carrierType == "quic" {
				variantCfg.Carrier = buildVariantQUICCarrier(b.tlsCfg)
			} else {
				return nil, fmt.Errorf("carrier %q resolved to nil", carrierType)
			}
		} else {
			variantCfg.Carrier = c
		}
	}

	behaviorsCfg := b.cfg.Transport.UQSP.Behaviors
	obfsCfg := b.cfg.Transport.UQSP.Obfuscation

	if (obfsCfg.Profile == "salamander" || obfsCfg.Profile == "adaptive") && obfsCfg.SalamanderKey != "" {
		salamanderOverlay := &SalamanderOverlay{
			EnabledField: true,
			Key:          obfsCfg.SalamanderKey,
		}
		variantCfg.Behaviors = append(variantCfg.Behaviors, salamanderOverlay)
	}

	if behaviorsCfg.AWG.Enabled {
		awgOverlay := behavior.NewAWGOverlay(behaviorsCfg.AWG)
		variantCfg.Behaviors = append(variantCfg.Behaviors, awgOverlay)
	}

	if obfsCfg.MorphingEnabled {
		morphOverlay := &MorphingOverlay{
			EnabledField: obfsCfg.MorphingEnabled,
			PaddingMin:   obfsCfg.PaddingMin,
			PaddingMax:   obfsCfg.PaddingMax,
		}
		variantCfg.Behaviors = append(variantCfg.Behaviors, morphOverlay)
	}

	b.wireQPPAndViolatedTCP(&variantCfg)

	return NewUnifiedProtocol(variantCfg)
}

func (b *VariantBuilder) BuildVariantTrust() (*UnifiedProtocol, error) {
	variantCfg := VariantConfig{
		Variant:       VariantTrust,
		TLSConfig:     b.tlsCfg,
		EnableWARP:    b.warpEnabledForVariant(VariantTrust),
		WARPConfig:    b.copyWARPConfig(),
		EnableReverse: b.reverseEnabledForVariant(VariantTrust),
		ReverseMode:   b.buildReverseMode(VariantTrust),
		Behaviors:     []behavior.Overlay{},
	}

	carrierType := b.cfg.Transport.UQSP.Carrier.Type
	if carrierType == "" {
		carrierType = "trusttunnel"
	}

	carrierCfg := b.cfg.Transport.UQSP.Carrier
	if carrierCfg.Type == "" {
		carrierCfg.Type = carrierType
	}
	c, err := carrier.SelectCarrier(carrierCfg, b.tlsCfg, b.smuxCfg, b.authToken)
	if err != nil {
		return nil, fmt.Errorf("select carrier: %w", err)
	}
	if c == nil {
		if carrierType == "quic" {
			c = buildVariantQUICCarrier(b.tlsCfg)
		} else {
			return nil, fmt.Errorf("carrier %q resolved to nil", carrierType)
		}
	}
	variantCfg.Carrier = c

	behaviorsCfg := b.cfg.Transport.UQSP.Behaviors

	if behaviorsCfg.TLSFrag.Enabled {
		tlsfragOverlay := &behavior.TLSFragOverlay{
			EnabledField: behaviorsCfg.TLSFrag.Enabled,
			Strategy:     behaviorsCfg.TLSFrag.Strategy,
			ChunkSize:    behaviorsCfg.TLSFrag.ChunkSize,
			MinDelay:     behaviorsCfg.TLSFrag.MinDelay,
			MaxDelay:     behaviorsCfg.TLSFrag.MaxDelay,
			Randomize:    behaviorsCfg.TLSFrag.Randomize,
		}
		variantCfg.Behaviors = append(variantCfg.Behaviors, tlsfragOverlay)
	}
	if behaviorsCfg.CSTP.Enabled {
		variantCfg.Behaviors = append(variantCfg.Behaviors, behavior.NewCSTPOverlay(behaviorsCfg.CSTP))
	}
	if behaviorsCfg.AnyTLS.Enabled {
		variantCfg.Behaviors = append(variantCfg.Behaviors, behavior.NewAnyTLSOverlay(behaviorsCfg.AnyTLS))
	}

	b.wireQPPAndViolatedTCP(&variantCfg)

	return NewUnifiedProtocol(variantCfg)
}

// variantPolicyKey maps a ProtocolVariant to its YAML config key.
func variantPolicyKey(v ProtocolVariant) string {
	switch v {
	case VariantXHTTP_TLS:
		return "4a"
	case VariantRawTCP:
		return "4b"
	case VariantTLSMirror:
		return "4c"
	case VariantUDP:
		return "4d"
	case VariantTrust:
		return "4e"
	default:
		return ""
	}
}

// warpEnabledForVariant checks per-variant policy, falling back to global WARP config.
func (b *VariantBuilder) warpEnabledForVariant(v ProtocolVariant) bool {
	return b.cfg.Transport.UQSP.WARPEnabledForVariant(variantPolicyKey(v), b.cfg.WARP.Enabled)
}

// reverseEnabledForVariant checks per-variant policy, falling back to global reverse config.
func (b *VariantBuilder) reverseEnabledForVariant(v ProtocolVariant) bool {
	return b.cfg.Transport.UQSP.ReverseEnabledForVariant(variantPolicyKey(v))
}

func (b *VariantBuilder) copyWARPConfig() *warp.Config {
	if b.cfg == nil {
		return nil
	}
	cp := b.cfg.WARP
	return &cp
}

func (b *VariantBuilder) buildReverseMode(variant ProtocolVariant) *ReverseMode {
	if b.cfg == nil || !b.reverseEnabledForVariant(variant) {
		return nil
	}
	rev := b.cfg.Transport.UQSP.Reverse
	mode := &ReverseMode{
		Enabled:           true,
		Role:              b.cfg.GetReverseRole(),
		ClientAddress:     rev.ClientAddress,
		ServerAddress:     rev.ServerAddress,
		HeartbeatInterval: rev.HeartbeatInterval,
		ReconnectDelay:    rev.ReconnectDelay,
		MaxRetries:        rev.MaxRetries,
		AuthToken:         rev.AuthToken,
		TLSConfig:         b.tlsCfg,
	}
	// HTTP registration improves reverse connectability behind CDNs.
	if variant == VariantXHTTP_TLS || variant == VariantTrust {
		mode.UseHTTPRegistration = true
		mode.RegistrationPath = "/_reverse_register"
	}
	return mode
}

func BuildVariantForRole(cfg *config.Config, tlsCfg *tls.Config, smuxCfg *smux.Config, authToken string) (*UnifiedProtocol, ProtocolVariant, error) {
	builder := NewVariantBuilder(cfg, tlsCfg, smuxCfg, authToken)

	variant := DetectVariant(cfg)

	proto, err := builder.Build(variant)
	if err != nil {
		return nil, variant, fmt.Errorf("build variant %s: %w", VariantName(variant), err)
	}

	// Underlay dialer is the single place we decide how TCP dials are made
	// (direct, WARP, SOCKS). Carriers that use tlsutil.DialUTLS will pick it up
	// via context injection in UnifiedProtocol.Dial.
	d, err := underlay.NewDialer(&cfg.Transport)
	if err != nil {
		_ = proto.Close()
		return nil, variant, fmt.Errorf("underlay dialer: %w", err)
	}
	proto.variant.UnderlayDialer = d

	// Enforce deterministic overlay execution order across all variants.
	proto.variant.Behaviors = behavior.SortBehaviors(proto.variant.Behaviors)

	// Validate carrier role capability: if this node is a listener (gateway),
	// ensure the carrier supports Listen.  Client-only carriers that cannot
	// listen will error immediately rather than at runtime.
	carrierType := effectiveCarrierType(cfg, variant)
	if cfg.Role == "gateway" || cfg.Role == "server" {
		if !proto.variant.EnableReverse && !carrier.SupportsListen(carrierType) {
			return nil, variant, fmt.Errorf("carrier %q does not support listen role; choose quic/trusttunnel/rawtcp/faketcp/icmptun/webtunnel or enable reverse mode", carrierType)
		}
	}
	if cfg.Role == "agent" || cfg.Role == "client" {
		if !carrier.SupportsDial(carrierType) {
			return nil, variant, fmt.Errorf("carrier %q does not support dial role", carrierType)
		}
	}

	return proto, variant, nil
}

func effectiveCarrierType(cfg *config.Config, variant ProtocolVariant) string {
	if cfg == nil {
		return "quic"
	}

	carrierType := strings.ToLower(strings.TrimSpace(cfg.Transport.UQSP.Carrier.Type))
	if carrierType != "" {
		return carrierType
	}

	switch variant {
	case VariantXHTTP_TLS:
		return "xhttp"
	case VariantRawTCP:
		return "rawtcp"
	case VariantTLSMirror:
		return "xhttp"
	case VariantUDP:
		return "quic"
	case VariantTrust:
		return "trusttunnel"
	default:
		return "quic"
	}
}

func DetectVariant(cfg *config.Config) ProtocolVariant {
	switch cfg.GetVariant() {
	case 0:
		return VariantXHTTP_TLS
	case 1:
		return VariantRawTCP
	case 2:
		return VariantTLSMirror
	case 3:
		return VariantUDP
	case 4:
		return VariantTrust
	default:
		return VariantUDP
	}
}

func VariantName(v ProtocolVariant) string {
	switch v {
	case VariantXHTTP_TLS:
		return "xhttp-tls"
	case VariantRawTCP:
		return "raw-tcp"
	case VariantTLSMirror:
		return "tls-mirror"
	case VariantUDP:
		return "udp"
	case VariantTrust:
		return "trust"
	default:
		return "unknown"
	}
}

func VariantFromName(name string) ProtocolVariant {
	switch name {
	case "xhttp-tls", "xhttp_tls", "4a":
		return VariantXHTTP_TLS
	case "raw-tcp", "raw_tcp", "4b":
		return VariantRawTCP
	case "tls-mirror", "tls_mirror", "4c":
		return VariantTLSMirror
	case "udp", "4d":
		return VariantUDP
	case "trust", "4e":
		return VariantTrust
	default:
		return VariantUDP
	}
}

func buildVariantQUICCarrier(tlsCfg *tls.Config) carrier.Carrier {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp"},
	}
	if tlsCfg != nil {
		cfg = tlsCfg.Clone()
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{"uqsp"}
		}
	}
	return carrier.NewQUICCarrier(cfg, nil)
}

type nativeQUICCarrier struct{}

func (c *nativeQUICCarrier) Network() string { return "quic" }
func (c *nativeQUICCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("native QUIC carrier requires special handling")
}
func (c *nativeQUICCarrier) Listen(addr string) (carrier.Listener, error) {
	return nil, fmt.Errorf("native QUIC carrier requires special handling")
}
func (c *nativeQUICCarrier) Close() error      { return nil }
func (c *nativeQUICCarrier) IsAvailable() bool { return true }

type VariantDialer struct {
	proto   *UnifiedProtocol
	variant ProtocolVariant
	addr    string
}

func NewVariantDialer(proto *UnifiedProtocol, variant ProtocolVariant, addr string) *VariantDialer {
	return &VariantDialer{
		proto:   proto,
		variant: variant,
		addr:    addr,
	}
}

func (d *VariantDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.proto.Dial(ctx, d.addr)
}

func (d *VariantDialer) Variant() ProtocolVariant {
	return d.variant
}

func (d *VariantDialer) VariantName() string {
	return VariantName(d.variant)
}

type NoizeOverlay struct {
	EnabledField    bool
	PaddingMin      int
	PaddingMax      int
	TimingJitterMs  int
	MorphingEnabled bool
}

func (o *NoizeOverlay) Name() string  { return "noize" }
func (o *NoizeOverlay) Enabled() bool { return o.EnabledField }
func (o *NoizeOverlay) Apply(conn net.Conn) (net.Conn, error) {
	cfg := noize.Config{
		Enabled:          true,
		Preset:           "medium",
		JunkMinSize:      o.PaddingMin,
		JunkMaxSize:      o.PaddingMax,
		Adaptive:         o.MorphingEnabled,
		SignaturePackets: []string{"https", "dns"},
	}
	n := noize.New(cfg)
	return &noizeConn{
		Conn:  conn,
		noize: n,
	}, nil
}

type SalamanderOverlay struct {
	EnabledField bool
	Key          string
}

func (o *SalamanderOverlay) Name() string  { return "salamander" }
func (o *SalamanderOverlay) Enabled() bool { return o.EnabledField }
func (o *SalamanderOverlay) Apply(conn net.Conn) (net.Conn, error) {
	return obfs.NewSalamanderConn(conn, o.Key)
}

type MorphingOverlay struct {
	EnabledField bool
	PaddingMin   int
	PaddingMax   int
}

func (o *MorphingOverlay) Name() string  { return "morphing" }
func (o *MorphingOverlay) Enabled() bool { return o.EnabledField }
func (o *MorphingOverlay) Apply(conn net.Conn) (net.Conn, error) {
	minPad := o.PaddingMin
	maxPad := o.PaddingMax
	if minPad < 0 {
		minPad = 0
	}
	if maxPad < minPad {
		maxPad = minPad
	}
	return &morphingConn{
		Conn:   conn,
		minPad: minPad,
		maxPad: maxPad,
	}, nil
}

type PQSigOverlay struct {
	enforce bool
}

func NewPQSigOverlay() *PQSigOverlay { return &PQSigOverlay{} }
func NewPQSigOverlayWithEnforce(enforce bool) *PQSigOverlay {
	return &PQSigOverlay{enforce: enforce}
}
func (o *PQSigOverlay) Name() string  { return "pqsig" }
func (o *PQSigOverlay) Enabled() bool { return true }
func (o *PQSigOverlay) Apply(conn net.Conn) (net.Conn, error) {
	return &pqSigConn{Conn: conn, enforce: o.enforce}, nil
}

type morphingConn struct {
	net.Conn
	minPad  int
	maxPad  int
	readBuf []byte
	mu      sync.Mutex
}

func (c *morphingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	padLen := c.minPad
	if c.maxPad > c.minPad {
		padLen += int(kcpbase.FastRandom.Int64n(int64(c.maxPad - c.minPad + 1)))
	}
	frame := make([]byte, 4+len(p)+padLen)
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(p)))
	binary.BigEndian.PutUint16(frame[2:4], uint16(padLen))
	copy(frame[4:], p)
	if padLen > 0 {
		kcpbase.FastRandom.Read(frame[4+len(p):])
	}
	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *morphingConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}
	payloadLen := int(binary.BigEndian.Uint16(header[:2]))
	padLen := int(binary.BigEndian.Uint16(header[2:4]))
	if payloadLen < 0 || padLen < 0 || payloadLen+padLen > 64*1024 {
		return 0, fmt.Errorf("invalid morphing frame")
	}
	frame := make([]byte, payloadLen+padLen)
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return 0, err
	}
	n := copy(p, frame[:payloadLen])
	if n < payloadLen {
		c.readBuf = append(c.readBuf, frame[n:payloadLen]...)
	}
	return n, nil
}

type pqSigConn struct {
	net.Conn
	once         sync.Once
	handshakeErr error
	enforce      bool
}

func (c *pqSigConn) Read(p []byte) (int, error) {
	if err := c.ensureHandshake(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *pqSigConn) Write(p []byte) (int, error) {
	if err := c.ensureHandshake(); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *pqSigConn) ensureHandshake() error {
	c.once.Do(func() {
		c.handshakeErr = c.handshake()
	})
	return c.handshakeErr
}

func (c *pqSigConn) handshake() error {
	keyPair, err := pqsig.GenerateMLDSA65KeyPair()
	if err != nil {
		return err
	}
	signer, err := pqsig.NewMLDSA65Signer(keyPair.PrivateKey)
	if err != nil {
		return err
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	sig, err := signer.Sign(nil, challenge, nil)
	if err != nil {
		return err
	}

	msg := make([]byte, 0, 4+2+2+len(challenge)+len(keyPair.PublicKey)+len(sig))
	msg = append(msg, 'P', 'Q', 'S', '1')
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(keyPair.PublicKey)))
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(sig)))
	msg = append(msg, challenge...)
	msg = append(msg, keyPair.PublicKey...)
	msg = append(msg, sig...)

	if err := c.Conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	defer c.Conn.SetDeadline(time.Time{})

	out := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
	out = append(out, msg...)
	if _, err := c.Conn.Write(out); err != nil {
		return err
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
		return err
	}
	peerLen := int(binary.BigEndian.Uint16(lenBuf))
	if peerLen < 40 {
		return fmt.Errorf("invalid PQ signature frame")
	}
	peer := make([]byte, peerLen)
	if _, err := io.ReadFull(c.Conn, peer); err != nil {
		return err
	}
	if string(peer[:4]) != "PQS1" {
		return fmt.Errorf("invalid PQ signature magic")
	}
	pubLen := int(binary.BigEndian.Uint16(peer[4:6]))
	sigLen := int(binary.BigEndian.Uint16(peer[6:8]))
	if 8+32+pubLen+sigLen != len(peer) {
		return fmt.Errorf("invalid PQ signature lengths")
	}
	peerChallenge := peer[8 : 8+32]
	peerPub := peer[8+32 : 8+32+pubLen]
	peerSig := peer[8+32+pubLen:]

	verifier, err := pqsig.NewMLDSA65Verifier(peerPub)
	if err != nil {
		return err
	}
	if err := verifier.Verify(peerChallenge, peerSig); err != nil {
		if c.enforce {
			return fmt.Errorf("PQ signature verification failed (enforced): %w", err)
		}
	}
	return nil
}

func secureRandInt(max int) int {
	if max <= 1 {
		return 0
	}
	return int(kcpbase.FastRandom.Int64n(int64(max)))
}

type noizeConn struct {
	net.Conn
	noize *noize.Noize
	once  sync.Once
	stop  sync.Once
}

func (c *noizeConn) ensureStarted() {
	c.once.Do(func() {
		if c.noize == nil {
			return
		}
		c.noize.Start(func(b []byte) error {
			_, err := c.Conn.Write(b)
			return err
		})
	})
}

func (c *noizeConn) Read(p []byte) (int, error) {
	c.ensureStarted()
	return c.Conn.Read(p)
}

func (c *noizeConn) Write(p []byte) (int, error) {
	c.ensureStarted()
	return c.Conn.Write(p)
}

func (c *noizeConn) Close() error {
	c.stop.Do(func() {
		if c.noize != nil {
			c.noize.Stop()
		}
	})
	return c.Conn.Close()
}
