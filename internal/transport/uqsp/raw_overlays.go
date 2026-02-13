package uqsp

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"stealthlink/internal/config"
	"stealthlink/internal/transport/uqsp/behavior"
)

func isRawCarrierType(carrierType string) bool {
	switch strings.ToLower(strings.TrimSpace(carrierType)) {
	case "rawtcp", "faketcp", "icmptun":
		return true
	default:
		return false
	}
}

func (d *Dialer) applyCarrierOverlays(conn net.Conn, serverMode bool) (net.Conn, error) {
	return applyCarrierOverlays(conn, d.Config, d.AuthToken, serverMode)
}

func (l *Listener) applyCarrierOverlays(conn net.Conn, serverMode bool) (net.Conn, error) {
	return applyCarrierOverlays(conn, l.Config, l.AuthToken, serverMode)
}

func applyCarrierOverlays(conn net.Conn, cfg *config.UQSPConfig, authToken string, serverMode bool) (net.Conn, error) {
	if conn == nil || cfg == nil || !isRawCarrierType(cfg.Carrier.Type) {
		return conn, nil
	}
	overlays, err := buildRawCarrierOverlays(cfg, authToken, serverMode)
	if err != nil {
		return nil, err
	}
	for _, overlay := range overlays {
		if overlay == nil || !overlay.Enabled() {
			continue
		}
		conn, err = overlay.Apply(conn)
		if err != nil {
			return nil, fmt.Errorf("apply overlay %s: %w", overlay.Name(), err)
		}
	}
	return conn, nil
}

func buildRawCarrierOverlays(cfg *config.UQSPConfig, authToken string, serverMode bool) ([]behavior.Overlay, error) {
	overlays := make([]behavior.Overlay, 0, 4)
	behaviors := cfg.Behaviors
	obfsCfg := cfg.Obfuscation

	if behaviors.Obfs4.Enabled {
		resolved := behaviors.Obfs4
		applyObfs4DerivedDefaults(&resolved, authToken)
		obfs4Overlay := &behavior.Obfs4Overlay{
			EnabledField: true,
			NodeID:       resolved.NodeID,
			PublicKey:    resolved.PublicKey,
			PrivateKey:   resolved.PrivateKey,
			Seed:         resolved.Seed,
			IATMode:      resolved.IATMode,
			ServerMode:   serverMode,
		}
		if err := obfs4Overlay.Validate(); err != nil {
			return nil, fmt.Errorf("obfs4 validation: %w", err)
		}
		overlays = append(overlays, obfs4Overlay)
	}

	if strings.ToLower(strings.TrimSpace(obfsCfg.Profile)) != "none" {
		overlays = append(overlays, &MorphingOverlay{
			EnabledField: true,
			PaddingMin:   obfsCfg.PaddingMin,
			PaddingMax:   obfsCfg.PaddingMax,
		})
	}

	overlays = append(overlays, behavior.NewGFWResistTCPOverlay())

	if behaviors.AWG.Enabled {
		overlays = append(overlays, behavior.NewAWGOverlay(behaviors.AWG))
	}
	if behaviors.QPP.Enabled && strings.TrimSpace(behaviors.QPP.Key) != "" {
		overlays = append(overlays, behavior.NewQPPOverlay(behaviors.QPP))
	}
	if behaviors.ViolatedTCP.Enabled {
		overlays = append(overlays, behavior.NewViolatedTCPOverlay(behaviors.ViolatedTCP))
	}

	return overlays, nil
}

func applyObfs4DerivedDefaults(cfg *config.Obfs4BehaviorConfig, authToken string) {
	token := strings.TrimSpace(authToken)
	if token == "" {
		return
	}
	if strings.TrimSpace(cfg.Seed) == "" {
		sum := sha256.Sum256([]byte("stealthlink-obfs4-seed:" + token))
		cfg.Seed = base64.StdEncoding.EncodeToString(sum[:])
	}
	if strings.TrimSpace(cfg.NodeID) == "" {
		sum := sha256.Sum256([]byte("stealthlink-obfs4-node:" + token))
		cfg.NodeID = base64.StdEncoding.EncodeToString(sum[:])
	}
}
