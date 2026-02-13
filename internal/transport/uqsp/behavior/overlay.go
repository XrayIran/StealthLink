// Package behavior provides protocol behavior overlays for UQSP.
// These overlays port behaviors from ShadowTLS, TLSMirror, AWG, REALITY, and ECH as
// configuration-driven protocol modifications.
package behavior

import (
	"context"
	"crypto/tls"
	"net"
)

// Overlay applies protocol behaviors to connections.
// Implementations provide specific protocol modifications.
type Overlay interface {
	// Apply applies the behavior overlay to a connection
	Apply(conn net.Conn) (net.Conn, error)

	// Name returns the name of this overlay
	Name() string

	// Enabled returns whether this overlay is enabled
	Enabled() bool
}

// ContextPreparer can inject dial-time settings before a carrier connection is established.
type ContextPreparer interface {
	PrepareContext(ctx context.Context) (context.Context, error)
}

// Manager manages multiple behavior overlays
type Manager struct {
	overlays []Overlay
}

// NewManager creates a new behavior overlay manager
func NewManager() *Manager {
	return &Manager{
		overlays: make([]Overlay, 0),
	}
}

// AddOverlay adds an overlay to the manager
func (m *Manager) AddOverlay(overlay Overlay) {
	if overlay.Enabled() {
		m.overlays = append(m.overlays, overlay)
	}
}

// Apply applies all enabled overlays to a connection
func (m *Manager) Apply(conn net.Conn) (net.Conn, error) {
	var err error
	for _, overlay := range m.overlays {
		conn, err = overlay.Apply(conn)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

// GetOverlays returns the list of enabled overlays
func (m *Manager) GetOverlays() []Overlay {
	return m.overlays
}

// TLSConnWrapper wraps a TLS connection to provide additional behavior
type TLSConnWrapper struct {
	*tls.Conn
	overlays []Overlay
}

// Close closes the connection
func (c *TLSConnWrapper) Close() error {
	return c.Conn.Close()
}

// OverlayConfig configures all behavior overlays
type OverlayConfig struct {
	ShadowTLS   ShadowTLSOverlay
	TLSMirror   TLSMirrorOverlay
	AnyTLS      AnyTLSOverlay
	AWG         AWGOverlay
	Reality     RealityOverlay
	ECH         ECHOverlay
	Obfs4       Obfs4Overlay
	Vision      VisionOverlay
	DomainFront DomainFrontOverlay
	TLSFrag     TLSFragOverlay
	CSTP        CSTPOverlay
	ViolatedTCP ViolatedTCPOverlay
	QPP         QPPOverlay
}

func NewManagerFromConfig(cfg *OverlayConfig) *Manager {
	m := NewManager()
	if cfg == nil {
		return m
	}

	if cfg.ShadowTLS.Enabled() {
		m.AddOverlay(&cfg.ShadowTLS)
	}
	if cfg.TLSMirror.Enabled() {
		m.AddOverlay(&cfg.TLSMirror)
	}
	if cfg.AnyTLS.Enabled() {
		m.AddOverlay(&cfg.AnyTLS)
	}
	if cfg.AWG.Enabled() {
		m.AddOverlay(&cfg.AWG)
	}
	if cfg.Reality.Enabled() {
		m.AddOverlay(&cfg.Reality)
	}
	if cfg.ECH.Enabled() {
		m.AddOverlay(&cfg.ECH)
	}
	if cfg.Obfs4.Enabled() {
		m.AddOverlay(&cfg.Obfs4)
	}
	if cfg.Vision.Enabled() {
		m.AddOverlay(&cfg.Vision)
	}
	if cfg.DomainFront.Enabled() {
		m.AddOverlay(&cfg.DomainFront)
	}
	if cfg.TLSFrag.Enabled() {
		m.AddOverlay(&cfg.TLSFrag)
	}
	if cfg.CSTP.Enabled() {
		m.AddOverlay(&cfg.CSTP)
	}
	if cfg.ViolatedTCP.Enabled() {
		m.AddOverlay(&cfg.ViolatedTCP)
	}
	if cfg.QPP.Enabled() {
		m.AddOverlay(&cfg.QPP)
	}

	return m
}

func SortBehaviors(overlays []Overlay) []Overlay {
	if len(overlays) <= 1 {
		return overlays
	}
	sorted := make([]Overlay, 0, len(overlays))
	var phase2, phase3 []Overlay

	for _, o := range overlays {
		switch overlayPriority(o.Name()) {
		case 1:
			sorted = append(sorted, o)
		case 2:
			phase2 = append(phase2, o)
		default:
			phase3 = append(phase3, o)
		}
	}
	sorted = append(sorted, phase2...)
	sorted = append(sorted, phase3...)
	return sorted
}

// overlayPriority returns execution phase for known overlay names.
func overlayPriority(name string) int {
	switch name {
	case "ech", "domainfront":
		return 1
	case "reality", "shadowtls", "tlsmirror", "anytls", "obfs4", "gfwresist_tls", "gfwresist_tcp", "violated_tcp":
		return 2
	case "qpp":
		return 0
	default:
		return 3
	}
}
