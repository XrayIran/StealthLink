package stealth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"stealthlink/internal/config"
	"stealthlink/internal/mux"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/uqsp"

	"github.com/xtaci/smux"
)

// Target holds connection target information
type Target struct {
	Addr        string
	Host        string
	SNI         string
	Origin      string
	Path        string
	Fingerprint string
	Headers     map[string]string
}

// BuildSessionConfig builds smux config from global config
func BuildSessionConfig(cfg *config.Config) *smux.Config {
	return mux.Config(
		cfg.SmuxKeepAliveInterval(),
		cfg.SmuxKeepAliveTimeout(),
		cfg.Mux.MaxStreamsPerSession,
		cfg.Mux.MaxStreamBuffer,
		cfg.Mux.MaxReceiveBuffer,
	)
}

// BuildAgentDialer builds a dialer for the agent
func BuildAgentDialer(cfg *config.Config, target Target, smuxCfg *smux.Config, proxyDial func(ctx context.Context, network, addr string) (net.Conn, error)) (transport.Dialer, string, string, error) {
	// UQSP is now the only supported transport
	if !cfg.UQSPEnabled() {
		return nil, "", "", fmt.Errorf("transport.type=%s is not supported. Use transport.type=uqsp", cfg.Transport.Type)
	}

	return buildUQSPAgentDialer(cfg, target, smuxCfg)
}

// buildUQSPAgentDialer builds a UQSP dialer for the agent
func buildUQSPAgentDialer(cfg *config.Config, target Target, smuxCfg *smux.Config) (transport.Dialer, string, string, error) {
	// Build TLS config
	tlsCfg, err := buildTLSConfigForUQSP(cfg, target)
	if err != nil {
		return nil, "", "", err
	}

	// Get auth token
	authToken := cfg.ActiveSharedKey()
	if cfg.Role == "agent" {
		authToken = cfg.AgentToken(cfg.Agent.ID)
	}

	// Create UQSP dialer
	d := uqsp.NewDialer(
		&cfg.Transport.UQSP,
		tlsCfg,
		smuxCfg,
		authToken,
	)

	return d, target.Addr, "uqsp", nil
}

// buildTLSConfigForUQSP builds TLS configuration for UQSP
func buildTLSConfigForUQSP(cfg *config.Config, target Target) (*tls.Config, error) {
	cam := cfg.Transport.Stealth.Camouflage
	sni := firstNonEmpty(target.SNI, cam.TLS.ServerName)

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: cam.TLS.InsecureSkipVerify,
	}

	return tlsCfg, nil
}

// BuildGatewayListener builds a listener for the gateway
func BuildGatewayListener(cfg *config.Config, smuxCfg *smux.Config) (transport.Listener, string, error) {
	// UQSP is now the only supported transport
	if !cfg.UQSPEnabled() {
		return nil, "", fmt.Errorf("transport.type=%s is not supported. Use transport.type=uqsp", cfg.Transport.Type)
	}

	return buildUQSPGatewayListener(cfg, smuxCfg)
}

// buildUQSPGatewayListener builds a UQSP listener for the gateway
func buildUQSPGatewayListener(cfg *config.Config, smuxCfg *smux.Config) (transport.Listener, string, error) {
	// Build TLS config
	tlsCfg, err := buildServerTLSConfigForUQSP(cfg)
	if err != nil {
		return nil, "", err
	}

	// Get auth token
	authToken := cfg.ActiveSharedKey()

	// Create UQSP listener
	l, err := uqsp.Listen(
		cfg.Gateway.Listen,
		&cfg.Transport.UQSP,
		tlsCfg,
		smuxCfg,
		authToken,
	)
	if err != nil {
		return nil, "", err
	}

	return l, "uqsp", nil
}

// buildServerTLSConfigForUQSP builds server TLS configuration for UQSP
func buildServerTLSConfigForUQSP(cfg *config.Config) (*tls.Config, error) {
	cam := cfg.Transport.Stealth.Camouflage

	tlsCfg := &tls.Config{}

	// Load certificate if specified
	if cam.TLS.CertFile != "" && cam.TLS.KeyFile != "" {
		// Load certificates from files
		cert, err := tls.LoadX509KeyPair(cam.TLS.CertFile, cam.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// MetricsLabel returns the metrics label for the transport
func MetricsLabel(cfg *config.Config) string {
	if cfg.UQSPEnabled() {
		return "uqsp"
	}
	return "legacy"
}

// IsHTTPProfile returns true if the profile is an HTTP-based profile
// Deprecated: HTTP profiles are no longer used with UQSP
func IsHTTPProfile(profile string) bool {
	// With UQSP, we no longer use HTTP profiles
	// This function is kept for backwards compatibility
	return false
}

// Helper functions

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func cloneHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
