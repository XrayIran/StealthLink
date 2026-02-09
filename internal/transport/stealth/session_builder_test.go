package stealth

import (
	"testing"
	"time"

	"stealthlink/internal/config"
	awgtransport "stealthlink/internal/transport/awg"
	"stealthlink/internal/transport/xhttp"
)

func TestBuildSessionConfigUsesStealthSessionValues(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.Stealth.Session.MaxStreamsPerSession = 42
	cfg.Transport.Stealth.Session.MaxStreamsTotal = 100
	cfg.Transport.Stealth.Session.SmuxKeepAliveInterval = "3s"
	cfg.Transport.Stealth.Session.SmuxKeepAliveTimeout = "9s"
	cfg.Transport.Stealth.Session.HeaderTimeout = "11s"
	cfg.Transport.Stealth.Session.MaxStreamBuffer = 1234
	cfg.Transport.Stealth.Session.MaxReceiveBuffer = 5678
	cfg.Mux.MaxStreamsPerSession = cfg.Transport.Stealth.Session.MaxStreamsPerSession
	cfg.Mux.MaxStreamsTotal = cfg.Transport.Stealth.Session.MaxStreamsTotal
	cfg.Mux.SmuxKeepAliveInterval = cfg.Transport.Stealth.Session.SmuxKeepAliveInterval
	cfg.Mux.SmuxKeepAliveTimeout = cfg.Transport.Stealth.Session.SmuxKeepAliveTimeout
	cfg.Mux.HeaderTimeout = cfg.Transport.Stealth.Session.HeaderTimeout
	cfg.Mux.MaxStreamBuffer = cfg.Transport.Stealth.Session.MaxStreamBuffer
	cfg.Mux.MaxReceiveBuffer = cfg.Transport.Stealth.Session.MaxReceiveBuffer

	smuxCfg := BuildSessionConfig(cfg)
	if smuxCfg.KeepAliveInterval != 3*time.Second {
		t.Fatalf("unexpected KeepAliveInterval: %s", smuxCfg.KeepAliveInterval)
	}
	if smuxCfg.KeepAliveTimeout != 9*time.Second {
		t.Fatalf("unexpected KeepAliveTimeout: %s", smuxCfg.KeepAliveTimeout)
	}
	if smuxCfg.MaxStreamBuffer != 1234 {
		t.Fatalf("unexpected MaxStreamBuffer: %d", smuxCfg.MaxStreamBuffer)
	}
	if smuxCfg.MaxReceiveBuffer != 5678 {
		t.Fatalf("unexpected MaxReceiveBuffer: %d", smuxCfg.MaxReceiveBuffer)
	}
}

func TestBuildAgentDialerSplitHTTPUsesXHTTP(t *testing.T) {
	t.Skip("Legacy stealth transport removed - UQSP is the only supported transport")
	_ = xhttp.Dialer{}
}

func TestBuildAgentDialerAWGUsesAWGCarrier(t *testing.T) {
	t.Skip("Legacy stealth transport removed - UQSP is the only supported transport")
	_ = awgtransport.Dialer{}
}
