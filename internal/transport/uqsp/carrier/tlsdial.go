package carrier

import (
	"context"
	"crypto/tls"
	"net"
	"strings"

	"stealthlink/internal/tlsutil"
)

var defaultECHResolver = tlsutil.NewECHResolver(tlsutil.ECHConfig{
	Enabled:      true,
	RetryWithout: true,
})

func dialCarrierTLS(ctx context.Context, network, addr string, tlsConfig *tls.Config, fingerprint string) (net.Conn, error) {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	if strings.TrimSpace(fingerprint) == "" {
		// Harden defaults: always emulate a real browser fingerprint.
		fingerprint = "chrome_auto"
	}

	cfg, err := tlsutil.EnsureServerName(tlsConfig, addr)
	if err != nil {
		return nil, err
	}

	echOpts, hasECH := tlsutil.ECHDialOptionsFromContext(ctx)
	targetHost := cfg.ServerName
	if targetHost == "" {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr == nil {
			targetHost = host
		} else {
			targetHost = addr
		}
	}
	targetHost = strings.TrimSpace(targetHost)
	dialAddr := addr
	var failoverAddrs []string

	if frontOpts, ok := tlsutil.FrontDialOptionsFromContext(ctx); ok && frontOpts.Enabled {
		if frontOpts.FrontDomain != "" {
			cfg.ServerName = frontOpts.FrontDomain
		}
		if frontOpts.ConnectIP != "" {
			_, port, splitErr := net.SplitHostPort(addr)
			if splitErr == nil && port != "" {
				dialAddr = net.JoinHostPort(frontOpts.ConnectIP, port)
			}
		}
		if len(frontOpts.FailoverHosts) > 0 {
			_, port, splitErr := net.SplitHostPort(addr)
			if splitErr == nil && port != "" {
				for _, h := range frontOpts.FailoverHosts {
					h = strings.TrimSpace(h)
					if h == "" {
						continue
					}
					if _, _, err := net.SplitHostPort(h); err == nil {
						failoverAddrs = append(failoverAddrs, h)
						continue
					}
					failoverAddrs = append(failoverAddrs, net.JoinHostPort(h, port))
				}
			}
		}
	}

	if hasECH && echOpts.Enabled {
		if echOpts.PublicName != "" {
			cfg.ServerName = echOpts.PublicName
		}
		cfg.EncryptedClientHelloConfigList = tlsutil.NormalizeECHConfigList(echOpts.ConfigList)
		if len(cfg.EncryptedClientHelloConfigList) == 0 && targetHost != "" {
			if rec, resolveErr := defaultECHResolver.Resolve(ctx, targetHost); resolveErr == nil {
				cfg.EncryptedClientHelloConfigList = tlsutil.NormalizeECHConfigList(rec.Config)
			}
		}
	}

	if fingerprint != "" {
		conn, err := tlsutil.DialUTLS(ctx, network, dialAddr, cfg, fingerprint)
		if err != nil && len(failoverAddrs) > 0 {
			for _, fa := range failoverAddrs {
				conn, err = tlsutil.DialUTLS(ctx, network, fa, cfg, fingerprint)
				if err == nil {
					break
				}
			}
		}
		if err == nil || !hasECH || !echOpts.Enabled || echOpts.RequireECH {
			return conn, err
		}
		cfgNoECH := cfg.Clone()
		cfgNoECH.EncryptedClientHelloConfigList = nil
		defaultECHResolver.Invalidate(targetHost)
		return tlsutil.DialUTLS(ctx, network, dialAddr, cfgNoECH, fingerprint)
	}

	dialer := tls.Dialer{Config: cfg}
	conn, err := dialer.DialContext(ctx, network, dialAddr)
	if err != nil && len(failoverAddrs) > 0 {
		for _, fa := range failoverAddrs {
			conn, err = dialer.DialContext(ctx, network, fa)
			if err == nil {
				break
			}
		}
	}
	if err == nil || !hasECH || !echOpts.Enabled || echOpts.RequireECH {
		return conn, err
	}
	cfgNoECH := cfg.Clone()
	cfgNoECH.EncryptedClientHelloConfigList = nil
	defaultECHResolver.Invalidate(targetHost)
	fallbackDialer := &tls.Dialer{Config: cfgNoECH}
	return fallbackDialer.DialContext(ctx, network, dialAddr)
}
