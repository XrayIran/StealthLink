package carrier

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

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
	var frontOpts tlsutil.FrontDialOptions
	var connectIPs []string

	if fo, ok := tlsutil.FrontDialOptionsFromContext(ctx); ok {
		frontOpts = fo
	}
	primarySNI := strings.TrimSpace(cfg.ServerName)
	if frontOpts.Enabled {
		if strings.TrimSpace(frontOpts.FrontDomain) != "" {
			primarySNI = strings.TrimSpace(frontOpts.FrontDomain)
		}
		if len(frontOpts.ConnectIPCandidates) > 0 {
			connectIPs = append(connectIPs, frontOpts.ConnectIPCandidates...)
		} else if strings.TrimSpace(frontOpts.ConnectIP) != "" {
			connectIPs = append(connectIPs, strings.TrimSpace(frontOpts.ConnectIP))
		}
		connectIPs = tlsutil.OrderConnectIPCandidates(frontOpts.PoolKey, connectIPs)
		if len(connectIPs) > 0 {
			_, port, splitErr := net.SplitHostPort(addr)
			if splitErr == nil && port != "" {
				dialAddr = net.JoinHostPort(connectIPs[0], port)
				for _, ip := range connectIPs[1:] {
					if net.ParseIP(ip) == nil {
						continue
					}
					failoverAddrs = append(failoverAddrs, net.JoinHostPort(ip, port))
				}
			}
		}
		// Connect-address failovers: only accept explicit IPs or host:port entries.
		if len(frontOpts.FailoverHosts) > 0 {
			_, port, splitErr := net.SplitHostPort(addr)
			if splitErr == nil && port != "" {
				for _, h := range frontOpts.FailoverHosts {
					h = strings.TrimSpace(h)
					if h == "" {
						continue
					}
					if ip := net.ParseIP(h); ip != nil {
						failoverAddrs = append(failoverAddrs, net.JoinHostPort(h, port))
						continue
					}
					if _, _, err := net.SplitHostPort(h); err == nil {
						failoverAddrs = append(failoverAddrs, h)
						continue
					}
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
		tryDial := func(tcfg *tls.Config, sni string) (net.Conn, error) {
			start := time.Now()
			conn, err := tlsutil.DialUTLS(ctx, network, dialAddr, tcfg, fingerprint)
			if frontOpts.Enabled && len(connectIPs) > 0 {
				tlsutil.ReportConnectIPResult(frontOpts.PoolKey, connectIPs[0], err == nil, time.Since(start))
			}
			if err != nil && len(failoverAddrs) > 0 {
				for i, fa := range failoverAddrs {
					altStart := time.Now()
					conn, err = tlsutil.DialUTLS(ctx, network, fa, tcfg, fingerprint)
					if frontOpts.Enabled && len(connectIPs) > i+1 {
						tlsutil.ReportConnectIPResult(frontOpts.PoolKey, connectIPs[i+1], err == nil, time.Since(altStart))
					}
					if err == nil {
						break
					}
				}
			}
			if frontOpts.Enabled {
				tlsutil.ReportFrontCandidateResult(frontOpts.PoolKey, sni, err == nil, time.Since(start))
			}
			return conn, err
		}

		// If fronting is enabled, iterate SNI candidates with basic health scoring.
		if frontOpts.Enabled && primarySNI != "" && (!hasECH || !echOpts.Enabled) {
			cfo := frontOpts
			cfo.FrontDomain = primarySNI
			cands := tlsutil.OrderFrontCandidates(cfo)
			var lastErr error
			for _, sni := range cands {
				tcfg := cfg.Clone()
				tcfg.ServerName = sni
				conn, err := tryDial(tcfg, sni)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		}

		// Default path (including ECH behavior).
		conn, err := tryDial(cfg, primarySNI)
		if err == nil || !hasECH || !echOpts.Enabled || echOpts.RequireECH {
			return conn, err
		}
		cfgNoECH := cfg.Clone()
		cfgNoECH.EncryptedClientHelloConfigList = nil
		defaultECHResolver.Invalidate(targetHost)
		return tryDial(cfgNoECH, primarySNI)
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
