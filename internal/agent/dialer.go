package agent

import (
	"fmt"
	"net"
	"net/url"

	"stealthlink/internal/config"
)

type hostKey struct {
	name        string
	sni         string
	host        string
	origin      string
	path        string
	fingerprint string
	connectIP   string
	maxConns    int
}

type transportTarget struct {
	addr        string
	host        string
	sni         string
	origin      string
	path        string
	fingerprint string
	headers     map[string]string
}

type serviceGroup struct {
	services []*config.Service
	headers  map[string]string
}

func groupServices(cfg *config.Config) map[hostKey]serviceGroup {
	out := make(map[hostKey]serviceGroup)
	profile := cfg.StealthCamouflageProfile()
	for i := range cfg.Services {
		svc := &cfg.Services[i]
		key := hostKey{
			name:        svc.Name,
			sni:         svc.Host.SNI,
			host:        svc.Host.Host,
			origin:      svc.Host.Origin,
			path:        svc.Host.Path,
			fingerprint: svc.Host.Fingerprint,
			connectIP:   svc.Host.ConnectIP,
			maxConns:    svc.Host.MaxConns,
		}
		if cfg.Transport.Type == "stealth" && (profile == config.StealthProfileHTTPSWSS || profile == config.StealthProfileHTTPSH2 || profile == config.StealthProfileHTTPSSplit) {
			if key.path == "" {
				key.path = cfg.Transport.Stealth.Camouflage.HTTPCover.Path
			}
		} else {
			key.path = ""
			key.origin = ""
		}
		grp := out[key]
		if grp.services == nil {
			grp.services = []*config.Service{}
		}
		grp.services = append(grp.services, svc)
		if len(grp.headers) == 0 && len(svc.Host.Headers) > 0 {
			grp.headers = make(map[string]string, len(svc.Host.Headers))
			for k, v := range svc.Host.Headers {
				grp.headers[k] = v
			}
		}
		out[key] = grp
	}
	return out
}

func buildTarget(cfg *config.Config, key hostKey, svcHeaders map[string]string) transportTarget {
	profile := cfg.StealthCamouflageProfile()
	baseAddr := cfg.Agent.GatewayAddr
	port := ""
	if _, p, err := net.SplitHostPort(baseAddr); err == nil {
		port = p
	}
	host := baseAddr
	if key.host != "" {
		if _, port, err := net.SplitHostPort(baseAddr); err == nil {
			if _, _, err := net.SplitHostPort(key.host); err == nil {
				host = key.host
			} else {
				host = net.JoinHostPort(key.host, port)
			}
		} else {
			host = key.host
		}
	} else if cfg.Transport.Stealth.Camouflage.TLS.ServerName != "" {
		if port != "" {
			host = net.JoinHostPort(cfg.Transport.Stealth.Camouflage.TLS.ServerName, port)
		} else {
			host = cfg.Transport.Stealth.Camouflage.TLS.ServerName
		}
	}
	addr := baseAddr
	if key.connectIP != "" {
		if _, _, err := net.SplitHostPort(key.connectIP); err == nil {
			addr = key.connectIP
		} else if port != "" {
			addr = net.JoinHostPort(key.connectIP, port)
		} else {
			addr = key.connectIP
		}
	} else if key.host != "" {
		addr = host
	}
	sni := cfg.Transport.Stealth.Camouflage.TLS.ServerName
	if key.sni != "" {
		sni = key.sni
	}
	if sni == "" && host != "" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			sni = h
		} else {
			sni = host
		}
	}
	origin := cfg.Transport.Stealth.Camouflage.HTTPCover.Origin
	if key.origin != "" {
		origin = key.origin
	}
	path := key.path
	if path == "" {
		path = "/_sl"
	}
	fingerprint := cfg.Transport.Stealth.Camouflage.TLSShape.Fingerprint
	if key.fingerprint != "" {
		fingerprint = key.fingerprint
	}
	headers := map[string]string{}
	if profile == config.StealthProfileHTTPSWSS || profile == config.StealthProfileHTTPSH2 || profile == config.StealthProfileHTTPSSplit {
		for k, v := range cfg.Transport.Stealth.Camouflage.HTTPCover.Headers {
			headers[k] = v
		}
	}
	// Service-level header overrides / additions.
	for k, v := range svcHeaders {
		headers[k] = v
	}
	return transportTarget{
		addr:        addr,
		host:        host,
		sni:         sni,
		origin:      origin,
		path:        path,
		fingerprint: fingerprint,
		headers:     headers,
	}
}

func buildURL(scheme, host, path string) string {
	if path == "" {
		path = "/_sl"
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

func validateURL(raw string) bool {
	_, err := url.Parse(raw)
	return err == nil
}
