package transport

import (
	"context"
	"net"
	"net/url"

	"stealthlink/internal/transport/tfo"
	"golang.org/x/net/proxy"
)

// ProxyDialer builds a net.Dialer respecting HTTP/SOCKS proxies. Empty URL yields direct dialing.
func ProxyDialer(proxyURL string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if proxyURL == "" {
		return (&net.Dialer{}).DialContext
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return (&net.Dialer{}).DialContext
	}

	d, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return (&net.Dialer{}).DialContext
	}

	// Prefer context dialer when available.
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.Dial(network, addr)
	}
}

// ProxyDialerWithTFO builds a dialer with TFO support.
func ProxyDialerWithTFO(proxyURL string, tfoConfig tfo.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	tfoConfig.ApplyDefaults()

	if !tfoConfig.Enabled || proxyURL != "" {
		// TFO doesn't work through proxies, use regular dialer
		return ProxyDialer(proxyURL)
	}

	// Use TFO-enabled dialer
	d := tfo.Dialer(tfoConfig)
	return d.DialContext
}
