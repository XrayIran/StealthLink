package snowflake

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stealthlink/internal/tlsutil"
	"stealthlink/internal/transport/uqsp/rendezvous"
)

var _ rendezvous.Client = (*BrokerRendezvousClient)(nil)

type BrokerRendezvousConfig struct {
	BrokerURL       string
	FrontDomain     string
	UTLSFingerprint string
	AuthToken       string

	// Optional, primarily for tests.
	TLSConfig *tls.Config

	// Retry tuning.
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration

	Now   func() time.Time
	Sleep func(time.Duration)
	Rand  *mathrand.Rand
}

// BrokerRendezvousClient implements a technique-only HTTP(S) rendezvous broker client.
// It is intentionally minimal and does not claim upstream Snowflake protocol interop.
type BrokerRendezvousClient struct {
	cfg BrokerRendezvousConfig
}

func NewBrokerRendezvousClient(cfg BrokerRendezvousConfig) (*BrokerRendezvousClient, error) {
	cfg.BrokerURL = strings.TrimSpace(cfg.BrokerURL)
	if cfg.BrokerURL == "" {
		return nil, fmt.Errorf("broker_url is required")
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = 200 * time.Millisecond
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 3 * time.Second
	}
	if strings.TrimSpace(cfg.UTLSFingerprint) == "" {
		cfg.UTLSFingerprint = "chrome_auto"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = time.Sleep
	}
	if cfg.Rand == nil {
		// Deterministic seed unless overridden; callers can inject randomness if desired.
		cfg.Rand = mathrand.New(mathrand.NewSource(1))
	}
	return &BrokerRendezvousClient{cfg: cfg}, nil
}

type publishReq struct {
	Key       string `json:"key,omitempty"`
	Value     string `json:"value,omitempty"`
	Address   string `json:"address,omitempty"` // compatibility with legacy broker shape
	Role      string `json:"role,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	TTL       int64  `json:"ttl_seconds,omitempty"`
}

type pollResp struct {
	Key     string `json:"key,omitempty"`
	Value   string `json:"value,omitempty"`
	Address string `json:"address,omitempty"` // compatibility with legacy broker shape
}

func (c *BrokerRendezvousClient) Publish(ctx context.Context, key, value string, ttl time.Duration) error {
	endpoint, realHost, client, err := c.buildClient()
	if err != nil {
		return err
	}
	// Legacy reverse broker expects /register.
	endpoint = endpoint.ResolveReference(&url.URL{Path: strings.TrimRight(endpoint.Path, "/") + "/register"})

	reqBody, _ := json.Marshal(publishReq{
		Key:       strings.TrimSpace(key),
		Value:     strings.TrimSpace(value),
		Address:   strings.TrimSpace(value),
		Role:      "rendezvous",
		Timestamp: c.cfg.Now().Unix(),
		TTL:       int64(ttl.Seconds()),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if realHost != "" {
		req.Host = realHost
	}
	if t := strings.TrimSpace(c.cfg.AuthToken); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_ = discard(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("broker register rejected: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *BrokerRendezvousClient) Poll(ctx context.Context, key string) (string, error) {
	endpoint, realHost, client, err := c.buildClient()
	if err != nil {
		return "", err
	}
	endpoint = endpoint.ResolveReference(&url.URL{Path: strings.TrimRight(endpoint.Path, "/") + "/poll"})

	var lastErr error
	backoff := c.cfg.BaseBackoff
	for attempt := 0; attempt < c.cfg.MaxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return "", err
		}
		if realHost != "" {
			req.Host = realHost
		}
		if t := strings.TrimSpace(c.cfg.AuthToken); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
		if strings.TrimSpace(key) != "" {
			req.Header.Set("X-Rendezvous-Key", strings.TrimSpace(key))
		}

		resp, err := client.Do(req)
		if err == nil {
			func() {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusNoContent {
					lastErr = errors.New("no rendezvous value")
					return
				}
				if resp.StatusCode < 200 || resp.StatusCode > 299 {
					lastErr = fmt.Errorf("broker poll rejected: HTTP %d", resp.StatusCode)
					_ = discard(resp.Body)
					return
				}
				var pr pollResp
				if derr := json.NewDecoder(resp.Body).Decode(&pr); derr != nil {
					lastErr = derr
					return
				}
				out := strings.TrimSpace(pr.Value)
				if out == "" {
					out = strings.TrimSpace(pr.Address)
				}
				if out == "" {
					lastErr = errors.New("empty rendezvous value")
					return
				}
				lastErr = nil
				key = out
			}()
			if lastErr == nil {
				return key, nil
			}
		} else {
			lastErr = err
		}

		// Exponential backoff + bounded jitter.
		if attempt < c.cfg.MaxAttempts-1 {
			j := time.Duration(float64(backoff) * (c.cfg.Rand.Float64() * 0.15))
			sleep := backoff + j
			if sleep > c.cfg.MaxBackoff {
				sleep = c.cfg.MaxBackoff
			}
			c.cfg.Sleep(sleep)
			backoff *= 2
			if backoff > c.cfg.MaxBackoff {
				backoff = c.cfg.MaxBackoff
			}
		}
	}
	return "", lastErr
}

func (c *BrokerRendezvousClient) buildClient() (*url.URL, string, *http.Client, error) {
	base, err := url.Parse(c.cfg.BrokerURL)
	if err != nil {
		return nil, "", nil, err
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, "", nil, fmt.Errorf("broker_url scheme must be http or https")
	}
	if strings.TrimSpace(base.Host) == "" {
		return nil, "", nil, fmt.Errorf("broker_url missing host")
	}
	realHost := base.Host
	// Ensure port in dial address matches URL.
	dialAddr := base.Host
	if _, _, splitErr := net.SplitHostPort(dialAddr); splitErr != nil {
		if base.Scheme == "https" {
			dialAddr = net.JoinHostPort(dialAddr, "443")
		} else {
			dialAddr = net.JoinHostPort(dialAddr, "80")
		}
	}

	tlsCfg := &tls.Config{}
	if c.cfg.TLSConfig != nil {
		tlsCfg = c.cfg.TLSConfig.Clone()
	}
	frontDomain := strings.TrimSpace(c.cfg.FrontDomain)
	if frontDomain != "" {
		tlsCfg.ServerName = frontDomain
	} else if h := base.Hostname(); h != "" {
		tlsCfg.ServerName = h
	}

	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	if base.Scheme == "https" {
		fp := strings.TrimSpace(c.cfg.UTLSFingerprint)
		tr.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Always dial the real broker host:port. Fronting only affects SNI.
			return tlsutil.DialUTLS(ctx, network, dialAddr, tlsCfg, fp)
		}
	}

	return base, realHost, &http.Client{Timeout: 10 * time.Second, Transport: tr}, nil
}

func discard(r ioReader) error {
	buf := make([]byte, 32*1024)
	for {
		_, err := r.Read(buf)
		if err != nil {
			return nil
		}
	}
}

type ioReader interface {
	Read([]byte) (int, error)
}
