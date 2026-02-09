// Package fakedns implements FakeDNS for transparent proxying.
// Based on v2rayA's FakeDNS implementation.
package fakedns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// FakeIPRange is the default fake IP range (198.18.0.0/15)
	FakeIPRange = "198.18.0.0/15"
	// DefaultTTL is the default TTL for fake DNS responses
	DefaultTTL = 300 // 5 minutes
)

// FakeDNS provides fake IP addresses for DNS queries.
// It maps fake IPs to real domains for later restoration.
type FakeDNS struct {
	ipPool      *IPPool
	domainToIP  map[string]net.IP
	ipToDomain  map[string]string
	ttl         time.Duration
	mu          sync.RWMutex
}

// Config configures FakeDNS.
type Config struct {
	Enabled bool          `yaml:"enabled"`
	IPRange string        `yaml:"ip_range"` // CIDR range for fake IPs (default: 198.18.0.0/15)
	TTL     time.Duration `yaml:"ttl"`      // TTL for DNS responses (default: 5m)
}

// ApplyDefaults sets default values.
func (c *Config) ApplyDefaults() {
	if c.IPRange == "" {
		c.IPRange = FakeIPRange
	}
	if c.TTL <= 0 {
		c.TTL = DefaultTTL * time.Second
	}
}

// New creates a new FakeDNS instance.
func New(config Config) (*FakeDNS, error) {
	config.ApplyDefaults()

	ipPool, err := NewIPPool(config.IPRange)
	if err != nil {
		return nil, fmt.Errorf("create IP pool: %w", err)
	}

	fd := &FakeDNS{
		ipPool:     ipPool,
		domainToIP: make(map[string]net.IP),
		ipToDomain: make(map[string]string),
		ttl:        config.TTL,
	}

	return fd, nil
}

// Resolve returns a fake IP for a domain.
func (f *FakeDNS) Resolve(domain string) net.IP {
	// Normalize domain
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.RLock()
	if ip, ok := f.domainToIP[domain]; ok {
		f.mu.RUnlock()
		return ip
	}
	f.mu.RUnlock()

	// Allocate new IP
	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check after locking
	if ip, ok := f.domainToIP[domain]; ok {
		return ip
	}

	ip := f.ipPool.Allocate()
	if ip == nil {
		return nil
	}

	f.domainToIP[domain] = ip
	f.ipToDomain[ip.String()] = domain

	return ip
}

// GetDomain returns the real domain for a fake IP.
func (f *FakeDNS) GetDomain(ip net.IP) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	domain, ok := f.ipToDomain[ip.String()]
	return domain, ok
}

// GetDomainByString returns the real domain for a fake IP string.
func (f *FakeDNS) GetDomainByString(ip string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	domain, ok := f.ipToDomain[ip]
	return domain, ok
}

// IsFakeIP checks if an IP is from the fake range.
func (f *FakeDNS) IsFakeIP(ip net.IP) bool {
	return f.ipPool.Contains(ip)
}

// Release releases a domain/IP mapping.
func (f *FakeDNS) Release(domain string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.Lock()
	defer f.mu.Unlock()

	if ip, ok := f.domainToIP[domain]; ok {
		delete(f.domainToIP, domain)
		delete(f.ipToDomain, ip.String())
		f.ipPool.Release(ip)
	}
}

// IPPool manages a pool of fake IP addresses.
type IPPool struct {
	network *net.IPNet
	current net.IP
	mu      sync.Mutex
	used    map[string]bool
}

// NewIPPool creates a new IP pool from a CIDR range.
func NewIPPool(cidr string) (*IPPool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Start from the first usable IP
	ip := network.IP.Mask(network.Mask)
	// Increment to skip network address
	ip = nextIP(ip)

	return &IPPool{
		network: network,
		current: ip,
		used:    make(map[string]bool),
	}, nil
}

// Allocate allocates a new IP from the pool.
func (p *IPPool) Allocate() net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Simple linear allocation
	start := p.current
	for {
		ip := p.current
		p.current = nextIP(p.current)

		// Check if IP is in range and not used
		if !p.network.Contains(ip) {
			// Wrap around
			p.current = p.network.IP.Mask(p.network.Mask)
			p.current = nextIP(p.current)
			ip = p.current
		}

		if !p.used[ip.String()] {
			p.used[ip.String()] = true
			return ip
		}

		// Check if we've gone full circle
		if p.current.Equal(start) {
			return nil // Pool exhausted
		}
	}
}

// Release releases an IP back to the pool.
func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, ip.String())
}

// Contains checks if an IP is in the pool's range.
func (p *IPPool) Contains(ip net.IP) bool {
	return p.network.Contains(ip)
}

// nextIP returns the next IP in sequence.
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)

	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}

	return next
}

// Resolver is a DNS resolver that uses FakeDNS.
type Resolver struct {
	fakeDNS *FakeDNS
}

// NewResolver creates a new FakeDNS resolver.
func NewResolver(fakeDNS *FakeDNS) *Resolver {
	return &Resolver{fakeDNS: fakeDNS}
}

// LookupHost looks up a hostname using FakeDNS.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	ip := r.fakeDNS.Resolve(host)
	if ip != nil {
		return []string{ip.String()}, nil
	}
	return nil, fmt.Errorf("failed to allocate fake IP")
}

// LookupIPAddr looks up a hostname and returns IP addresses.
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	ip := r.fakeDNS.Resolve(host)
	if ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	return nil, fmt.Errorf("failed to allocate fake IP")
}
