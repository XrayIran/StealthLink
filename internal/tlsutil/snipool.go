package tlsutil

import (
	"math/rand"
	"sync"
	"sync/atomic"
)

// SNIPool manages a pool of decoy SNI domains for stealth.
// It supports multiple rotation strategies to distribute
// TLS handshake patterns across different domains.
type SNIPool struct {
	mu           sync.RWMutex
	decoyDomains []string
	strategy     string // "random", "round-robin", "weighted"
	weights      []int  // For weighted strategy
	currentIndex uint64 // Atomic counter for round-robin
}

// NewSNIPool creates a new SNI pool with the given strategy.
func NewSNIPool(domains []string, strategy string) *SNIPool {
	if len(domains) == 0 {
		domains = []string{"www.microsoft.com", "www.apple.com", "www.google.com"}
	}
	if strategy == "" {
		strategy = "random"
	}

	return &SNIPool{
		decoyDomains: domains,
		strategy:     strategy,
		weights:      make([]int, len(domains)),
	}
}

// NewSNIPoolWithWeights creates a new SNI pool with weighted distribution.
func NewSNIPoolWithWeights(domains []string, weights []int) *SNIPool {
	if len(domains) != len(weights) {
		// Fall back to equal weights
		weights = make([]int, len(domains))
		for i := range weights {
			weights[i] = 1
		}
	}

	return &SNIPool{
		decoyDomains: domains,
		strategy:     "weighted",
		weights:      weights,
	}
}

// GetSNI returns a decoy SNI based on the configured strategy.
func (p *SNIPool) GetSNI(reqHost string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.decoyDomains) == 0 {
		return reqHost
	}

	switch p.strategy {
	case "round-robin":
		idx := atomic.AddUint64(&p.currentIndex, 1) % uint64(len(p.decoyDomains))
		return p.decoyDomains[idx]

	case "weighted":
		return p.weightedSelect()

	case "random":
		fallthrough
	default:
		return p.decoyDomains[rand.Intn(len(p.decoyDomains))]
	}
}

// weightedSelect selects a domain based on weights.
func (p *SNIPool) weightedSelect() string {
	totalWeight := 0
	for _, w := range p.weights {
		totalWeight += w
	}
	if totalWeight == 0 {
		return p.decoyDomains[0]
	}

	r := rand.Intn(totalWeight)
	for i, w := range p.weights {
		r -= w
		if r < 0 {
			return p.decoyDomains[i]
		}
	}
	return p.decoyDomains[0]
}

// AddDomain adds a new decoy domain to the pool.
func (p *SNIPool) AddDomain(domain string, weight int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.decoyDomains = append(p.decoyDomains, domain)
	p.weights = append(p.weights, weight)
}

// RemoveDomain removes a domain from the pool.
func (p *SNIPool) RemoveDomain(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, d := range p.decoyDomains {
		if d == domain {
			// Remove by swapping with last and truncating
			p.decoyDomains[i] = p.decoyDomains[len(p.decoyDomains)-1]
			p.decoyDomains = p.decoyDomains[:len(p.decoyDomains)-1]
			p.weights[i] = p.weights[len(p.weights)-1]
			p.weights = p.weights[:len(p.weights)-1]
			return
		}
	}
}

// SetDomains replaces all domains in the pool.
func (p *SNIPool) SetDomains(domains []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.decoyDomains = make([]string, len(domains))
	copy(p.decoyDomains, domains)

	// Reset weights to equal
	p.weights = make([]int, len(domains))
	for i := range p.weights {
		p.weights[i] = 1
	}
}

// Domains returns a copy of the current domain list.
func (p *SNIPool) Domains() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]string, len(p.decoyDomains))
	copy(result, p.decoyDomains)
	return result
}

// Strategy returns the current rotation strategy.
func (p *SNIPool) Strategy() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.strategy
}

// SetStrategy changes the rotation strategy.
func (p *SNIPool) SetStrategy(strategy string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.strategy = strategy
}

// CommonDecoyDomains provides a list of common CDN domains
// that are suitable for TLS camouflage.
func CommonDecoyDomains() []string {
	return []string{
		"www.microsoft.com",
		"www.apple.com",
		"www.google.com",
		"www.amazon.com",
		"www.cloudflare.com",
		"www.akamai.com",
		"www.fastly.com",
		"www.github.com",
		"www.linkedin.com",
		"www.reddit.com",
		"www.twitter.com",
		"www.facebook.com",
		"www.instagram.com",
		"www.youtube.com",
		"www.netflix.com",
		"www.spotify.com",
		"www.dropbox.com",
		"www.salesforce.com",
		"www.shopify.com",
		"www.cloudfront.net",
	}
}

// RegionalDecoyDomains returns domains suitable for specific regions.
func RegionalDecoyDomains(region string) []string {
	switch region {
	case "cn":
		return []string{
			"www.baidu.com",
			"www.taobao.com",
			"www.jd.com",
			"www.qq.com",
			"www.weibo.com",
			"www.bilibili.com",
			"www.zhihu.com",
		}
	case "eu":
		return []string{
			"www.bbc.co.uk",
			"www.spiegel.de",
			"www.lemonde.fr",
			"www.corriere.it",
			"www.elpais.com",
			"www.gov.uk",
		}
	case "ru":
		return []string{
			"www.yandex.ru",
			"www.vk.com",
			"www.mail.ru",
			"www.ozon.ru",
			"www.avito.ru",
		}
	default:
		return CommonDecoyDomains()
	}
}
