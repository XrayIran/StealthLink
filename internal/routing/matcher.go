// Package routing implements rule-based routing with IP/CIDR/domain/port matching.
package routing

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
)

// MatchType represents the type of routing match
type MatchType string

const (
	MatchTypeIP        MatchType = "ip"
	MatchTypeCIDR      MatchType = "cidr"
	MatchTypeDomain    MatchType = "domain"
	MatchTypeDomainSuffix MatchType = "domain_suffix"
	MatchTypeRegex     MatchType = "regex"
	MatchTypePort      MatchType = "port"
	MatchTypePortRange MatchType = "port_range"
	MatchTypeProtocol  MatchType = "protocol"
	MatchTypeDefault   MatchType = "default"
)

// Matcher represents a single routing rule matcher
type Matcher struct {
	Type    MatchType
	Pattern string
	Negate  bool

	// Compiled matchers
	ip       net.IP
	ipNet    *net.IPNet
	port     int
	portMin  int
	portMax  int
	domains  map[string]struct{}
	regex    *regexp.Regexp
}

// Compile compiles the matcher pattern
func (m *Matcher) Compile() error {
	switch m.Type {
	case MatchTypeIP:
		m.ip = net.ParseIP(m.Pattern)
		if m.ip == nil {
			return fmt.Errorf("invalid IP: %s", m.Pattern)
		}

	case MatchTypeCIDR:
		_, ipNet, err := net.ParseCIDR(m.Pattern)
		if err != nil {
			return fmt.Errorf("invalid CIDR: %s", m.Pattern)
		}
		m.ipNet = ipNet

	case MatchTypeDomain:
		m.domains = make(map[string]struct{})
		for _, d := range strings.Split(m.Pattern, ",") {
			m.domains[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
		}

	case MatchTypeDomainSuffix:
		// Pattern is already a suffix

	case MatchTypeRegex:
		r, err := regexp.Compile(m.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex: %s", m.Pattern)
		}
		m.regex = r

	case MatchTypePort:
		if _, err := fmt.Sscanf(m.Pattern, "%d", &m.port); err != nil {
			return fmt.Errorf("invalid port: %s", m.Pattern)
		}

	case MatchTypePortRange:
		var err error
		_, err = fmt.Sscanf(m.Pattern, "%d-%d", &m.portMin, &m.portMax)
		if err != nil {
			return fmt.Errorf("invalid port range: %s", m.Pattern)
		}

	case MatchTypeProtocol, MatchTypeDefault:
		// No compilation needed

	default:
		return fmt.Errorf("unknown match type: %s", m.Type)
	}

	return nil
}

// Match checks if the target matches this matcher
func (m *Matcher) Match(target *Target) (bool, error) {
	var matched bool

	switch m.Type {
	case MatchTypeIP:
		matched = m.ip.Equal(target.IP)

	case MatchTypeCIDR:
		matched = m.ipNet.Contains(target.IP)

	case MatchTypeDomain:
		host := strings.ToLower(target.Host)
		_, matched = m.domains[host]

	case MatchTypeDomainSuffix:
		host := strings.ToLower(target.Host)
		matched = strings.HasSuffix(host, m.Pattern)

	case MatchTypeRegex:
		matched = m.regex.MatchString(target.Host)

	case MatchTypePort:
		matched = target.Port == m.port

	case MatchTypePortRange:
		matched = target.Port >= m.portMin && target.Port <= m.portMax

	case MatchTypeProtocol:
		matched = strings.ToLower(target.Protocol) == strings.ToLower(m.Pattern)

	case MatchTypeDefault:
		matched = true
	}

	if m.Negate {
		return !matched, nil
	}
	return matched, nil
}

// Target represents a routing target
type Target struct {
	Host     string
	IP       net.IP
	Port     int
	Protocol string
}

// Rule represents a routing rule
type Rule struct {
	Name       string
	Priority   int
	Matchers   []*Matcher
	Action     Action
	Tags       []string
	Enabled    bool
}

// Action represents the action to take for a matched rule
type Action struct {
	Type      ActionType
	Chain     string
	Transport string
	Proxy     string
}

// ActionType represents the type of action
type ActionType string

const (
	ActionTypeDirect  ActionType = "direct"
	ActionTypeProxy   ActionType = "proxy"
	ActionTypeBlock   ActionType = "block"
	ActionTypeChain   ActionType = "chain"
)

// RuleSet manages a set of routing rules
type RuleSet struct {
	rules []*Rule
	mu    sync.RWMutex
}

// NewRuleSet creates a new rule set
func NewRuleSet() *RuleSet {
	return &RuleSet{
		rules: make([]*Rule, 0),
	}
}

// AddRule adds a rule to the set
func (rs *RuleSet) AddRule(rule *Rule) error {
	// Compile matchers
	for _, m := range rule.Matchers {
		if err := m.Compile(); err != nil {
			return err
		}
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Insert by priority
	inserted := false
	for i, r := range rs.rules {
		if rule.Priority > r.Priority {
			rs.rules = append(rs.rules[:i], append([]*Rule{rule}, rs.rules[i:]...)...)
			inserted = true
			break
		}
	}

	if !inserted {
		rs.rules = append(rs.rules, rule)
	}

	return nil
}

// RemoveRule removes a rule by name
func (rs *RuleSet) RemoveRule(name string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	for i, r := range rs.rules {
		if r.Name == name {
			rs.rules = append(rs.rules[:i], rs.rules[i+1:]...)
			return
		}
	}
}

// Match finds the first matching rule for a target
func (rs *RuleSet) Match(target *Target) (*Rule, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	for _, rule := range rs.rules {
		if !rule.Enabled {
			continue
		}

		matched := true
		for _, matcher := range rule.Matchers {
			m, err := matcher.Match(target)
			if err != nil {
				return nil, err
			}
			if !m {
				matched = false
				break
			}
		}

		if matched {
			return rule, nil
		}
	}

	return nil, nil
}

// GetRules returns all rules
func (rs *RuleSet) GetRules() []*Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	result := make([]*Rule, len(rs.rules))
	copy(result, rs.rules)
	return result
}

// IPRange represents an IP range for matching
type IPRange struct {
	Start net.IP
	End   net.IP
}

// Contains checks if an IP is within the range
func (r *IPRange) Contains(ip net.IP) bool {
	if len(ip) != len(r.Start) {
		return false
	}

	startInt := ipToUint32(r.Start)
	endInt := ipToUint32(r.End)
	ipInt := ipToUint32(ip)

	return ipInt >= startInt && ipInt <= endInt
}

func ipToUint32(ip net.IP) uint32 {
	if len(ip) == 16 {
		// IPv6 mapped IPv4
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

// DomainTrie is a trie structure for efficient domain matching
type DomainTrie struct {
	root *trieNode
	mu   sync.RWMutex
}

type trieNode struct {
	children map[string]*trieNode
	isEnd    bool
}

// NewDomainTrie creates a new domain trie
func NewDomainTrie() *DomainTrie {
	return &DomainTrie{
		root: &trieNode{children: make(map[string]*trieNode)},
	}
}

// Insert adds a domain to the trie
func (t *DomainTrie) Insert(domain string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	parts := strings.Split(strings.ToLower(domain), ".")
	node := t.root

	// Insert in reverse order (TLD first)
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if node.children[part] == nil {
			node.children[part] = &trieNode{children: make(map[string]*trieNode)}
		}
		node = node.children[part]
	}

	node.isEnd = true
}

// Match checks if a domain matches any pattern in the trie
func (t *DomainTrie) Match(domain string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	parts := strings.Split(strings.ToLower(domain), ".")
	node := t.root

	// Match in reverse order
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if node.children[part] == nil {
			return node.isEnd // Return true if we're at an end node (suffix match)
		}
		node = node.children[part]
	}

	return node.isEnd
}

// GeoMatcher matches targets by geographic location
type GeoMatcher struct {
	countries map[string]struct{}
	asns      map[uint32]struct{}
	mu        sync.RWMutex
}

// NewGeoMatcher creates a new geographic matcher
func NewGeoMatcher() *GeoMatcher {
	return &GeoMatcher{
		countries: make(map[string]struct{}),
		asns:      make(map[uint32]struct{}),
	}
}

// AddCountry adds a country code to match
func (g *GeoMatcher) AddCountry(code string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.countries[strings.ToUpper(code)] = struct{}{}
}

// AddASN adds an ASN to match
func (g *GeoMatcher) AddASN(asn uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.asns[asn] = struct{}{}
}

// Match checks if the geo attributes match
func (g *GeoMatcher) Match(countryCode string, asn uint32) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if _, ok := g.countries[strings.ToUpper(countryCode)]; ok {
		return true
	}

	if _, ok := g.asns[asn]; ok {
		return true
	}

	return false
}

// MatcherCache caches compiled matchers for performance
type MatcherCache struct {
	cache map[string]*Matcher
	mu    sync.RWMutex
}

// NewMatcherCache creates a new matcher cache
func NewMatcherCache() *MatcherCache {
	return &MatcherCache{
		cache: make(map[string]*Matcher),
	}
}

// GetOrCompile gets a cached matcher or compiles a new one
func (c *MatcherCache) GetOrCompile(matchType MatchType, pattern string) (*Matcher, error) {
	key := string(matchType) + ":" + pattern

	c.mu.RLock()
	if m, ok := c.cache[key]; ok {
		c.mu.RUnlock()
		return m, nil
	}
	c.mu.RUnlock()

	m := &Matcher{
		Type:    matchType,
		Pattern: pattern,
	}

	if err := m.Compile(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[key] = m
	c.mu.Unlock()

	return m, nil
}
