package phantom

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	defaultV4CIDR = "198.51.100.0/24" // TEST-NET-2
	defaultV6CIDR = "2001:db8::/64"   // documentation prefix
	maxPoolSize   = 256
)

type Config struct {
	Enabled        bool   `yaml:"enabled"`
	SharedSecret   string `yaml:"shared_secret"`
	EpochSeed      string `yaml:"epoch_seed"`
	SubnetPrefixV4 string `yaml:"subnet_prefix_v4"`
	SubnetPrefixV6 string `yaml:"subnet_prefix_v6"`
	PoolSize       int    `yaml:"pool_size"`
}

type Pool struct {
	ips []net.IP
	idx int
}

func NewPool(cfg Config) (*Pool, error) {
	if !cfg.Enabled {
		return &Pool{}, nil
	}
	secret, err := decodeSecret(cfg.SharedSecret)
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("phantom shared_secret is required")
	}

	v4net, err := parsePrefix(cfg.SubnetPrefixV4, defaultV4CIDR)
	if err != nil {
		return nil, fmt.Errorf("parse subnet_prefix_v4: %w", err)
	}
	v6net, err := parsePrefix(cfg.SubnetPrefixV6, defaultV6CIDR)
	if err != nil {
		return nil, fmt.Errorf("parse subnet_prefix_v6: %w", err)
	}

	n := cfg.PoolSize
	if n <= 0 {
		n = 64
	}
	if n > maxPoolSize {
		n = maxPoolSize
	}

	out := make([]net.IP, 0, n)
	for i := 0; i < n; i++ {
		ip, derr := deriveIPWithEpoch(secret, cfg.EpochSeed, uint32(i), v4net, v6net)
		if derr != nil {
			return nil, derr
		}
		out = append(out, ip)
	}
	return &Pool{ips: out}, nil
}

func (p *Pool) Next() net.IP {
	if p == nil || len(p.ips) == 0 {
		return nil
	}
	ip := p.ips[p.idx%len(p.ips)]
	p.idx = (p.idx + 1) % len(p.ips)
	return append(net.IP(nil), ip...)
}

// NextCandidates returns up to n candidates starting from the current index,
// then advances the index by 1 (so successive dials rotate).
func (p *Pool) NextCandidates(n int) []net.IP {
	if p == nil || len(p.ips) == 0 || n <= 0 {
		return nil
	}
	if n > len(p.ips) {
		n = len(p.ips)
	}
	out := make([]net.IP, 0, n)
	start := p.idx % len(p.ips)
	for i := 0; i < n; i++ {
		ip := p.ips[(start+i)%len(p.ips)]
		out = append(out, append(net.IP(nil), ip...))
	}
	p.idx = (p.idx + 1) % len(p.ips)
	return out
}

func decodeSecret(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	// Accept base64 secrets; otherwise treat the raw string bytes as the key.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	return []byte(s), nil
}

func parsePrefix(prefix string, fallbackCIDR string) (*net.IPNet, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		_, n, err := net.ParseCIDR(fallbackCIDR)
		return n, err
	}
	if strings.Contains(prefix, "/") {
		_, n, err := net.ParseCIDR(prefix)
		return n, err
	}
	// Allow "198.51.100." style prefixes for convenience.
	if strings.HasSuffix(prefix, ".") {
		prefix = prefix + "0/24"
		_, n, err := net.ParseCIDR(prefix)
		return n, err
	}
	ip := net.ParseIP(prefix)
	if ip == nil {
		return nil, fmt.Errorf("invalid prefix %q (expected CIDR or IP)", prefix)
	}
	if v4 := ip.To4(); v4 != nil {
		_, n, err := net.ParseCIDR(v4.String() + "/24")
		return n, err
	}
	_, n, err := net.ParseCIDR(ip.String() + "/64")
	return n, err
}

func deriveIP(secret []byte, idx uint32, v4net, v6net *net.IPNet) (net.IP, error) {
	return deriveIPWithEpoch(secret, "", idx, v4net, v6net)
}

func deriveIPWithEpoch(secret []byte, epoch string, idx uint32, v4net, v6net *net.IPNet) (net.IP, error) {
	var idxBuf [4]byte
	binary.BigEndian.PutUint32(idxBuf[:], idx)

	epoch = strings.TrimSpace(epoch)
	// HKDF(secret, info="stealthlink-phantom-v1:<epoch>:<idx>") -> 32 bytes
	info := append([]byte("stealthlink-phantom-v1:"), []byte(epoch)...)
	info = append(info, ':')
	info = append(info, idxBuf[:]...)
	h := hkdf.New(sha256.New, secret, nil, info)
	buf := make([]byte, 32)
	if _, err := io.ReadFull(h, buf); err != nil {
		return nil, err
	}

	useV6 := (buf[0] & 0x80) != 0
	if useV6 && v6net != nil {
		base := v6net.IP.To16()
		if base == nil {
			return nil, fmt.Errorf("invalid v6 network base")
		}
		ip := applyMask(base, v6net.Mask, buf[1:17])
		return ip, nil
	}
	if v4net == nil {
		return nil, fmt.Errorf("missing v4 network")
	}
	base := v4net.IP.To4()
	if base == nil {
		return nil, fmt.Errorf("invalid v4 network base")
	}
	ip := applyMask(base, v4net.Mask, buf[1:5])
	return ip, nil
}

func applyMask(base net.IP, mask net.IPMask, rnd []byte) net.IP {
	ip := append(net.IP(nil), base...)
	for i := 0; i < len(ip) && i < len(mask); i++ {
		var r byte
		if i < len(rnd) {
			r = rnd[i]
		}
		ip[i] = (ip[i] & mask[i]) | (r & ^mask[i])
	}
	return ip
}
