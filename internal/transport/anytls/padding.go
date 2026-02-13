package anytls

import (
	"crypto/rand"
	"math/big"
	"strconv"
	"strings"
)

// PaddingConfig defines padding settings for AnyTLS.
type PaddingConfig struct {
	Scheme string   // "random" | "fixed" | "burst" | "adaptive" or custom line array
	Min    int      // default: 100
	Max    int      // default: 900
	Lines  []string // raw sing-box format lines
}

// Generator generates padding lengths based on a scheme.
type Generator struct {
	cfg    PaddingConfig
	ranges []paddingRange
	index  int
}

type paddingRange struct {
	min int
	max int
}

// NewGenerator creates a new padding generator.
func NewGenerator(cfg PaddingConfig) *Generator {
	if cfg.Min == 0 {
		cfg.Min = 100
	}
	if cfg.Max == 0 {
		cfg.Max = 900
	}

	g := &Generator{cfg: cfg}
	g.compile()
	return g
}

func (g *Generator) compile() {
	switch g.cfg.Scheme {
	case "random":
		g.ranges = []paddingRange{{min: g.cfg.Min, max: g.cfg.Max}}
	case "fixed":
		g.ranges = []paddingRange{{min: g.cfg.Max, max: g.cfg.Max}}
	case "burst":
		// [0, 0, 0, 500-1500] (bursty pattern)
		g.ranges = []paddingRange{
			{min: 0, max: 0},
			{min: 0, max: 0},
			{min: 0, max: 0},
			{min: 500, max: 1500},
		}
	case "adaptive":
		// Placeholder for adaptive: use random with a wider range for now
		g.ranges = []paddingRange{{min: g.cfg.Min, max: g.cfg.Max * 2}}
	default:
		if len(g.cfg.Lines) > 0 {
			for _, line := range g.cfg.Lines {
				g.ranges = append(g.ranges, parseRange(line))
			}
		} else {
			// Default to random
			g.ranges = []paddingRange{{min: g.cfg.Min, max: g.cfg.Max}}
		}
	}
}

func parseRange(line string) paddingRange {
	line = strings.TrimSpace(line)
	if strings.Contains(line, "-") {
		parts := strings.Split(line, "-")
		if len(parts) == 2 {
			min, _ := strconv.Atoi(parts[0])
			max, _ := strconv.Atoi(parts[1])
			return paddingRange{min: min, max: max}
		}
	}
	val, _ := strconv.Atoi(line)
	return paddingRange{min: val, max: val}
}

// Next returns the next padding length.
func (g *Generator) Next() int {
	if len(g.ranges) == 0 {
		return 0
	}

	r := g.ranges[g.index]
	g.index = (g.index + 1) % len(g.ranges)

	if r.min == r.max {
		return r.min
	}

	diff := int64(r.max - r.min + 1)
	n, _ := rand.Int(rand.Reader, big.NewInt(diff))
	return r.min + int(n.Int64())
}
