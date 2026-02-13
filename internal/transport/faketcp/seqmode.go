package faketcp

import "stealthlink/internal/transport/kcpbase"

type SeqMode int

const (
	SeqModeStatic SeqMode = iota
	SeqModeIncrement
	SeqModeRandom
	SeqModeCombined
	SeqModeFullRandom
)

type SeqGenerator struct {
	mode      SeqMode
	base      uint32
	increment uint32
	counter   uint32
}

func NewSeqGenerator(mode SeqMode, base uint32) *SeqGenerator {
	return &SeqGenerator{
		mode:      mode,
		base:      base,
		increment: 1,
	}
}

func (g *SeqGenerator) Next() uint32 {
	switch g.mode {
	case SeqModeStatic:
		return g.base
	case SeqModeIncrement:
		g.counter++
		return g.base + g.counter*g.increment
	case SeqModeRandom:
		return uint32(kcpbase.FastRandom.Int64n(1 << 32))
	case SeqModeCombined:
		if g.counter%2 == 0 {
			g.counter++
			return g.base + g.counter*g.increment
		}
		g.counter++
		return uint32(kcpbase.FastRandom.Int64n(1 << 32))
	case SeqModeFullRandom:
		g.counter++
		offset := uint32(kcpbase.FastRandom.Int64n(10000))
		return g.base + g.counter*offset
	default:
		return g.base + g.counter
	}
}

func (g *SeqGenerator) SetIncrement(inc uint32) {
	g.increment = inc
}

func (g *SeqGenerator) Reset(base uint32) {
	g.base = base
	g.counter = 0
}

type SeqModeConfig struct {
	Mode      SeqMode `yaml:"mode"`
	BaseSeq   uint32  `yaml:"base_seq"`
	Increment uint32  `yaml:"increment"`
}

func DefaultSeqModeConfig() SeqModeConfig {
	return SeqModeConfig{
		Mode:      SeqModeIncrement,
		BaseSeq:   0,
		Increment: 1,
	}
}

func ParseSeqMode(s string) SeqMode {
	switch s {
	case "static", "0":
		return SeqModeStatic
	case "increment", "incremental", "1":
		return SeqModeIncrement
	case "random", "2":
		return SeqModeRandom
	case "combined", "3":
		return SeqModeCombined
	case "fullrandom", "full_random", "4":
		return SeqModeFullRandom
	default:
		return SeqModeIncrement
	}
}

func (m SeqMode) String() string {
	switch m {
	case SeqModeStatic:
		return "static"
	case SeqModeIncrement:
		return "increment"
	case SeqModeRandom:
		return "random"
	case SeqModeCombined:
		return "combined"
	case SeqModeFullRandom:
		return "fullrandom"
	default:
		return "unknown"
	}
}
