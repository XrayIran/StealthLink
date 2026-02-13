package kcpbase

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	mathrand "math/rand/v2"
	"stealthlink/internal/metrics"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/cpu"
)

// Entropy classes
const (
	ClassCrypto = "crypto"
	ClassFast   = "fast"
)

// Entropy methods
const (
	MethodAESNI      = "aes-ni"
	MethodChaCha8    = "chacha8"
	MethodCryptoRand = "crypto-rand"
)

var (
	// CryptoRandom is a secure entropy source for keys and nonces
	CryptoRandom *EntropySource
	// FastRandom is a hardware-accelerated entropy source for padding and jitter
	FastRandom *EntropySource
)

func init() {
	CryptoRandom = NewEntropySource(ClassCrypto)
	FastRandom = NewEntropySource(ClassFast)
}

const reseedThreshold = 1024 * 1024 // 1 MiB

// EntropySource provides fast random number generation
type EntropySource struct {
	class         string
	method        string
	generator     generator
	reseedCounter atomic.Uint64
	mu            sync.Mutex
}

type generator interface {
	Read(p []byte) (n int, err error)
	Reseed() error
}

// NewEntropySource creates a new entropy source for the given class
func NewEntropySource(class string) *EntropySource {
	method := MethodCryptoRand
	var gen generator

	if class == ClassFast {
		if cpu.X86.HasAES {
			method = MethodAESNI
			gen = newAESNIGenerator()
		} else {
			method = MethodChaCha8
			gen = newChaCha8Generator()
		}
	} else {
		gen = &cryptoRandGenerator{}
	}

	metrics.SetEntropyMethod(method, true)

	return &EntropySource{
		class:     class,
		method:    method,
		generator: gen,
	}
}

func (s *EntropySource) Read(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, err = s.generator.Read(p)
	if err != nil {
		return n, err
	}

	metrics.AddEntropyBytes(int64(n), s.class)

	newVal := s.reseedCounter.Add(uint64(n))
	if newVal >= reseedThreshold {
		s.reseedCounter.Store(0)
		_ = s.generator.Reseed()
		metrics.IncEntropyReseeds()
	}

	return n, nil
}

// Int64n returns a random number in [0, max). It uses Read internally.
func (s *EntropySource) Int64n(max int64) int64 {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	_, _ = s.Read(b[:])
	val := binary.LittleEndian.Uint64(b[:])
	return int64(val % uint64(max))
}

// AES-NI Generator
type aesNIGenerator struct {
	block   cipher.Block
	counter uint64
	buffer  [aes.BlockSize]byte
	pos     int
}

func newAESNIGenerator() *aesNIGenerator {
	g := &aesNIGenerator{}
	_ = g.Reseed()
	return g
}

func (g *aesNIGenerator) Reseed() error {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	g.block = block
	g.counter = 0
	g.pos = aes.BlockSize
	return nil
}

func (g *aesNIGenerator) Read(p []byte) (n int, err error) {
	n = 0
	for n < len(p) {
		if g.pos >= aes.BlockSize {
			var input [aes.BlockSize]byte
			binary.LittleEndian.PutUint64(input[:8], g.counter)
			g.counter++
			g.block.Encrypt(g.buffer[:], input[:])
			g.pos = 0
		}
		
		toCopy := copy(p[n:], g.buffer[g.pos:])
		n += toCopy
		g.pos += toCopy
	}
	return n, nil
}

// ChaCha8 Generator
type chacha8Generator struct {
	source *mathrand.ChaCha8
}

func newChaCha8Generator() *chacha8Generator {
	g := &chacha8Generator{}
	_ = g.Reseed()
	return g
}

func (g *chacha8Generator) Reseed() error {
	var seed [32]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return err
	}
	g.source = mathrand.NewChaCha8(seed)
	return nil
}

func (g *chacha8Generator) Read(p []byte) (n int, err error) {
	// Use math/rand/v2 functionality efficiently
	for i := 0; i < len(p); i += 8 {
		val := g.source.Uint64()
		if len(p)-i >= 8 {
			binary.LittleEndian.PutUint64(p[i:], val)
		} else {
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], val)
			copy(p[i:], buf[:len(p)-i])
		}
	}
	return len(p), nil
}

// Crypto Rand Generator
type cryptoRandGenerator struct{}

func (g *cryptoRandGenerator) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

func (g *cryptoRandGenerator) Reseed() error {
	return nil // crypto/rand doesn't need manual reseed
}
