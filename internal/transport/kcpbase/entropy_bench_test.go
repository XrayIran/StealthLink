package kcpbase

import (
	"crypto/rand"
	"testing"
)

func BenchmarkCryptoRand(b *testing.B) {
	buf := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rand.Read(buf)
	}
}

func BenchmarkFastRandom(b *testing.B) {
	fast := NewEntropySource(ClassFast)
	buf := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = fast.Read(buf)
	}
}

func BenchmarkFastRandomInt64n(b *testing.B) {
	fast := NewEntropySource(ClassFast)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fast.Int64n(1000)
	}
}

func BenchmarkChaCha8(b *testing.B) {
	g := newChaCha8Generator()
	buf := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = g.Read(buf)
	}
}

func BenchmarkAESNI(b *testing.B) {
	g := newAESNIGenerator()
	buf := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = g.Read(buf)
	}
}
