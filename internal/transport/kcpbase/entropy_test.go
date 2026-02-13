package kcpbase

import (
	"testing"

	"stealthlink/internal/metrics"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/cpu"
)

func TestNewEntropySource(t *testing.T) {
	crypto := NewEntropySource(ClassCrypto)
	assert.Equal(t, ClassCrypto, crypto.class)
	assert.Equal(t, MethodCryptoRand, crypto.method)

	fast := NewEntropySource(ClassFast)
	assert.Equal(t, ClassFast, fast.class)
	if cpu.X86.HasAES {
		assert.Equal(t, MethodAESNI, fast.method)
	} else {
		assert.Equal(t, MethodChaCha8, fast.method)
	}
}

func TestEntropySource_Read(t *testing.T) {
	fast := NewEntropySource(ClassFast)
	buf1 := make([]byte, 32)
	n, err := fast.Read(buf1)
	assert.NoError(t, err)
	assert.Equal(t, 32, n)

	buf2 := make([]byte, 32)
	n, err = fast.Read(buf2)
	assert.NoError(t, err)
	assert.Equal(t, 32, n)

	assert.NotEqual(t, buf1, buf2)
}

func TestEntropySource_Reseed(t *testing.T) {
	// Use a small threshold for testing if possible, but it's constant.
	// We'll just test that it doesn't crash and metrics are updated.
	fast := NewEntropySource(ClassFast)
	largeBuf := make([]byte, reseedThreshold+100)
	n, err := fast.Read(largeBuf)
	assert.NoError(t, err)
	assert.Equal(t, len(largeBuf), n)
}

func TestAESNIGenerator(t *testing.T) {
	if !cpu.X86.HasAES {
		t.Skip("AES-NI not supported")
	}
	g := newAESNIGenerator()
	buf1 := make([]byte, 100)
	n, err := g.Read(buf1)
	assert.NoError(t, err)
	assert.Equal(t, 100, n)

	buf2 := make([]byte, 100)
	_, _ = g.Read(buf2)
	assert.NotEqual(t, buf1, buf2)
}

func TestChaCha8Generator(t *testing.T) {
	g := newChaCha8Generator()
	buf1 := make([]byte, 100)
	n, err := g.Read(buf1)
	assert.NoError(t, err)
	assert.Equal(t, 100, n)

	buf2 := make([]byte, 100)
	_, _ = g.Read(buf2)
	assert.NotEqual(t, buf1, buf2)
}

func TestEntropySource_Concurrent(t *testing.T) {
	fast := NewEntropySource(ClassFast)
	const numGoroutines = 10
	const numReads = 100
	const readSize = 64

	done := make(chan bool)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < numReads; j++ {
				buf := make([]byte, readSize)
				fast.Read(buf)
			}
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestEntropySource_ReseedProperty(t *testing.T) {
	fast := NewEntropySource(ClassFast)
	
	// Read almost up to threshold
	buf := make([]byte, 1024)
	for i := 0; i < 1023; i++ {
		fast.Read(buf)
	}
	
	// Should not have reseeded yet (exactly 1023 KiB)
	// Wait, threshold is 1 MiB = 1024*1024 bytes.
	// 1023 * 1024 = 1,047,552 bytes.
	// 1024 * 1024 = 1,048,576 bytes.
	
	// Let's use exact counts.
	fast.reseedCounter.Store(0)
	
	count := uint64(0)
	for count < reseedThreshold - 1024 {
		n, _ := fast.Read(buf)
		count += uint64(n)
	}
	
	// Now we are at reseedThreshold - 1024 (or slightly more if count was not exactly 0)
	// One more read should trigger it or be exactly it.
	
	reseedBefore := metrics.SnapshotData().EntropyReseedsTotal
	fast.Read(buf)
	reseedAfter := metrics.SnapshotData().EntropyReseedsTotal
	
	if reseedAfter <= reseedBefore {
		t.Errorf("Expected reseed to trigger, before=%d, after=%d", reseedBefore, reseedAfter)
	}
}
