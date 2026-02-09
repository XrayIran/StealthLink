package uqsp

import (
	"bytes"
	"net"
	"testing"
)

func BenchmarkMorphingOverlayWriteRead(b *testing.B) {
	a, c := net.Pipe()
	defer a.Close()
	defer c.Close()

	o := &MorphingOverlay{EnabledField: true, PaddingMin: 8, PaddingMax: 64}
	ca, err := o.Apply(a)
	if err != nil {
		b.Fatalf("apply A: %v", err)
	}
	cb, err := o.Apply(c)
	if err != nil {
		b.Fatalf("apply B: %v", err)
	}

	payload := bytes.Repeat([]byte("p"), 1024)
	recv := make([]byte, len(payload))

	done := make(chan struct{})
	go func() {
		for i := 0; i < b.N; i++ {
			_, _ = cb.Read(recv)
		}
		close(done)
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ca.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	b.StopTimer()
	<-done
}

func BenchmarkDatagramFragmentReassemble(b *testing.B) {
	frag := NewDatagramFragmenter()
	reasm := NewDatagramReassembler()
	payload := bytes.Repeat([]byte("abcdef"), 1200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frags := frag.Fragment(uint32(i+1), payload)
		for _, f := range frags {
			out, err := reasm.AddFragment(f)
			if err != nil {
				b.Fatalf("reassemble: %v", err)
			}
			if out != nil && len(out) != len(payload) {
				b.Fatalf("len(out)=%d want=%d", len(out), len(payload))
			}
		}
	}
}
