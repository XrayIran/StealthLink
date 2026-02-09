package uqsp

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestSalamanderOverlayRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	o := &SalamanderOverlay{EnabledField: true, Key: "test-key"}
	ca, err := o.Apply(a)
	if err != nil {
		t.Fatalf("apply A: %v", err)
	}
	cb, err := o.Apply(b)
	if err != nil {
		t.Fatalf("apply B: %v", err)
	}

	want := []byte("hello salamander")
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(want))
		_, err := io.ReadFull(cb, buf)
		if err != nil {
			done <- err
			return
		}
		if string(buf) != string(want) {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- nil
	}()

	if _, err := ca.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestMorphingOverlayRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	o := &MorphingOverlay{EnabledField: true, PaddingMin: 4, PaddingMax: 16}
	ca, err := o.Apply(a)
	if err != nil {
		t.Fatalf("apply A: %v", err)
	}
	cb, err := o.Apply(b)
	if err != nil {
		t.Fatalf("apply B: %v", err)
	}

	want := []byte("hello morphing overlay")
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(want))
		_, err := io.ReadFull(cb, buf)
		if err != nil {
			done <- err
			return
		}
		if string(buf) != string(want) {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- nil
	}()

	if _, err := ca.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestPQSigOverlayHandshakeAndData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		serverCh <- c
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer a.Close()
	b := <-serverCh
	defer b.Close()

	o := NewPQSigOverlay()
	ca, err := o.Apply(a)
	if err != nil {
		t.Fatalf("apply A: %v", err)
	}
	cb, err := o.Apply(b)
	if err != nil {
		t.Fatalf("apply B: %v", err)
	}

	errCh := make(chan error, 2)
	go func() {
		_, err := ca.Write([]byte("client-data"))
		errCh <- err
	}()
	go func() {
		_, err := cb.Write([]byte("server-data"))
		errCh <- err
	}()

	bufA := make([]byte, 64)
	bufB := make([]byte, 64)
	_ = ca.SetReadDeadline(time.Now().Add(5 * time.Second))
	_ = cb.SetReadDeadline(time.Now().Add(5 * time.Second))
	nA, err := ca.Read(bufA)
	if err != nil {
		t.Fatalf("A read: %v", err)
	}
	nB, err := cb.Read(bufB)
	if err != nil {
		t.Fatalf("B read: %v", err)
	}

	if string(bufA[:nA]) != "server-data" {
		t.Fatalf("A got %q", string(bufA[:nA]))
	}
	if string(bufB[:nB]) != "client-data" {
		t.Fatalf("B got %q", string(bufB[:nB]))
	}

	for i := 0; i < 2; i++ {
		if werr := <-errCh; werr != nil {
			t.Fatalf("write err: %v", werr)
		}
	}
}

func TestNoizeOverlayWrapsAndCloses(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	o := &NoizeOverlay{EnabledField: true, PaddingMin: 1, PaddingMax: 8, MorphingEnabled: true}
	c, err := o.Apply(a)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if c == nil {
		t.Fatal("nil conn")
	}
	_ = c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, _ = c.Write([]byte("x"))
	_ = c.Close()
}
