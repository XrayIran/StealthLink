package uqsp

import (
	"bytes"
	"testing"
	"time"
)

func TestDatagramFragmenterAndReassembler(t *testing.T) {
	payload := bytes.Repeat([]byte("abc123"), 600) // > MaxFragmentSize
	frag := NewDatagramFragmenter()
	reasm := NewDatagramReassembler()

	frags := frag.Fragment(42, payload)
	if len(frags) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(frags))
	}

	var out []byte
	for _, f := range frags {
		d, err := reasm.AddFragment(f)
		if err != nil {
			t.Fatalf("add fragment: %v", err)
		}
		if d != nil {
			out = d
		}
	}

	if !bytes.Equal(out, payload) {
		t.Fatalf("reassembled payload mismatch got=%d want=%d", len(out), len(payload))
	}
}

func TestHysteriaDatagramEncodeDecode(t *testing.T) {
	in := &HysteriaDatagram{PacketID: 7, FragmentID: 1, FragmentCount: 2, SessionID: 99, Payload: []byte("ping")}
	enc := in.Encode()
	var out HysteriaDatagram
	if err := out.Decode(enc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.PacketID != in.PacketID || out.FragmentID != in.FragmentID || out.FragmentCount != in.FragmentCount || out.SessionID != in.SessionID || string(out.Payload) != string(in.Payload) {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", out, *in)
	}
}

func TestDatagramReassemblerTimeoutEviction(t *testing.T) {
	reasm := NewDatagramReassemblerWithConfig(20*time.Millisecond, 1<<20)

	_, err := reasm.AddFragment(&DatagramFragment{
		SessionID:      1,
		FragmentID:     9,
		FragmentIndex:  0,
		TotalFragments: 2,
		Data:           []byte("first"),
	})
	if err != nil {
		t.Fatalf("add first fragment: %v", err)
	}

	time.Sleep(30 * time.Millisecond)

	out, err := reasm.AddFragment(&DatagramFragment{
		SessionID:      1,
		FragmentID:     9,
		FragmentIndex:  1,
		TotalFragments: 2,
		Data:           []byte("second"),
	})
	if err != nil {
		t.Fatalf("add expired companion fragment: %v", err)
	}
	if out != nil {
		t.Fatal("expected incomplete reassembly after timeout eviction")
	}
}

func TestDatagramReassemblerDeduplicatesFragments(t *testing.T) {
	reasm := NewDatagramReassembler()

	f0 := &DatagramFragment{
		SessionID:      2,
		FragmentID:     3,
		FragmentIndex:  0,
		TotalFragments: 2,
		Data:           []byte("A"),
	}
	f0dup := &DatagramFragment{
		SessionID:      2,
		FragmentID:     3,
		FragmentIndex:  0,
		TotalFragments: 2,
		Data:           []byte("A"),
	}
	f1 := &DatagramFragment{
		SessionID:      2,
		FragmentID:     3,
		FragmentIndex:  1,
		TotalFragments: 2,
		Data:           []byte("B"),
	}

	if _, err := reasm.AddFragment(f0); err != nil {
		t.Fatalf("add f0: %v", err)
	}
	if _, err := reasm.AddFragment(f0dup); err != nil {
		t.Fatalf("add duplicate f0: %v", err)
	}
	out, err := reasm.AddFragment(f1)
	if err != nil {
		t.Fatalf("add f1: %v", err)
	}
	if string(out) != "AB" {
		t.Fatalf("got %q want AB", string(out))
	}
}

func TestDatagramReassemblerRejectsOversizeFragment(t *testing.T) {
	reasm := NewDatagramReassemblerWithConfig(30*time.Second, 64)
	_, err := reasm.AddFragment(&DatagramFragment{
		SessionID:      99,
		FragmentID:     1,
		FragmentIndex:  0,
		TotalFragments: 1,
		Data:           bytes.Repeat([]byte("x"), 80),
	})
	if err == nil {
		t.Fatal("expected oversize fragment rejection")
	}
}

func TestDatagramFragmenterPaddingAppliedBeforeFragmentation(t *testing.T) {
	frag := &DatagramFragmenter{
		nextID:     1,
		PaddingMin: 10,
		PaddingMax: 10,
	}
	reasm := NewDatagramReassembler()

	payload := []byte("short payload")
	frags := frag.Fragment(1, payload)

	// With padding, each fragment contains: [origLen(2)][data][padding]
	// Total = 2 + len(payload) + 10 = 25 bytes, fits in one fragment
	if len(frags) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(frags))
	}

	// The padded data should start with 2-byte length prefix
	data := frags[0].Data
	if len(data) < 2+len(payload) {
		t.Fatalf("padded data too short: %d", len(data))
	}
	origLen := int(data[0])<<8 | int(data[1])
	if origLen != len(payload) {
		t.Fatalf("original length header mismatch: got %d want %d", origLen, len(payload))
	}
	if !bytes.Equal(data[2:2+origLen], payload) {
		t.Fatal("payload mismatch after padding")
	}

	// Reassembly returns the padded bytes (caller strips padding)
	out, err := reasm.AddFragment(frags[0])
	if err != nil {
		t.Fatalf("add fragment: %v", err)
	}
	if out == nil {
		t.Fatal("expected complete reassembly")
	}
}

func TestDatagramFragmenterNoPaddingByDefault(t *testing.T) {
	frag := NewDatagramFragmenter()
	reasm := NewDatagramReassembler()

	payload := []byte("no padding test")
	frags := frag.Fragment(1, payload)
	if len(frags) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(frags))
	}

	out, err := reasm.AddFragment(frags[0])
	if err != nil {
		t.Fatalf("add fragment: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("payload mismatch without padding")
	}
}
