package uqsp

import (
	"bytes"
	"testing"
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
