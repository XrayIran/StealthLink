package icmptun

import (
	"errors"
	"syscall"
	"testing"

	"stealthlink/internal/transport/transportutil"
)

func TestXorPayloadRoundTrip(t *testing.T) {
	orig := []byte("hello-icmp")
	enc := xorPayload(orig, 1234)
	dec := xorPayload(enc, 1234)
	if string(dec) != string(orig) {
		t.Fatalf("xor roundtrip mismatch: got=%q want=%q", dec, orig)
	}
}

func TestICMPConnWriteChunksByMTU(t *testing.T) {
	cfg := Config{MTU: 64, WindowSize: 64}
	cfg.ApplyDefaults()
	chunks := 0
	bytes := 0
	maxChunk := cfg.MTU - 8
	if maxChunk < 64 {
		maxChunk = 64
	}
	c := newICMPConn(cfg, nil, nil, func(p []byte) error {
		chunks++
		bytes += len(p)
		if len(p) > maxChunk {
			t.Fatalf("chunk exceeds payload mtu: %d", len(p))
		}
		return nil
	}, nil)
	defer c.Close()

	in := make([]byte, 1000)
	n, err := c.Write(in)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len(in) || bytes != len(in) {
		t.Fatalf("write length mismatch: n=%d bytes=%d want=%d", n, bytes, len(in))
	}
	if chunks <= 1 {
		t.Fatalf("expected chunking, got chunks=%d", chunks)
	}
}

func TestSocketBufferBounds(t *testing.T) {
	if v := socketBufferBytes(1500, 1); v < 1<<20 {
		t.Fatalf("expected min 1MB, got %d", v)
	}
	if v := socketBufferBytes(1500, 50000); v > 16<<20 {
		t.Fatalf("expected max 16MB, got %d", v)
	}
}

func TestIsTransientICMPBufferError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "enobufs", err: syscall.ENOBUFS, want: true},
		{name: "enomem", err: syscall.ENOMEM, want: true},
		{name: "string", err: errors.New("socket: ENOBUFS"), want: true},
		{name: "other", err: errors.New("permission denied"), want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := transportutil.IsTransientBufferError(tc.err); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
