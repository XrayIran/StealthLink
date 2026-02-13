package rawtcp

import (
	"errors"
	"syscall"
	"testing"

	"stealthlink/internal/transport/transportutil"
)

func TestIsTransientBufferError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "enobufs", err: syscall.ENOBUFS, want: true},
		{name: "enomem", err: syscall.ENOMEM, want: true},
		{name: "wrapped", err: errors.New("pcap write failed: ENOBUFS"), want: true},
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
