//go:build !cgo

package rawtcp

import "testing"

func TestAvailableNoCgoBuild(t *testing.T) {
	ok, reason := Available()
	if ok {
		t.Fatalf("Available()=%v reason=%q, want ok=false", ok, reason)
	}
	if reason == "" {
		t.Fatalf("expected non-empty reason when unavailable")
	}
}

