//go:build cgo

package rawtcp

import "testing"

func TestAvailableCgoBuild(t *testing.T) {
	ok, reason := Available()
	if !ok {
		t.Fatalf("Available()=%v reason=%q, want ok=true", ok, reason)
	}
}

