//go:build linux
// +build linux

package batch

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestMain(m *testing.M) {
	if skipReason := udpRestrictionReason(); skipReason != "" {
		fmt.Fprintf(os.Stderr, "skipping batch tests: %s\n", skipReason)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func udpRestrictionReason() string {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err == nil {
		_ = conn.Close()
		return ""
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return err.Error()
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.EPERM) || errors.Is(opErr.Err, syscall.EACCES) {
			return err.Error()
		}
	}
	return ""
}
