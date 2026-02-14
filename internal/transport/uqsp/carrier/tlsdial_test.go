package carrier

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestDialCarrierTLSWithFingerprint(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", testTLSConfig(t))
	if err != nil {
		if isSocketPermissionError(err) {
			t.Skipf("socket listen not permitted in this environment: %v", err)
		}
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != "ping" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverErr <- err
	}()

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "127.0.0.1",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialCarrierTLS(ctx, "tcp", ln.Addr().String(), cfg, "chrome")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: %q", string(reply))
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}
}

func TestDialCarrierTLSWithoutFingerprint(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", testTLSConfig(t))
	if err != nil {
		if isSocketPermissionError(err) {
			t.Skipf("socket listen not permitted in this environment: %v", err)
		}
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != "ping" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverErr <- err
	}()

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "127.0.0.1",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialCarrierTLS(ctx, "tcp", ln.Addr().String(), cfg, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: %q", string(reply))
	}
	_ = conn.Close()

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}
}

func isSocketPermissionError(err error) bool {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.Is(opErr.Err, syscall.EPERM) || errors.Is(opErr.Err, syscall.EACCES)
	}
	return false
}
