package faketcp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func TestFakeTCPDialListenDataFlow(t *testing.T) {
	cfg := &Config{
		MTU:           1400,
		WindowSize:    65535,
		RTO:           100 * time.Millisecond,
		Keepalive:     30 * time.Second,
		KeepaliveIdle: 60 * time.Second,
	}

	ln, err := Listen("127.0.0.1:0", cfg, smux.DefaultConfig(), "")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		sess, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer sess.Close()

		stream, err := sess.AcceptStream()
		if err != nil {
			serverErr <- err
			return
		}
		defer stream.Close()

		buf := make([]byte, 64)
		n, err := stream.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		if string(buf[:n]) != "ping" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		if _, err := stream.Write([]byte("pong")); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	dialer := NewDialer(cfg, smux.DefaultConfig(), "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sess, err := dialer.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer sess.Close()

	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("open stream failed: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	reply := make([]byte, 64)
	n, err := stream.Read(reply)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(reply[:n]) != "pong" {
		t.Fatalf("unexpected reply: %q", string(reply[:n]))
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}
}

func TestFakeTCPHandleRSTClosesSession(t *testing.T) {
	s := &fakeSession{
		state:   StateEstablished,
		readCh:  make(chan *packet, 1),
		writeCh: make(chan []byte, 1),
		closeCh: make(chan struct{}),
		readyCh: make(chan struct{}, 1),
	}

	s.handleRST(nil)

	if s.state != StateClosed {
		t.Fatalf("state=%v want=%v", s.state, StateClosed)
	}

	buf := make([]byte, 16)
	if _, err := s.Read(buf); err != io.EOF {
		t.Fatalf("read error=%v want=%v", err, io.EOF)
	}
}

func TestFakeTCPDialTimeoutWithoutServer(t *testing.T) {
	temp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := temp.LocalAddr().String()
	temp.Close()

	cfg := &Config{
		MTU:           1400,
		WindowSize:    65535,
		RTO:           50 * time.Millisecond,
		Keepalive:     30 * time.Second,
		KeepaliveIdle: 60 * time.Second,
	}
	dialer := NewDialer(cfg, smux.DefaultConfig(), "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := dialer.Dial(ctx, addr); err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}
