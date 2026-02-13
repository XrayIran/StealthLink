package faketcp

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"stealthlink/internal/transport/batch"
	"stealthlink/internal/transport/transportutil"

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

func TestIsTransientUDPBufferError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "enobufs", err: syscall.ENOBUFS, want: true},
		{name: "enomem", err: syscall.ENOMEM, want: true},
		{name: "string", err: errors.New("send failed: ENOBUFS"), want: true},
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

func TestFakeTCPReorderBufferDrainsContiguous(t *testing.T) {
	s := &fakeSession{
		state:      StateEstablished,
		readCh:     make(chan *packet, 256),
		writeCh:    make(chan []byte, 256),
		closeCh:    make(chan struct{}),
		readyCh:    make(chan struct{}, 1),
		reorderBuf: make(map[uint32]*packet),
		config:     DefaultConfig(),
		batchMgr:   batch.NewBatchIOManager(batch.BatchConfig{Enabled: false}),
	}

	// Simulate out-of-order: deliver seq 10 first, then seq 0
	s.rcvNxt = 0
	ooo := &packet{Type: PacketTypeData, Seq: 5, Payload: []byte("BBB")}
	s.handleData(ooo) // Out of order — should be buffered

	if len(s.reorderBuf) != 1 {
		t.Fatalf("expected 1 buffered packet, got %d", len(s.reorderBuf))
	}

	// Now deliver the expected seq=0.
	// sendPacket ACK errors are ignored by handleData, so no socket is required.
	first := &packet{Type: PacketTypeData, Seq: 0, Payload: []byte("AAAAA")}
	s.handleData(first)

	// rcvNxt should advance past both packets: 0+5=5, then 5+3=8
	if s.rcvNxt != 8 {
		t.Fatalf("rcvNxt=%d want=8", s.rcvNxt)
	}
	if len(s.reorderBuf) != 0 {
		t.Fatalf("reorderBuf should be empty, got %d entries", len(s.reorderBuf))
	}
}

func TestEncodePacketContainsTCPOptions(t *testing.T) {
	pkt := &packet{
		Type:    PacketTypeData,
		Seq:     100,
		Ack:     50,
		Payload: []byte("hello"),
	}
	data := encodePacket(pkt, FPProfileLinuxDefault)
	if len(data) != HeaderSize+5 {
		t.Fatalf("encoded length %d want %d", len(data), HeaderSize+5)
	}
	// Check MSS at offset 12-13
	mss := uint16(data[12])<<8 | uint16(data[13])
	if mss != 1460 {
		t.Fatalf("MSS=%d want=1460", mss)
	}
	// Check window scale at offset 14
	if data[14] != 7 {
		t.Fatalf("window_scale=%d want=7", data[14])
	}
	// Check SACK permitted at offset 15
	if data[15] != 1 {
		t.Fatalf("sack_permitted=%d want=1", data[15])
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

func TestBuildSessionCryptoDirectionalKeys(t *testing.T) {
	cfg := &Config{
		CryptoKey: "unit-test-secret",
		AEADMode:  "chacha20poly1305",
	}
	clientCrypto, err := buildSessionCrypto(cfg, true)
	if err != nil {
		t.Fatalf("client crypto: %v", err)
	}
	serverCrypto, err := buildSessionCrypto(cfg, false)
	if err != nil {
		t.Fatalf("server crypto: %v", err)
	}
	if clientCrypto == nil || serverCrypto == nil {
		t.Fatal("expected crypto contexts")
	}

	pkt := &packet{
		Type:   PacketTypeData,
		Seq:    123,
		Ack:    99,
		Window: 2048,
	}
	plain := []byte("payload")
	cipherText := clientCrypto.send.Seal(plain, pkt)
	got, err := serverCrypto.recv.Open(cipherText, pkt)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got=%q want=%q", got, plain)
	}
}
