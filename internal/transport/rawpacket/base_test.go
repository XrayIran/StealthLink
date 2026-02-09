package rawpacket

import (
	"net"
	"testing"
	"time"
)

type mockPacketConn struct {
	lastWrite []byte
	lastAddr  net.Addr
	readBuf   []byte
	readAddr  net.Addr
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n = copy(p, m.readBuf)
	return n, m.readAddr, nil
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	m.lastWrite = append(m.lastWrite[:0], p...)
	m.lastAddr = addr
	return len(p), nil
}

func (m *mockPacketConn) Close() error { return nil }
func (m *mockPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12000}
}
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestPacketConnTCPRoundTripHelpers(t *testing.T) {
	mock := &mockPacketConn{}
	cfg := DefaultConfig()
	cfg.RemoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22000}

	pc := NewPacketConn(mock, TypeRawTCP, cfg)
	payload := []byte("hello")
	n, err := pc.writeTCPPacket(payload)
	if err != nil {
		t.Fatalf("writeTCPPacket: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("write bytes=%d want=%d", n, len(payload))
	}
	if len(mock.lastWrite) <= 20 {
		t.Fatalf("unexpected TCP packet size: %d", len(mock.lastWrite))
	}

	out := make([]byte, 64)
	got, err := pc.processTCPPacket(mock.lastWrite, cfg.RemoteAddr, out)
	if err != nil {
		t.Fatalf("processTCPPacket: %v", err)
	}
	if string(out[:got]) != string(payload) {
		t.Fatalf("payload mismatch got=%q want=%q", out[:got], payload)
	}
}

func TestPacketConnICMPRoundTripHelpers(t *testing.T) {
	mock := &mockPacketConn{}
	cfg := DefaultConfig()
	cfg.Type = TypeICMP
	cfg.ICMP.Obfuscate = true
	cfg.ICMP.ObfuscationKey = "k"
	cfg.RemoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 33000}

	pc := NewPacketConn(mock, TypeICMP, cfg)
	payload := []byte("ping-payload")
	n, err := pc.writeICMPPacket(payload)
	if err != nil {
		t.Fatalf("writeICMPPacket: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("write bytes=%d want=%d", n, len(payload))
	}

	out := make([]byte, 64)
	got, err := pc.processICMPPacket(mock.lastWrite, cfg.RemoteAddr, out)
	if err != nil {
		t.Fatalf("processICMPPacket: %v", err)
	}
	if string(out[:got]) != string(payload) {
		t.Fatalf("payload mismatch got=%q want=%q", out[:got], payload)
	}
}
