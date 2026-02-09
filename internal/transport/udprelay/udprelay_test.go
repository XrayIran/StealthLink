package udprelay

import (
	"bytes"
	"testing"
	"time"
)

func TestDefaultSessionConfig(t *testing.T) {
	cfg := DefaultSessionConfig()
	if cfg.MTU != 1400 {
		t.Errorf("expected MTU 1400, got %d", cfg.MTU)
	}
	if cfg.WindowSize != 128 {
		t.Errorf("expected WindowSize 128, got %d", cfg.WindowSize)
	}
	if cfg.MaxRetries != 5 {
		t.Errorf("expected MaxRetries 5, got %d", cfg.MaxRetries)
	}
}

func TestSessionState(t *testing.T) {
	tests := []struct {
		state SessionState
		want  string
	}{
		{SessionStateInit, "init"},
		{SessionStateHandshaking, "handshaking"},
		{SessionStateEstablished, "established"},
		{SessionStateClosing, "closing"},
		{SessionStateClosed, "closed"},
		{SessionState(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("SessionState(%d).String() = %s, want %s", tt.state, got, tt.want)
		}
	}
}

func TestPacketHeaderEncodeDecode(t *testing.T) {
	original := &PacketHeader{
		SessionID: 12345,
		Type:      PacketTypeData,
		Flags:     0x01,
		SeqNum:    100,
		AckNum:    50,
		Length:    10,
	}

	encoded := original.Encode()
	if len(encoded) != PacketHeaderSize {
		t.Errorf("expected header size %d, got %d", PacketHeaderSize, len(encoded))
	}

	decoded, err := DecodePacketHeader(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID: got %d, want %d", decoded.SessionID, original.SessionID)
	}
	if decoded.Type != original.Type {
		t.Errorf("Type: got %d, want %d", decoded.Type, original.Type)
	}
	if decoded.SeqNum != original.SeqNum {
		t.Errorf("SeqNum: got %d, want %d", decoded.SeqNum, original.SeqNum)
	}
}

func TestPacketEncodeDecode(t *testing.T) {
	original := &Packet{
		Header: PacketHeader{
			SessionID: 999,
			Type:      PacketTypeData,
			SeqNum:    42,
		},
		Payload: []byte("hello world"),
	}

	encoded := original.Encode()
	decoded, err := DecodePacket(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Header.SessionID != original.Header.SessionID {
		t.Errorf("SessionID mismatch")
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Errorf("Payload mismatch: got %v, want %v", decoded.Payload, original.Payload)
	}
}

func TestFragmentHeaderEncodeDecode(t *testing.T) {
	fh := &FragmentHeader{
		FragID:     1,
		FragIndex:  2,
		FragTotal:  5,
		FragOffset: 100,
	}

	data := []byte("fragment data")
	encoded := fh.Encode(data)

	decodedFH, decodedData, err := DecodeFragment(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decodedFH.FragID != fh.FragID {
		t.Errorf("FragID: got %d, want %d", decodedFH.FragID, fh.FragID)
	}
	if decodedFH.FragIndex != fh.FragIndex {
		t.Errorf("FragIndex: got %d, want %d", decodedFH.FragIndex, fh.FragIndex)
	}
	if !bytes.Equal(decodedData, data) {
		t.Errorf("Data mismatch")
	}
}

func TestReassembler(t *testing.T) {
	r := NewReassembler(5 * time.Second)

	// Create fragments
	frag1 := &FragmentHeader{FragID: 1, FragIndex: 0, FragTotal: 3, FragOffset: 0}
	frag2 := &FragmentHeader{FragID: 1, FragIndex: 1, FragTotal: 3, FragOffset: 10}
	frag3 := &FragmentHeader{FragID: 1, FragIndex: 2, FragTotal: 3, FragOffset: 20}

	data1 := []byte("0123456789")
	data2 := []byte("abcdefghij")
	data3 := []byte("klmnopqrst")

	// Add first fragment (incomplete)
	complete, _ := r.AddFragment(frag1, data1)
	if complete {
		t.Error("expected incomplete after first fragment")
	}

	// Add third fragment (still incomplete)
	complete, _ = r.AddFragment(frag3, data3)
	if complete {
		t.Error("expected incomplete after third fragment")
	}

	// Add second fragment (complete)
	complete, reassembled := r.AddFragment(frag2, data2)
	if !complete {
		t.Error("expected complete after all fragments")
	}

	expected := append(append(data1, data2...), data3...)
	if !bytes.Equal(reassembled, expected) {
		t.Errorf("reassembled mismatch: got %d bytes, want %d bytes", len(reassembled), len(expected))
	}
}

func TestSlidingWindow(t *testing.T) {
	w := NewSlidingWindow(100)

	// Test sequence number generation
	seq1 := w.NextSendSeq()
	seq2 := w.NextSendSeq()
	if seq2 != seq1+1 {
		t.Errorf("expected seq2 = seq1 + 1, got %d vs %d", seq2, seq1)
	}

	// Test expected sequence
	if w.ExpectedSeq() != 0 {
		t.Errorf("expected ExpectedSeq = 0, got %d", w.ExpectedSeq())
	}

	// Test IsExpected
	if !w.IsExpected(0) {
		t.Error("expected seq 0 to be expected")
	}
	if !w.IsExpected(5) {
		t.Error("expected seq 5 to be expected (future)")
	}

	// Test advancing receive window
	w.AdvanceRecv(5)
	if w.ExpectedSeq() != 6 {
		t.Errorf("expected ExpectedSeq = 6, got %d", w.ExpectedSeq())
	}

	// Test pending
	w.AddPending(1, []byte("test"))
	w.AddPending(2, []byte("test2"))
	if w.PendingCount() != 2 {
		t.Errorf("expected 2 pending, got %d", w.PendingCount())
	}

	// Test ACK
	w.Ack(1)
	if w.PendingCount() != 1 {
		t.Errorf("expected 1 pending after ACK, got %d", w.PendingCount())
	}
}

func TestRTTEstimator(t *testing.T) {
	e := NewRTTEstimator()

	initialRTT := e.RTT()
	if initialRTT != 100*time.Millisecond {
		t.Errorf("expected initial RTT 100ms, got %v", initialRTT)
	}

	// Update with samples
	e.Update(50 * time.Millisecond)
	e.Update(60 * time.Millisecond)
	e.Update(55 * time.Millisecond)

	rtt := e.RTT()
	if rtt < 40*time.Millisecond || rtt > 70*time.Millisecond {
		t.Errorf("RTT out of expected range: %v", rtt)
	}

	rto := e.RTO()
	if rto < rtt {
		t.Errorf("RTO should be >= RTT, got %v vs %v", rto, rtt)
	}
}

func TestReplayWindow(t *testing.T) {
	rw := NewReplayWindow(1 << 20)

	// First packet should be accepted
	if !rw.CheckAndAdd(100) {
		t.Error("expected first packet to be accepted")
	}

	// Same packet should be rejected (duplicate)
	if rw.CheckAndAdd(100) {
		t.Error("expected duplicate to be rejected")
	}

	// New packet should be accepted
	if !rw.CheckAndAdd(101) {
		t.Error("expected new packet to be accepted")
	}

	// Out of order packet within window should be accepted
	if !rw.CheckAndAdd(99) {
		t.Error("expected out-of-order packet to be accepted")
	}

	// Now 99 should be rejected (already seen)
	if rw.CheckAndAdd(99) {
		t.Error("expected duplicate out-of-order packet to be rejected")
	}

	// Very old packet (outside 64-packet window) should be rejected
	// After accepting 101, base is 101. Packet 30 is 71 behind.
	if rw.CheckAndAdd(30) {
		t.Error("expected very old packet to be rejected")
	}
}

func TestRelay(t *testing.T) {
	cfg := &RelayConfig{
		LocalAddr:              "127.0.0.1:0",
		MTU:                    1400,
		MaxSessions:            10,
		SessionTimeout:         5 * time.Second,
		EnableFairness:         true,
		EnableReplayProtection: true,
	}

	relay, err := NewRelay(cfg)
	if err != nil {
		t.Fatalf("failed to create relay: %v", err)
	}
	defer relay.Close()

	// Check address is assigned
	if relay.Addr() == nil {
		t.Error("expected relay to have address")
	}

	// Check initial stats
	stats := relay.GetStats()
	if stats.SessionCount != 0 {
		t.Errorf("expected 0 sessions, got %d", stats.SessionCount)
	}
}

func TestRelaySessionLifecycle(t *testing.T) {
	// This test would need actual UDP communication
	// For now just test the basic structure
	t.Log("Session lifecycle test - requires network communication")
}

func TestSessionIsIdle(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.IdleTimeout = 100 * time.Millisecond

	s := NewSession(1, nil, cfg)

	// New session should not be idle
	if s.IsIdle() {
		t.Error("new session should not be idle")
	}

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	if !s.IsIdle() {
		t.Error("session should be idle after timeout")
	}
}

func TestDefaultRelayConfig(t *testing.T) {
	cfg := DefaultRelayConfig()
	if cfg.MTU != 1400 {
		t.Errorf("expected MTU 1400, got %d", cfg.MTU)
	}
	if cfg.MaxSessions != 1000 {
		t.Errorf("expected MaxSessions 1000, got %d", cfg.MaxSessions)
	}
	if !cfg.EnableFairness {
		t.Error("expected EnableFairness to be true")
	}
}

func TestSessionFragmentation(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.MaxFragmentSize = 50
	cfg.EnableFragment = true

	s := NewSession(1, nil, cfg)

	// Large data that needs fragmentation
	largeData := make([]byte, 200)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	fragments := s.fragment(largeData)

	// Should produce multiple fragments
	if len(fragments) < 2 {
		t.Errorf("expected multiple fragments, got %d", len(fragments))
	}

	// Each fragment should be within limit
	for i, f := range fragments {
		if len(f.Payload) > cfg.MaxFragmentSize {
			t.Errorf("fragment %d exceeds max size: %d > %d", i, len(f.Payload), cfg.MaxFragmentSize)
		}
	}
}

func BenchmarkPacketEncode(b *testing.B) {
	pkt := &Packet{
		Header: PacketHeader{
			SessionID: 12345,
			Type:      PacketTypeData,
			SeqNum:    100,
		},
		Payload: make([]byte, 1000),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pkt.Encode()
	}
}

func BenchmarkPacketDecode(b *testing.B) {
	pkt := &Packet{
		Header: PacketHeader{
			SessionID: 12345,
			Type:      PacketTypeData,
			SeqNum:    100,
		},
		Payload: make([]byte, 1000),
	}
	data := pkt.Encode()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodePacket(data)
	}
}

func BenchmarkReplayWindow(b *testing.B) {
	rw := NewReplayWindow(1 << 20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rw.CheckAndAdd(uint32(i))
	}
}
