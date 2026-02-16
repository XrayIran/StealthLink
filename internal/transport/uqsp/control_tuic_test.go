package uqsp

import (
	"testing"
	"time"
)

func TestZeroRTTTokenEncodeDecodeAndValidity(t *testing.T) {
	created := time.Now().Unix() - 5
	expires := time.Now().Unix() + 60
	var tok ZeroRTTToken
	tok.SessionID = 42
	tok.CreatedAt = created
	tok.ExpiresAt = expires
	tok.Capabilities = CapabilityDatagram | CapabilityPostQuantum
	for i := range tok.Token {
		tok.Token[i] = byte(i)
	}

	enc := tok.Encode()
	var dec ZeroRTTToken
	if err := dec.Decode(enc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.SessionID != tok.SessionID {
		t.Fatalf("session id mismatch: got %d want %d", dec.SessionID, tok.SessionID)
	}
	if dec.CreatedAt != tok.CreatedAt || dec.ExpiresAt != tok.ExpiresAt {
		t.Fatalf("time fields mismatch")
	}
	if dec.Capabilities != tok.Capabilities {
		t.Fatalf("cap mismatch: got %v want %v", dec.Capabilities, tok.Capabilities)
	}
	if !dec.IsValid() {
		t.Fatalf("expected token to be valid")
	}

	dec.ExpiresAt = time.Now().Unix() - 1
	if dec.IsValid() {
		t.Fatalf("expected token to be invalid after expiry")
	}
}

func TestUDPSessionRequestEncodeDecode(t *testing.T) {
	req := &UDPSessionRequest{SessionID: 7, TargetAddr: "example.com", TargetPort: 5353}
	enc := req.Encode()
	var dec UDPSessionRequest
	if err := dec.Decode(enc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.SessionID != req.SessionID || dec.TargetAddr != req.TargetAddr || dec.TargetPort != req.TargetPort {
		t.Fatalf("decoded mismatch: %+v want %+v", dec, *req)
	}
}

func TestUDPSessionResponseEncodeDecode(t *testing.T) {
	resp := &UDPSessionResponse{SessionID: 9, Accepted: false, ErrorCode: 1234}
	enc := resp.Encode()
	var dec UDPSessionResponse
	if err := dec.Decode(enc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.SessionID != resp.SessionID || dec.Accepted != resp.Accepted || dec.ErrorCode != resp.ErrorCode {
		t.Fatalf("decoded mismatch: %+v want %+v", dec, *resp)
	}
}

func TestHeartbeatFrameEncodeDecode(t *testing.T) {
	h := &HeartbeatFrame{Timestamp: time.Now().Unix(), SentBytes: 100, RecvBytes: 200}
	enc := h.Encode()
	var dec HeartbeatFrame
	if err := dec.Decode(enc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Timestamp != h.Timestamp || dec.SentBytes != h.SentBytes || dec.RecvBytes != h.RecvBytes {
		t.Fatalf("decoded mismatch: %+v want %+v", dec, *h)
	}
}

func TestTokenManagerGenerateValidateCleanup(t *testing.T) {
	tm := NewTokenManager()
	tok := tm.GenerateToken(1001, CapabilityDatagram)
	if tok.SessionID != 1001 {
		t.Fatalf("expected session id 1001")
	}
	if !tm.ValidateToken(1001, tok.Token) {
		t.Fatalf("expected token to validate")
	}
	if tm.ValidateToken(999, tok.Token) {
		t.Fatalf("expected validate to fail for unknown session")
	}

	// Expire and cleanup.
	tm.mu.Lock()
	tm.tokens[1001].ExpiresAt = time.Now().Unix() - 1
	tm.mu.Unlock()
	tm.Cleanup()
	if tm.ValidateToken(1001, tok.Token) {
		t.Fatalf("expected token to fail after cleanup")
	}
}
