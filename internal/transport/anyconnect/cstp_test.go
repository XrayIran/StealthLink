package anyconnect

import "testing"

func TestCSTPFrameEncodeParseRoundTrip(t *testing.T) {
	f := &CSTPFrame{Type: CSTPFrameData, Flags: 0xAA, Payload: []byte("hello")}
	f.Length = uint16(len(f.Payload))
	b := f.Encode()
	parsed, err := ParseCSTPFrame(b)
	if err != nil {
		t.Fatalf("ParseCSTPFrame: %v", err)
	}
	if parsed.Type != f.Type || parsed.Flags != f.Flags || parsed.Length != f.Length {
		t.Fatalf("header mismatch: got=%+v want=%+v", parsed, f)
	}
	if string(parsed.Payload) != string(f.Payload) {
		t.Fatalf("payload mismatch: got %q want %q", string(parsed.Payload), string(f.Payload))
	}
}

func TestParseCSTPFrameRejectsShort(t *testing.T) {
	if _, err := ParseCSTPFrame([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error for short frame")
	}
}
