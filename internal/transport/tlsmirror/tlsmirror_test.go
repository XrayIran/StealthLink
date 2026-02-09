package tlsmirror

import "testing"

func TestShouldSkipEnrollmentLoopback(t *testing.T) {
	d := &Dialer{config: Config{Enabled: true, AntiLoopback: true}}
	if !d.shouldSkipEnrollment("127.0.0.1") {
		t.Fatalf("expected loopback enrollment to be skipped")
	}
	if !d.shouldSkipEnrollment("localhost") {
		t.Fatalf("expected localhost enrollment to be skipped")
	}
}

func TestShouldSkipEnrollmentNonLoopback(t *testing.T) {
	d := &Dialer{config: Config{Enabled: true, AntiLoopback: true}}
	if d.shouldSkipEnrollment("example.com") {
		t.Fatalf("expected non-loopback enrollment not skipped")
	}
}
