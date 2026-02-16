package fakedns

import "testing"

func TestFakeDNSResolveAndReverse(t *testing.T) {
	fd, err := New(Config{Enabled: true, IPRange: "198.18.0.0/15"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ip1 := fd.Resolve("example.com")
	ip2 := fd.Resolve("example.com")
	if ip1 == nil || ip2 == nil {
		t.Fatalf("expected non-nil IP")
	}
	if !ip1.Equal(ip2) {
		t.Fatalf("expected stable mapping for same domain")
	}
	domain, ok := fd.GetDomain(ip1)
	if !ok || domain != "example.com" {
		t.Fatalf("expected reverse lookup to succeed, got ok=%v domain=%q", ok, domain)
	}
	if !fd.IsFakeIP(ip1) {
		t.Fatalf("expected IsFakeIP true")
	}

	fd.Release("example.com")
	if _, ok := fd.GetDomain(ip1); ok {
		t.Fatalf("expected mapping to be released")
	}
}
