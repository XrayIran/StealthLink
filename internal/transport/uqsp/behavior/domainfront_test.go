package behavior

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestDomainFrontDialerKeepsOriginalAddrWithoutRotation(t *testing.T) {
	overlay := &DomainFrontOverlay{
		EnabledField: true,
		FrontDomain:  "cdn.example.com",
		RealHost:     "real.example.com",
		RotateIPs:    false,
	}

	var gotAddr string
	dialer := &DomainFrontDialer{
		Dialer: func(network, addr string) (net.Conn, error) {
			gotAddr = addr
			c1, c2 := net.Pipe()
			go c2.Close()
			return c1, nil
		},
		Overlay:   overlay,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}

	_, _ = dialer.Dial("tcp", "real.example.com:8443")
	if gotAddr != "real.example.com:8443" {
		t.Fatalf("dial target = %q, want %q", gotAddr, "real.example.com:8443")
	}
}

func TestDomainFrontDialerUsesRotatedIPWhenAvailable(t *testing.T) {
	overlay := &DomainFrontOverlay{
		EnabledField: true,
		FrontDomain:  "cdn.example.com",
		RealHost:     "real.example.com",
		RotateIPs:    true,
		CustomIPs:    []string{"203.0.113.9"},
	}

	var gotAddr string
	dialer := &DomainFrontDialer{
		Dialer: func(network, addr string) (net.Conn, error) {
			gotAddr = addr
			c1, c2 := net.Pipe()
			go c2.Close()
			return c1, nil
		},
		Overlay:   overlay,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}

	_, _ = dialer.Dial("tcp", "real.example.com:9443")
	if gotAddr != "203.0.113.9:9443" {
		t.Fatalf("dial target = %q, want %q", gotAddr, "203.0.113.9:9443")
	}
}
