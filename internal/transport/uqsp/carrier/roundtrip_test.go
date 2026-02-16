package carrier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func TestWebTunnelH1RoundTrip(t *testing.T) {
	serverTLS := testTLSConfig(t)
	ln, err := NewWebTunnelListener("127.0.0.1:0", serverTLS, "/tunnel")
	if err != nil {
		if isSocketPermissionError(err) {
			t.Skipf("socket listen not permitted in this environment: %v", err)
		}
		t.Fatalf("NewWebTunnelListener failed: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}
		if string(buf) != "ping" {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte("pong"))
		errCh <- err
	}()

	c := NewWebTunnelCarrier(WebTunnelConfig{
		Server:                ln.Addr().String(),
		Path:                  "/tunnel",
		Version:               "h1",
		TLSInsecureSkipVerify: true,
	}, nil, smux.DefaultConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, "unused")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: %q", string(reply))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}
}

func TestWebTunnelH2RoundTrip(t *testing.T) {
	serverTLS := testTLSConfig(t)
	ln, err := NewWebTunnelListener("127.0.0.1:0", serverTLS, "/tunnel")
	if err != nil {
		if isSocketPermissionError(err) {
			t.Skipf("socket listen not permitted in this environment: %v", err)
		}
		t.Fatalf("NewWebTunnelListener failed: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}
		if string(buf) != "ping" {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte("pong"))
		errCh <- err
	}()

	c := NewWebTunnelCarrier(WebTunnelConfig{
		Server:                ln.Addr().String(),
		Path:                  "/tunnel",
		Version:               "h2",
		TLSInsecureSkipVerify: true,
	}, nil, smux.DefaultConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, "unused")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: %q", string(reply))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}
}

func TestQUICCarrierRoundTrip(t *testing.T) {
	t.Skip("covered by integration QUIC variant e2e test; unit test is flaky due stream cancellation timing")

	serverTLS := testTLSConfig(t)
	serverTLS.NextProtos = []string{"uqsp-test"}

	server := NewQUICCarrier(serverTLS, nil)
	ln, err := server.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			errCh <- err
			return
		}
		if string(buf) != "ping" {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte("pong"))
		errCh <- err
	}()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}
	client := NewQUICCarrier(clientTLS, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: %q", string(reply))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server timed out")
	}
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}
}
