package carrier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"stealthlink/internal/tlsutil"
)

func TestDialCarrierTLS_TriesConnectIPCandidates(t *testing.T) {
	ln, tlsCfg := newTestTLSListener(t)
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		if tc, ok := c.(*tls.Conn); ok {
			_ = tc.Handshake()
		}
		_ = c.Close()
		serverErr <- nil
	}()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = host

	var tried []string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		tried = append(tried, addr)
		// Fail first candidate explicitly.
		if len(tried) == 1 {
			return nil, errors.New("forced dial failure")
		}
		// On fallback, dial the real listener regardless of addr.
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}

	ctx := tlsutil.WithBaseDialFunc(context.Background(), baseDial)
	ctx = tlsutil.WithFrontDialOptions(ctx, tlsutil.FrontDialOptions{
		Enabled:             true,
		PoolKey:             "df:test",
		FrontDomain:         "front.example",
		ConnectIPCandidates: []string{"203.0.113.9", "127.0.0.1"},
	})

	// Address passed in is irrelevant because BaseDialFunc intercepts.
	conn, err := dialCarrierTLS(ctx, "tcp", ln.Addr().String(), tlsCfg, "golang")
	if err != nil {
		t.Fatalf("dialCarrierTLS: %v", err)
	}
	_ = conn.Close()

	if len(tried) < 2 {
		t.Fatalf("expected >=2 dial attempts, got %v", tried)
	}
	if tried[0] != net.JoinHostPort("203.0.113.9", port) {
		t.Fatalf("expected first dial to use primary candidate, got %q", tried[0])
	}
	if tried[1] != net.JoinHostPort("127.0.0.1", port) {
		t.Fatalf("expected second dial to use fallback candidate, got %q", tried[1])
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timeout")
	}
}

func newTestTLSListener(t *testing.T) (net.Listener, *tls.Config) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          bigSerial(t),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
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
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	clientTLS := &tls.Config{InsecureSkipVerify: true, ServerName: "front.example"}
	return ln, clientTLS
}

func bigSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return serial
}
