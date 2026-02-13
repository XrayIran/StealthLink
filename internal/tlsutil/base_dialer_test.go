package tlsutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestDialUTLS_UsesBaseDialFuncFromContext(t *testing.T) {
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = tlsConn.Handshake()
		_ = tlsConn.Close()
	}()

	var calls atomic.Int32
	ctx := WithBaseDialFunc(context.Background(), func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	})

	conn, err := DialUTLS(ctx, "tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.invalid",
	}, "chrome_auto")
	if err != nil {
		t.Fatalf("DialUTLS: %v", err)
	}
	_ = conn.Close()

	if got := calls.Load(); got != 1 {
		t.Fatalf("base dial func calls = %d, want 1", got)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("server accept goroutine did not finish")
	}
}

func selfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

