package integration

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

	"stealthlink/internal/transport/xhttp"
	"github.com/xtaci/smux"
)

func TestXMuxRotationIntegration(t *testing.T) {
	// Setup XHTTP Server
	serverTLS := xmuxIntegrationTLSConfig(t)
	serverTLS.NextProtos = []string{"h2", "http/1.1"}
	smuxCfg := smux.DefaultConfig()

	addr := "127.0.0.1:0"
	path := "/test-rotation"
	guard := "test-guard"
	
	cfg := xhttp.Config{
		Path: path,
	}
	cfg.ApplyDefaults()

	ln, err := xhttp.Listen(addr, cfg, serverTLS, smuxCfg, guard)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Handle sessions on server
	go func() {
		for {
			sess, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				for {
					stream, err := sess.AcceptStream()
					if err != nil {
						return
					}
					go io.Copy(stream, stream) // Echo
				}
			}()
		}
	}()

	// Setup XHTTP Client with low limits to trigger rotation
	clientTLS := xmuxIntegrationTLSConfig(t)
	clientTLS.InsecureSkipVerify = true
	clientTLS.NextProtos = []string{"h2", "http/1.1"}

	clientCfg := xhttp.Config{
		Path: path,
		XMux: xhttp.XMuxConfig{
			Enabled:          true,
			MaxConnections:   1,
			CMaxReuseTimes:   2,   // Rotate after 2 uses
			HMaxRequestTimes: 3,   // Rotate after 3 requests
			DrainTimeout:     5 * time.Second,
		},
	}
	clientCfg.ApplyDefaults()

	dialer := xhttp.NewDialer(clientCfg, clientTLS, smuxCfg, "", "", guard)
	
	serverAddr := ln.Addr().String()
	t.Logf("Server listening on %s", serverAddr)

	// Use 1: First dial
	s1, err := dialer.Dial(context.Background(), serverAddr)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	s1.Close() // Returns to pool

	// Use 2: Second dial (reuse s1)
	s2, err := dialer.Dial(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	s2.Close() // Returns to pool, but should be marked for retirement now

	// Use 3: Third dial should trigger rotation
	s3, err := dialer.Dial(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 3: %v", err)
	}
	
	// Verify it's a new connection by checking stats or internal state if possible
	// Since we can't easily see the ID here, we check if Stats show more than 1 total connection
	stats, ok := dialer.Stats()
	if !ok {
		t.Fatal("stats not available")
	}
	if stats.Total < 2 {
		t.Errorf("Expected at least 2 total connections (original + new replacement), got %d", stats.Total)
	}
	if stats.Draining == 0 {
		t.Error("Expected at least 1 draining connection")
	}
	s3.Close()
	
	// Test request limit
	// Wait a bit to ensure clean state
	clientCfg.XMux.CMaxReuseTimes = 100 // High enough to not affect
	dialer2 := xhttp.NewDialer(clientCfg, clientTLS, smuxCfg, "", "", guard)
	
	s4, err := dialer2.Dial(context.Background(), serverAddr)
	if err != nil {
		t.Fatalf("dial 4: %v", err)
	}
	// Send 3 requests (OpenStream)
	for i := 0; i < 3; i++ {
		t.Logf("Opening stream %d", i)
		conn, err := s4.OpenStream()
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}
		t.Logf("Stream %d opened", i)
		conn.Close()
	}
	s4.Close()
	
	// Next dial should rotate
	s5, err := dialer2.Dial(context.Background(), serverAddr)
	if err != nil {
		t.Fatalf("dial 5: %v", err)
	}
	stats2, ok := dialer2.Stats()
	t.Logf("Stats after dial 5: %+v", stats2)
	if !ok || stats2.Total < 2 {
		t.Error("Expected rotation after request limit reached")
	}
	s5.Close()
}

func xmuxIntegrationTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}
}
