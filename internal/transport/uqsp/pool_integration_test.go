package uqsp

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
	"sync"
	"testing"
	"time"

	"stealthlink/internal/config"

	"github.com/xtaci/smux"
)

func TestPool_LatencyReductionIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	listenAddr := "127.0.0.1:0"
	serverTLS, clientTLS := testTLSConfigPair(t)

	// Start server
	serverCfg := &config.Config{Role: "gateway"}
	serverCfg.Transport.Type = "uqsp"
	serverCfg.Transport.UQSP.Carrier.Type = "quic"
	serverCfg.Security.SharedKey = "test-key"

	ln, err := NewRuntimeListener(listenAddr, serverCfg, serverTLS, smux.DefaultConfig(), "test-token")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	actualAddr := ln.Addr().String()

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
					go func() {
						defer stream.Close()
						_, _ = io.Copy(stream, stream) // Echo
					}()
				}
			}()
		}
	}()

	runBenchmark := func(poolEnabled bool) (time.Duration, []time.Duration) {
		clientCfg := &config.Config{Role: "agent"}
		clientCfg.Transport.Type = "uqsp"
		clientCfg.Transport.UQSP.Carrier.Type = "quic"
		clientCfg.Security.SharedKey = "test-key"
		if poolEnabled {
			clientCfg.Transport.Pool.Enabled = true
			clientCfg.Transport.Pool.MinSize = 5
			clientCfg.Transport.Pool.MaxSize = 20
			clientCfg.Transport.Pool.Mode = "aggressive"
		}

		dialer, err := NewRuntimeDialer(clientCfg, clientTLS, smux.DefaultConfig(), "test-token")
		if err != nil {
			t.Fatalf("failed to create dialer: %v", err)
		}

		// Warmup if pooled
		if poolEnabled {
			time.Sleep(2 * time.Second) // Wait for pool to dial
		}

		const numRequests = 20
		dialLatencies := make([]time.Duration, numRequests)
		var mu sync.Mutex
		var wg sync.WaitGroup
		wg.Add(numRequests)

		totalStart := time.Now()
		for i := 0; i < numRequests; i++ {
			go func(idx int) {
				defer wg.Done()

				// Simulate high load with some stagger
				time.Sleep(time.Duration(idx*10) * time.Millisecond)

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				startDial := time.Now()
				sess, err := dialer.Dial(ctx, actualAddr)
				elapsed := time.Since(startDial)

				mu.Lock()
				dialLatencies[idx] = elapsed
				mu.Unlock()

				if err != nil {
					t.Errorf("dial failed: %v", err)
					return
				}
				defer sess.Close() // Return to pool if enabled

				stream, err := sess.OpenStream()
				if err != nil {
					t.Errorf("open stream failed: %v", err)
					return
				}
				defer stream.Close()

				data := []byte("hello")
				_, _ = stream.Write(data)
				buf := make([]byte, 5)
				_, _ = io.ReadFull(stream, buf)
			}(i)
		}
		wg.Wait()
		return time.Since(totalStart), dialLatencies
	}

	// First run: Pool DISABLED
	t.Log("Running WITHOUT pool...")
	_, latenciesNoPool := runBenchmark(false)
	var avgNoPool time.Duration
	for _, l := range latenciesNoPool {
		avgNoPool += l
	}
	avgNoPool /= time.Duration(len(latenciesNoPool))
	t.Logf("Average dial latency WITHOUT pool: %v", avgNoPool)

	// Second run: Pool ENABLED
	t.Log("Running WITH pool...")
	_, latenciesWithPool := runBenchmark(true)
	var avgWithPool time.Duration
	for _, l := range latenciesWithPool {
		avgWithPool += l
	}
	avgWithPool /= time.Duration(len(latenciesWithPool))
	t.Logf("Average dial latency WITH pool: %v", avgWithPool)

	if avgNoPool > 0 {
		reduction := float64(avgNoPool-avgWithPool) / float64(avgNoPool) * 100
		t.Logf("Dial latency reduction: %.2f%%", reduction)
	}
}

func testTLSConfigPair(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	tpl := &x509.Certificate{
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

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 key pair: %v", err)
	}

	serverTLS := &tls.Config{Certificates: []tls.Certificate{pair}}
	clientTLS := &tls.Config{InsecureSkipVerify: true}
	return serverTLS, clientTLS
}
