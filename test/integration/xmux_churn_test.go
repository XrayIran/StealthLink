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
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stealthlink/internal/metrics"
	"stealthlink/internal/transport/xhttp"

	"github.com/xtaci/smux"
)

// TestXMuxConnectionChurn_HighRequestRate verifies that high request rates trigger rotation
// based on HMaxRequestTimes limit.
func TestXMuxConnectionChurn_HighRequestRate(t *testing.T) {
	// Setup server
	serverTLS := generateTestTLSConfig(t)
	serverTLS.NextProtos = []string{"h2", "http/1.1"}
	smuxCfg := smux.DefaultConfig()

	addr := "127.0.0.1:0"
	path := "/test-high-rate"
	guard := "test-guard-rate"

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

	// Setup client with low request limit to trigger rotation quickly
	clientTLS := generateTestTLSConfig(t)
	clientTLS.InsecureSkipVerify = true
	clientTLS.NextProtos = []string{"h2", "http/1.1"}

	clientCfg := xhttp.Config{
		Path: path,
		XMux: xhttp.XMuxConfig{
			Enabled:          true,
			MaxConnections:   1,
			CMaxReuseTimes:   100, // High enough to not interfere
			HMaxRequestTimes: 10,  // Rotate after 10 requests
			DrainTimeout:     5 * time.Second,
		},
	}
	clientCfg.ApplyDefaults()

	dialer := xhttp.NewDialer(clientCfg, clientTLS, smuxCfg, "", "", guard)
	serverAddr := ln.Addr().String()

	// Get initial metrics
	initialStats := metrics.SnapshotData()
	initialRotations := int64(0)
	if count, ok := initialStats.XmuxConnectionRotationsTotal["request_limit"]; ok {
		initialRotations = count
	}

	// Send many requests to trigger rotation
	// Open 15 streams across multiple Get/Close cycles to trigger rotation after 10
	for i := 0; i < 15; i++ {
		sess, err := dialer.Dial(context.Background(), serverAddr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}

		stream, err := sess.OpenStream()
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}

		// Send some data
		msg := []byte("test message")
		if _, err := stream.Write(msg); err != nil {
			t.Fatalf("write stream %d: %v", i, err)
		}

		// Read echo
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(stream, buf); err != nil {
			t.Fatalf("read stream %d: %v", i, err)
		}

		stream.Close()
		sess.Close() // Return to pool after each request
	}

	// Verify rotation occurred
	stats, ok := dialer.Stats()
	if !ok {
		t.Fatal("stats not available")
	}

	if stats.Total < 2 {
		t.Errorf("Expected at least 2 total connections after rotation, got %d", stats.Total)
	}

	// Verify metrics show request_limit rotation
	finalStats := metrics.SnapshotData()
	finalRotations := int64(0)
	if count, ok := finalStats.XmuxConnectionRotationsTotal["request_limit"]; ok {
		finalRotations = count
	}

	if finalRotations <= initialRotations {
		t.Errorf("Expected request_limit rotations to increase from %d, got %d", initialRotations, finalRotations)
	}

	t.Logf("Request limit rotations: %d -> %d", initialRotations, finalRotations)
}

// TestXMuxConnectionChurn_AgeTrigger verifies that connections rotate based on age limit.
func TestXMuxConnectionChurn_AgeTrigger(t *testing.T) {
	// Setup server
	serverTLS := generateTestTLSConfig(t)
	serverTLS.NextProtos = []string{"h2", "http/1.1"}
	smuxCfg := smux.DefaultConfig()

	addr := "127.0.0.1:0"
	path := "/test-age"
	guard := "test-guard-age"

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

	// Setup client with short age limit
	clientTLS := generateTestTLSConfig(t)
	clientTLS.InsecureSkipVerify = true
	clientTLS.NextProtos = []string{"h2", "http/1.1"}

	clientCfg := xhttp.Config{
		Path: path,
		XMux: xhttp.XMuxConfig{
			Enabled:          true,
			MaxConnections:   1,
			CMaxReuseTimes:   100,
			HMaxRequestTimes: 100,
			HMaxReusableSecs: 2, // Rotate after 2 seconds
			DrainTimeout:     5 * time.Second,
		},
	}
	clientCfg.ApplyDefaults()

	dialer := xhttp.NewDialer(clientCfg, clientTLS, smuxCfg, "", "", guard)
	serverAddr := ln.Addr().String()

	// Get initial metrics
	initialStats := metrics.SnapshotData()
	initialRotations := int64(0)
	if count, ok := initialStats.XmuxConnectionRotationsTotal["age_limit"]; ok {
		initialRotations = count
	}

	// First connection
	sess1, err := dialer.Dial(context.Background(), serverAddr)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	sess1.Close()

	// Wait for age limit to be exceeded
	t.Log("Waiting for connection to age...")
	time.Sleep(2500 * time.Millisecond)

	// Second connection should trigger rotation
	sess2, err := dialer.Dial(context.Background(), serverAddr)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	sess2.Close()

	// Verify rotation occurred
	stats, ok := dialer.Stats()
	if !ok {
		t.Fatal("stats not available")
	}

	if stats.Total < 2 {
		t.Errorf("Expected at least 2 total connections after age rotation, got %d", stats.Total)
	}

	// Verify metrics show age_limit rotation
	finalStats := metrics.SnapshotData()
	finalRotations := int64(0)
	if count, ok := finalStats.XmuxConnectionRotationsTotal["age_limit"]; ok {
		finalRotations = count
	}

	if finalRotations <= initialRotations {
		t.Errorf("Expected age_limit rotations to increase from %d, got %d", initialRotations, finalRotations)
	}

	t.Logf("Age limit rotations: %d -> %d", initialRotations, finalRotations)
}

// TestXMuxConnectionChurn_NoLeaks verifies no connection leaks under sustained load.
func TestXMuxConnectionChurn_NoLeaks(t *testing.T) {
	// Setup server
	serverTLS := generateTestTLSConfig(t)
	serverTLS.NextProtos = []string{"h2", "http/1.1"}
	smuxCfg := smux.DefaultConfig()

	addr := "127.0.0.1:0"
	path := "/test-leaks"
	guard := "test-guard-leaks"

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

	// Setup client with moderate limits
	clientTLS := generateTestTLSConfig(t)
	clientTLS.InsecureSkipVerify = true
	clientTLS.NextProtos = []string{"h2", "http/1.1"}

	clientCfg := xhttp.Config{
		Path: path,
		XMux: xhttp.XMuxConfig{
			Enabled:          true,
			MaxConnections:   2,
			CMaxReuseTimes:   5,
			HMaxRequestTimes: 10,
			DrainTimeout:     2 * time.Second,
		},
	}
	clientCfg.ApplyDefaults()

	dialer := xhttp.NewDialer(clientCfg, clientTLS, smuxCfg, "", "", guard)
	serverAddr := ln.Addr().String()

	// Capture initial goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Run sustained load with connection churn
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var errorCount atomic.Int64

	numWorkers := 5         // Reduced to minimize goroutine count
	requestsPerWorker := 10 // Reduced to minimize goroutine count

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for j := 0; j < requestsPerWorker; j++ {
				sess, err := dialer.Dial(context.Background(), serverAddr)
				if err != nil {
					errorCount.Add(1)
					t.Logf("Worker %d request %d dial error: %v", workerID, j, err)
					continue
				}

				stream, err := sess.OpenStream()
				if err != nil {
					errorCount.Add(1)
					sess.Close()
					continue
				}

				msg := []byte("test")
				if _, err := stream.Write(msg); err != nil {
					errorCount.Add(1)
					stream.Close()
					sess.Close()
					continue
				}

				buf := make([]byte, len(msg))
				if _, err := io.ReadFull(stream, buf); err != nil {
					errorCount.Add(1)
					stream.Close()
					sess.Close()
					continue
				}

				stream.Close()
				sess.Close()
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// Allow time for cleanup - scavenger runs every 5 seconds, wait for 2 cycles
	time.Sleep(11 * time.Second)
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	// Check goroutine count
	finalGoroutines := runtime.NumGoroutine()
	goroutineDelta := finalGoroutines - initialGoroutines

	t.Logf("Goroutines: initial=%d, final=%d, delta=%d", initialGoroutines, finalGoroutines, goroutineDelta)
	t.Logf("Requests: success=%d, errors=%d", successCount.Load(), errorCount.Load())

	// Allow some tolerance for background goroutines and smux cleanup
	// Each smux session has several goroutines that may take time to clean up
	// With reduced load (5 workers * 10 requests), we expect fewer lingering goroutines
	if goroutineDelta > 80 {
		t.Errorf("Potential goroutine leak: delta=%d (threshold=80)", goroutineDelta)
	}

	// Verify most requests succeeded
	totalRequests := int64(numWorkers * requestsPerWorker)
	if successCount.Load() < totalRequests*8/10 {
		t.Errorf("Too many failed requests: %d/%d succeeded", successCount.Load(), totalRequests)
	}

	// Verify pool stats are reasonable
	stats, ok := dialer.Stats()
	if !ok {
		t.Fatal("stats not available")
	}

	t.Logf("Final pool stats: Total=%d, Active=%d, Idle=%d, Draining=%d",
		stats.Total, stats.Active, stats.Idle, stats.Draining)

	// Should have some connections but not excessive (after scavenger cleanup)
	if stats.Total > 5 {
		t.Errorf("Too many connections in pool after cleanup: %d", stats.Total)
	}
}

// TestXMuxConnectionChurn_MetricsVerification verifies that metrics correctly track rotation reasons.
func TestXMuxConnectionChurn_MetricsVerification(t *testing.T) {
	// Setup server
	serverTLS := generateTestTLSConfig(t)
	serverTLS.NextProtos = []string{"h2", "http/1.1"}
	smuxCfg := smux.DefaultConfig()

	addr := "127.0.0.1:0"
	path := "/test-metrics"
	guard := "test-guard-metrics"

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

	// Setup client with all limits configured
	clientTLS := generateTestTLSConfig(t)
	clientTLS.InsecureSkipVerify = true
	clientTLS.NextProtos = []string{"h2", "http/1.1"}

	clientCfg := xhttp.Config{
		Path: path,
		XMux: xhttp.XMuxConfig{
			Enabled:          true,
			MaxConnections:   1,
			CMaxReuseTimes:   3,
			HMaxRequestTimes: 5,
			HMaxReusableSecs: 10,
			DrainTimeout:     2 * time.Second,
		},
	}
	clientCfg.ApplyDefaults()

	dialer := xhttp.NewDialer(clientCfg, clientTLS, smuxCfg, "", "", guard)
	serverAddr := ln.Addr().String()

	// Get initial metrics
	initialStats := metrics.SnapshotData()
	t.Logf("Initial metrics: %+v", initialStats.XmuxConnectionRotationsTotal)

	// Trigger reuse_limit rotation
	for i := 0; i < 4; i++ {
		sess, err := dialer.Dial(context.Background(), serverAddr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		sess.Close()
	}

	// Trigger request_limit rotation with a new dialer
	clientCfg2 := xhttp.Config{
		Path: path,
		XMux: xhttp.XMuxConfig{
			Enabled:          true,
			MaxConnections:   1,
			CMaxReuseTimes:   100, // High enough to not interfere
			HMaxRequestTimes: 5,
			HMaxReusableSecs: 10,
			DrainTimeout:     2 * time.Second,
		},
	}
	clientCfg2.ApplyDefaults()
	dialer2 := xhttp.NewDialer(clientCfg2, clientTLS, smuxCfg, "", "", guard)

	// Open 6 streams across multiple Get/Close cycles
	for i := 0; i < 6; i++ {
		sess, err := dialer2.Dial(context.Background(), serverAddr)
		if err != nil {
			t.Fatalf("dial for request %d: %v", i, err)
		}
		stream, err := sess.OpenStream()
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}
		stream.Close()
		sess.Close()
	}

	// Get final metrics
	finalStats := metrics.SnapshotData()
	t.Logf("Final metrics: %+v", finalStats.XmuxConnectionRotationsTotal)

	// Verify rotation metrics increased
	reuseLimitBefore := int64(0)
	if count, ok := initialStats.XmuxConnectionRotationsTotal["reuse_limit"]; ok {
		reuseLimitBefore = count
	}
	reuseLimitAfter := int64(0)
	if count, ok := finalStats.XmuxConnectionRotationsTotal["reuse_limit"]; ok {
		reuseLimitAfter = count
	}

	requestLimitBefore := int64(0)
	if count, ok := initialStats.XmuxConnectionRotationsTotal["request_limit"]; ok {
		requestLimitBefore = count
	}
	requestLimitAfter := int64(0)
	if count, ok := finalStats.XmuxConnectionRotationsTotal["request_limit"]; ok {
		requestLimitAfter = count
	}

	if reuseLimitAfter <= reuseLimitBefore {
		t.Errorf("Expected reuse_limit rotations to increase from %d, got %d", reuseLimitBefore, reuseLimitAfter)
	}

	if requestLimitAfter <= requestLimitBefore {
		t.Errorf("Expected request_limit rotations to increase from %d, got %d", requestLimitBefore, requestLimitAfter)
	}

	t.Logf("Reuse limit rotations: %d -> %d", reuseLimitBefore, reuseLimitAfter)
	t.Logf("Request limit rotations: %d -> %d", requestLimitBefore, requestLimitAfter)

	// Verify reuse count metric
	if finalStats.XmuxConnectionReusesTotal <= initialStats.XmuxConnectionReusesTotal {
		t.Errorf("Expected connection reuses to increase from %d, got %d",
			initialStats.XmuxConnectionReusesTotal, finalStats.XmuxConnectionReusesTotal)
	}
}

// generateTestTLSConfig creates a self-signed TLS config for testing.
func generateTestTLSConfig(t *testing.T) *tls.Config {
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
