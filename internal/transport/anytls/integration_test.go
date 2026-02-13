package anytls

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// TestAnyTLSProtocolWorks verifies that the AnyTLS protocol works correctly
// by establishing a connection between a client and server, sending data,
// and verifying it's received correctly.
func TestAnyTLSProtocolWorks(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Setup test configuration
	password := "test-password-12345"

	cfg := &Config{
		Padding: PaddingConfig{
			Lines: []string{"100-900"}, // Use explicit line format
		},
		IdleSessionTimeout: 60 * time.Second,
		Password:           password,
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.KeepAliveInterval = 10 * time.Second
	smuxCfg.KeepAliveTimeout = 30 * time.Second

	// Start listener
	listener, err := Listen("127.0.0.1:0", cfg, smuxCfg, "")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	listenerAddr := listener.Addr().String()
	t.Logf("Listener started on %s", listenerAddr)

	// Channel to receive server-side errors
	serverErr := make(chan error, 1)
	serverReady := make(chan struct{})

	// Start server goroutine
	go func() {
		close(serverReady)

		// Accept a session
		sess, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer sess.Close()

		// Accept a stream
		stream, err := sess.AcceptStream()
		if err != nil {
			serverErr <- err
			return
		}
		defer stream.Close()

		// Read data from client
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil && err != io.EOF {
			serverErr <- err
			return
		}

		// Echo data back
		_, err = stream.Write(buf[:n])
		if err != nil {
			serverErr <- err
			return
		}

		serverErr <- nil
	}()

	// Wait for server to be ready
	<-serverReady
	time.Sleep(100 * time.Millisecond)

	// Create client dialer
	clientCfg := &Config{
		Padding: PaddingConfig{
			Lines: []string{"100-900"}, // Use explicit line format
		},
		IdleSessionTimeout: 60 * time.Second,
		Password:           password,
	}

	dialer, err := NewDialer(clientCfg, smuxCfg, "", listenerAddr)
	if err != nil {
		t.Fatalf("failed to create dialer: %v", err)
	}

	// Dial the server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sess, err := dialer.Dial(ctx, listenerAddr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer sess.Close()

	// Open a stream
	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	defer stream.Close()

	// Send test data
	testData := []byte("Hello, AnyTLS!")
	_, err = stream.Write(testData)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Read echo response
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("failed to read: %v", err)
	}

	// Verify data
	if string(buf[:n]) != string(testData) {
		t.Errorf("expected %q, got %q", testData, buf[:n])
	}

	// Check for server errors
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server")
	}

	t.Log("AnyTLS protocol test passed successfully")
}

// TestAnyTLSWithTLS verifies that AnyTLS works with TLS encryption
func TestAnyTLSWithTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Generate self-signed certificate for testing
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	password := "test-password-tls"

	// Server TLS config
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	serverCfg := &Config{
		Padding: PaddingConfig{
			Scheme: "fixed",
			Max:    500,
		},
		IdleSessionTimeout: 60 * time.Second,
		TLSConfig:          serverTLSConfig,
		Password:           password,
	}

	smuxCfg := smux.DefaultConfig()

	// Start listener
	listener, err := Listen("127.0.0.1:0", serverCfg, smuxCfg, "")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	listenerAddr := listener.Addr().String()
	t.Logf("TLS Listener started on %s", listenerAddr)

	// Server goroutine
	serverErr := make(chan error, 1)
	go func() {
		sess, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer sess.Close()

		stream, err := sess.AcceptStream()
		if err != nil {
			serverErr <- err
			return
		}
		defer stream.Close()

		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil && err != io.EOF {
			serverErr <- err
			return
		}

		_, err = stream.Write(buf[:n])
		serverErr <- err
	}()

	time.Sleep(100 * time.Millisecond)

	// Client TLS config (insecure for testing)
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}

	clientCfg := &Config{
		Padding: PaddingConfig{
			Scheme: "fixed",
			Max:    500,
		},
		IdleSessionTimeout: 60 * time.Second,
		TLSConfig:          clientTLSConfig,
		Password:           password,
	}

	dialer, err := NewDialer(clientCfg, smuxCfg, "", listenerAddr)
	if err != nil {
		t.Fatalf("failed to create dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sess, err := dialer.Dial(ctx, listenerAddr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer sess.Close()

	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	defer stream.Close()

	testData := []byte("Hello, AnyTLS with TLS!")
	_, err = stream.Write(testData)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("failed to read: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("expected %q, got %q", testData, buf[:n])
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server")
	}

	t.Log("AnyTLS with TLS test passed successfully")
}

// TestAnyTLSPaddingSchemes verifies different padding schemes work correctly
func TestAnyTLSPaddingSchemes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	schemes := []struct {
		name   string
		scheme string
		min    int
		max    int
	}{
		{"random", "random", 100, 900},
		{"fixed", "fixed", 0, 500},
		{"burst", "burst", 0, 0},
	}

	for _, tc := range schemes {
		t.Run(tc.name, func(t *testing.T) {
			password := "test-password-" + tc.name

			cfg := &Config{
				Padding: PaddingConfig{
					Scheme: tc.scheme,
					Min:    tc.min,
					Max:    tc.max,
				},
				IdleSessionTimeout: 30 * time.Second,
				Password:           password,
			}

			smuxCfg := smux.DefaultConfig()

			listener, err := Listen("127.0.0.1:0", cfg, smuxCfg, "")
			if err != nil {
				t.Fatalf("failed to create listener: %v", err)
			}
			defer listener.Close()

			listenerAddr := listener.Addr().String()

			serverErr := make(chan error, 1)
			go func() {
				sess, err := listener.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer sess.Close()

				stream, err := sess.AcceptStream()
				if err != nil {
					serverErr <- err
					return
				}
				defer stream.Close()

				buf := make([]byte, 1024)
				n, err := stream.Read(buf)
				if err != nil && err != io.EOF {
					serverErr <- err
					return
				}

				_, err = stream.Write(buf[:n])
				serverErr <- err
			}()

			time.Sleep(100 * time.Millisecond)

			clientCfg := &Config{
				Padding: PaddingConfig{
					Scheme: tc.scheme,
					Min:    tc.min,
					Max:    tc.max,
				},
				IdleSessionTimeout: 30 * time.Second,
				Password:           password,
			}

			dialer, err := NewDialer(clientCfg, smuxCfg, "", listenerAddr)
			if err != nil {
				t.Fatalf("failed to create dialer: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			sess, err := dialer.Dial(ctx, listenerAddr)
			if err != nil {
				t.Fatalf("failed to dial: %v", err)
			}
			defer sess.Close()

			stream, err := sess.OpenStream()
			if err != nil {
				t.Fatalf("failed to open stream: %v", err)
			}
			defer stream.Close()

			testData := []byte("Test padding: " + tc.name)
			_, err = stream.Write(testData)
			if err != nil {
				t.Fatalf("failed to write: %v", err)
			}

			buf := make([]byte, 1024)
			n, err := stream.Read(buf)
			if err != nil && err != io.EOF {
				t.Fatalf("failed to read: %v", err)
			}

			if string(buf[:n]) != string(testData) {
				t.Errorf("expected %q, got %q", testData, buf[:n])
			}

			select {
			case err := <-serverErr:
				if err != nil {
					t.Fatalf("server error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for server")
			}
		})
	}
}

// Helper function to generate self-signed certificate for testing
func generateSelfSignedCert() (tls.Certificate, error) {
	// For testing, we'll use a simple approach
	// In production, use proper certificate generation
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)

	keyPEM := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)

	return tls.X509KeyPair(certPEM, keyPEM)
}
