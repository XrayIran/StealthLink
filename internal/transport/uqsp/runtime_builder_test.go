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
	"stealthlink/internal/transport"

	"github.com/xtaci/smux"
)

func TestRuntimeDialerListenerRoundTrip(t *testing.T) {
	serverTLS, clientTLS := runtimeTLSConfigPair(t)

	serverCfg := &config.Config{}
	serverCfg.Role = "gateway"
	serverCfg.Transport.Type = "uqsp"
	serverCfg.Variant = "UDP+"
	serverCfg.Transport.UQSP.Carrier.Type = "quic"

	clientCfg := &config.Config{}
	clientCfg.Role = "agent"
	clientCfg.Transport.Type = "uqsp"
	clientCfg.Variant = "UDP+"
	clientCfg.Transport.UQSP.Carrier.Type = "quic"

	smuxCfg := smux.DefaultConfig()
	listener, err := NewRuntimeListener("127.0.0.1:0", serverCfg, serverTLS, smuxCfg, "shared-token")
	if err != nil {
		t.Fatalf("NewRuntimeListener() error = %v", err)
	}
	defer listener.Close()

	acceptCh := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		sess, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		acceptCh <- sess
	}()

	dialer, err := NewRuntimeDialer(clientCfg, clientTLS, smuxCfg, "shared-token")
	if err != nil {
		t.Fatalf("NewRuntimeDialer() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientSess, err := dialer.Dial(ctx, listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer clientSess.Close()

	var serverSess transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("Accept() error = %v", err)
	case serverSess = <-acceptCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for accepted session")
	}
	defer serverSess.Close()

	serverDone := make(chan error, 1)
	go func() {
		strm, err := serverSess.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		defer strm.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(strm, buf); err != nil {
			serverDone <- err
			return
		}
		if string(buf) != "ping" {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		_, err = strm.Write([]byte("pong"))
		serverDone <- err
	}()

	clientStrm, err := clientSess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer clientStrm.Close()

	if _, err := clientStrm.Write([]byte("ping")); err != nil {
		t.Fatalf("client write error = %v", err)
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(clientStrm, resp); err != nil {
		t.Fatalf("client read error = %v", err)
	}
	if string(resp) != "pong" {
		t.Fatalf("unexpected response %q", string(resp))
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server stream handler error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server handler")
	}
}

func TestRuntimeListenerRejectsClientOnlyCarrierForGateway(t *testing.T) {
	serverTLS, _ := runtimeTLSConfigPair(t)

	cfg := &config.Config{}
	cfg.Role = "gateway"
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "HTTP+"
	cfg.Transport.UQSP.Carrier.Type = "xhttp" // dial-only carrier

	_, err := NewRuntimeListener("127.0.0.1:0", cfg, serverTLS, smux.DefaultConfig(), "shared-token")
	if err == nil {
		t.Fatal("expected NewRuntimeListener() to fail for gateway + xhttp without reverse")
	}
}

func TestRuntimeDialerMaxConcurrentDialsConfig(t *testing.T) {
	_, clientTLS := runtimeTLSConfigPair(t)

	cfg := &config.Config{}
	cfg.Role = "agent"
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "UDP+"
	cfg.Transport.UQSP.Carrier.Type = "quic"
	cfg.Transport.UQSP.Runtime.MaxConcurrentDials = 7

	dialer, err := NewRuntimeDialer(cfg, clientTLS, smux.DefaultConfig(), "shared-token")
	if err != nil {
		t.Fatalf("NewRuntimeDialer() error = %v", err)
	}

	if dialer.dialSem == nil {
		t.Fatal("expected dial semaphore to be initialized")
	}
	if got := cap(dialer.dialSem); got != 7 {
		t.Fatalf("expected dial semaphore capacity 7, got %d", got)
	}
}

func TestRuntimeDialer_DialConcurrencyNotSerialized(t *testing.T) {
	const (
		workers      = 20
		sleepPerDial = 100 * time.Millisecond
		maxWall      = 600 * time.Millisecond
	)

	smuxCfg := smux.DefaultConfig()
	smuxCfg.KeepAliveDisabled = true

	rd := &RuntimeDialer{
		variant: VariantUDP,
		smuxCfg: smuxCfg,
		dialSem: make(chan struct{}, workers),
		dialFn: func(ctx context.Context, addr string) (net.Conn, error) {
			select {
			case <-time.After(sleepPerDial):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			c1, c2 := net.Pipe()
			go func() {
				_, _ = io.Copy(io.Discard, c2)
				_ = c2.Close()
			}()
			return c1, nil
		},
	}

	start := time.Now()

	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			sess, err := rd.dialOne(ctx, "ignored")
			if err == nil {
				_ = sess.Close()
			}
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("dialOne error: %v", err)
		}
	}

	elapsed := time.Since(start)
	if elapsed > maxWall {
		t.Fatalf("expected parallel dialing (wall<=%v), got %v", maxWall, elapsed)
	}
}

func runtimeTLSConfigPair(t *testing.T) (*tls.Config, *tls.Config) {
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
