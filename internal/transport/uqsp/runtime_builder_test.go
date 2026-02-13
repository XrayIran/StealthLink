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
	serverCfg.Variant = "4d"
	serverCfg.Transport.UQSP.Carrier.Type = "quic"

	clientCfg := &config.Config{}
	clientCfg.Role = "agent"
	clientCfg.Transport.Type = "uqsp"
	clientCfg.Variant = "4d"
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
	cfg.Variant = "4a"
	cfg.Transport.UQSP.Carrier.Type = "xhttp" // dial-only carrier

	_, err := NewRuntimeListener("127.0.0.1:0", cfg, serverTLS, smux.DefaultConfig(), "shared-token")
	if err == nil {
		t.Fatal("expected NewRuntimeListener() to fail for gateway + xhttp without reverse")
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
