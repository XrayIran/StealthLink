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

	uqsp "stealthlink/internal/transport/uqsp"
	uqspcarrier "stealthlink/internal/transport/uqsp/carrier"
)

func TestUQSPVariantsEndToEndOverLocalhost(t *testing.T) {
	variants := []uqsp.ProtocolVariant{
		uqsp.VariantXHTTP_TLS,
		uqsp.VariantRawTCP,
		uqsp.VariantTLSMirror,
		uqsp.VariantUDP,
		uqsp.VariantTrust,
	}

	for _, variant := range variants {
		variant := variant
		t.Run(uqsp.VariantName(variant), func(t *testing.T) {
			serverTLS := integrationTLSConfig(t)
			serverTLS.NextProtos = []string{"uqsp-variant-test"}
			clientTLS := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"uqsp-variant-test"},
			}

			serverProto, err := uqsp.NewUnifiedProtocol(uqsp.VariantConfig{
				Variant:   variant,
				Carrier:   uqspcarrier.NewQUICCarrier(serverTLS, nil),
				Behaviors: nil,
				TLSConfig: serverTLS,
			})
			if err != nil {
				t.Fatalf("server protocol: %v", err)
			}
			clientProto, err := uqsp.NewUnifiedProtocol(uqsp.VariantConfig{
				Variant:   variant,
				Carrier:   uqspcarrier.NewQUICCarrier(clientTLS, nil),
				Behaviors: nil,
				TLSConfig: clientTLS,
			})
			if err != nil {
				t.Fatalf("client protocol: %v", err)
			}

			ln, err := serverProto.Listen("127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			serverErr := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					serverErr <- err
					return
				}

				in := make([]byte, 4)
				if _, err := io.ReadFull(conn, in); err != nil {
					serverErr <- err
					return
				}
				if string(in) != "ping" {
					serverErr <- io.ErrUnexpectedEOF
					return
				}
				_, err = conn.Write([]byte("pong"))
				serverErr <- err
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, err := clientProto.Dial(ctx, ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			out := make([]byte, 4)
			if _, err := io.ReadFull(conn, out); err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(out) != "pong" {
				t.Fatalf("unexpected reply: %q", string(out))
			}

			select {
			case err := <-serverErr:
				if err != nil {
					t.Fatalf("server error: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("server timed out")
			}
		})
	}
}

func integrationTLSConfig(t *testing.T) *tls.Config {
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
