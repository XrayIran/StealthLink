package behavior

import (
	"bytes"
	"net"
	"testing"
	"time"

	"stealthlink/internal/config"
)

func TestQPPOverlayEnabled(t *testing.T) {
	cfg := config.QPPBehaviorConfig{
		Enabled: true,
		Key:     "test-qpp-key-must-be-secure-32!",
		NumSBox: 8,
	}

	overlay := NewQPPOverlay(cfg)
	if !overlay.Enabled() {
		t.Fatal("overlay should be enabled")
	}
	if overlay.Name() != "qpp" {
		t.Fatalf("expected name 'qpp', got %q", overlay.Name())
	}
}

func TestQPPOverlayDisabled(t *testing.T) {
	cfg := config.QPPBehaviorConfig{Enabled: false}
	overlay := NewQPPOverlay(cfg)

	if overlay.Enabled() {
		t.Fatal("overlay should be disabled")
	}
}

func TestQPPEncryptDecryptRoundTrip(t *testing.T) {
	overlay := NewQPPOverlay(config.QPPBehaviorConfig{
		Enabled: true,
		Key:     "round-trip-test-key-32-bytes-ok",
		NumSBox: 8,
	})

	testCases := [][]byte{
		[]byte("hello world"),
		[]byte("short"),
		make([]byte, 256),
		make([]byte, 1024),
	}

	for i, tc := range testCases {
		if i >= 2 {
			for j := range tc {
				tc[j] = byte(i + j)
			}
		}

		encrypted := overlay.Encrypt(tc)
		if bytes.Equal(tc, encrypted) && len(tc) > 0 {
			t.Errorf("case %d: encrypted data should differ from plaintext", i)
		}

		decrypted := overlay.Decrypt(encrypted)
		if !bytes.Equal(tc, decrypted) {
			t.Errorf("case %d: roundtrip failed, got %v, want %v", i, decrypted[:min(len(decrypted), 32)], tc[:min(len(tc), 32)])
		}
	}
}

func TestQPPConnApply(t *testing.T) {
	overlay := NewQPPOverlay(config.QPPBehaviorConfig{
		Enabled: true,
		Key:     "qpp-conn-test-key-32-bytes!!!",
		NumSBox: 8,
	})

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	wrapped, err := overlay.Apply(a)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if wrapped == a {
		t.Fatal("Apply should return a wrapped connection")
	}
}

func TestQPPConnApplyDisabled(t *testing.T) {
	overlay := NewQPPOverlay(config.QPPBehaviorConfig{Enabled: false})

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	wrapped, err := overlay.Apply(a)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if wrapped != a {
		t.Fatal("disabled overlay should return the same connection")
	}
}

func TestQPPConnApplyNoKey(t *testing.T) {
	overlay := NewQPPOverlay(config.QPPBehaviorConfig{
		Enabled: true,
		Key:     "",
	})

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	_, err := overlay.Apply(a)
	if err == nil {
		t.Fatal("Apply without key should fail")
	}
}

func TestQPPConnReadWrite(t *testing.T) {
	overlay := NewQPPOverlay(config.QPPBehaviorConfig{
		Enabled: true,
		Key:     "qpp-readwrite-test-key-32-bytes",
		NumSBox: 8,
	})

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	qppServer, err := overlay.Apply(serverConn)
	if err != nil {
		t.Fatalf("server Apply: %v", err)
	}
	qppClient, err := overlay.Apply(clientConn)
	if err != nil {
		t.Fatalf("client Apply: %v", err)
	}

	msg := []byte("test message through QPP overlay")
	errCh := make(chan error, 1)

	go func() {
		_, err := qppClient.Write(msg)
		errCh <- err
	}()

	buf := make([]byte, 1024)
	n, err := qppServer.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	received := buf[:n]
	if !bytes.Equal(received, msg) {
		t.Fatalf("received %q, want %q", string(received), string(msg))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Write error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write timeout")
	}
}

func TestQPPConnReadWriteFragmentedReads(t *testing.T) {
	overlay := NewQPPOverlay(config.QPPBehaviorConfig{
		Enabled: true,
		Key:     "qpp-fragmented-read-test-key-32!",
		NumSBox: 8,
	})

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	qppServer, err := overlay.Apply(serverConn)
	if err != nil {
		t.Fatalf("server Apply: %v", err)
	}
	qppClient, err := overlay.Apply(clientConn)
	if err != nil {
		t.Fatalf("client Apply: %v", err)
	}

	msg := bytes.Repeat([]byte("fragmented-"), 200)
	errCh := make(chan error, 1)
	go func() {
		_, err := qppClient.Write(msg)
		errCh <- err
	}()

	var received []byte
	chunk := make([]byte, 37)
	for len(received) < len(msg) {
		n, err := qppServer.Read(chunk)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		received = append(received, chunk[:n]...)
	}

	if !bytes.Equal(received, msg) {
		t.Fatalf("received %d bytes mismatch", len(received))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Write error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write timeout")
	}
}

func TestQPPDifferentKeys(t *testing.T) {
	overlay1 := NewQPPOverlay(config.QPPBehaviorConfig{
		Enabled: true,
		Key:     "first-key-32-bytes-secure-first!",
		NumSBox: 8,
	})
	overlay2 := NewQPPOverlay(config.QPPBehaviorConfig{
		Enabled: true,
		Key:     "second-key-32-bytes-secure-2nd",
		NumSBox: 8,
	})

	plaintext := []byte("test data for different keys")
	encrypted1 := overlay1.Encrypt(plaintext)
	encrypted2 := overlay2.Encrypt(plaintext)

	if bytes.Equal(encrypted1, encrypted2) {
		t.Fatal("different keys should produce different ciphertexts")
	}

	decrypted1 := overlay1.Decrypt(encrypted1)
	decrypted2 := overlay2.Decrypt(encrypted2)

	if !bytes.Equal(decrypted1, plaintext) {
		t.Fatal("overlay1 decrypt failed")
	}
	if !bytes.Equal(decrypted2, plaintext) {
		t.Fatal("overlay2 decrypt failed")
	}
}

func TestQPPKeyDerivation(t *testing.T) {
	key1 := GenerateQPPKey()
	if key1 == nil {
		t.Fatal("GenerateQPPKey returned nil")
	}
	if len(key1.PublicKey) != 32 {
		t.Fatalf("public key length: got %d, want 32", len(key1.PublicKey))
	}
	if len(key1.PrivateKey) != 32 {
		t.Fatalf("private key length: got %d, want 32", len(key1.PrivateKey))
	}

	key2 := GenerateQPPKey()
	if bytes.Equal(key1.PublicKey, key2.PublicKey) {
		t.Fatal("two generated keys should differ")
	}

	derived := DeriveQPPKey(key1.PrivateKey, key2.PublicKey)
	if len(derived) != 32 {
		t.Fatalf("derived key length: got %d, want 32", len(derived))
	}

	derived2 := DeriveQPPKey(key1.PrivateKey, key2.PublicKey)
	if !bytes.Equal(derived, derived2) {
		t.Fatal("same key pair should derive same shared key")
	}
}

func TestQPPStreamEncoder(t *testing.T) {
	overlay := NewQPPOverlay(config.QPPBehaviorConfig{
		Enabled: true,
		Key:     "stream-encoder-test-key-32b!!",
		NumSBox: 8,
	})

	encoder := NewQPPStreamEncoder(overlay, 16)

	input := []byte("hello world, this is a stream encoder test with multiple blocks")
	inputBuf := bytes.NewBuffer(input)
	outputBuf := &bytes.Buffer{}

	err := encoder.EncodeStream(inputBuf, outputBuf)
	if err != nil {
		t.Fatalf("EncodeStream: %v", err)
	}

	encoded := outputBuf.Bytes()
	if len(encoded) == 0 {
		t.Fatal("encoded output is empty")
	}

	decodeInput := bytes.NewBuffer(encoded)
	decodeOutput := &bytes.Buffer{}

	err = encoder.DecodeStream(decodeInput, decodeOutput)
	if err != nil {
		t.Fatalf("DecodeStream: %v", err)
	}

	decoded := decodeOutput.Bytes()
	if !bytes.Equal(decoded, input) {
		t.Fatalf("decoded output mismatch: got %q, want %q", string(decoded), string(input))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
