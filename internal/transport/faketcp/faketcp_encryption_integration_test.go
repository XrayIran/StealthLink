package faketcp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xtaci/smux"
)

func TestEncryptionIntegration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CryptoKey = "integration-test-secret"
	cfg.AEADMode = "chacha20poly1305"

	ln, err := Listen("127.0.0.1:0", cfg, smux.DefaultConfig(), "")
	require.NoError(t, err)
	defer ln.Close()

	done := make(chan bool)
	go func() {
		sess, err := ln.Accept()
		if err != nil {
			return
		}
		defer sess.Close()

		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, 10)
		n, err := stream.Read(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) == "hello" {
			_, _ = stream.Write([]byte("world"))
		}
		done <- true
	}()

	dialer := NewDialer(cfg, smux.DefaultConfig(), "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := dialer.Dial(ctx, ln.Addr().String())
	require.NoError(t, err)
	defer sess.Close()

	stream, err := sess.OpenStream()
	require.NoError(t, err)
	defer stream.Close()

	_, err = stream.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 10)
	n, err := stream.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "world", string(buf[:n]))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestAuthFailureIntegration(t *testing.T) {
	cfgClient := DefaultConfig()
	cfgClient.CryptoKey = "client-secret"
	cfgClient.AEADMode = "chacha20poly1305"
	cfgClient.RTO = 100 * time.Millisecond

	cfgServer := DefaultConfig()
	cfgServer.CryptoKey = "server-secret" // Different secret
	cfgServer.AEADMode = "chacha20poly1305"

	ln, err := Listen("127.0.0.1:0", cfgServer, smux.DefaultConfig(), "")
	require.NoError(t, err)
	defer ln.Close()

	dialer := NewDialer(cfgClient, smux.DefaultConfig(), "")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = dialer.Dial(ctx, ln.Addr().String())
	// Handshake should fail due to decryption failure (SYNACK won't be decrypted by client, or SYN won't be decrypted by server)
	assert.Error(t, err)
}
