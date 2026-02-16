//go:build integration
// +build integration

package uqsp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// TestUQSPReverseInit verifies that the Gateway can dial the Agent (Reverse Init).
func TestUQSPReverseInit(t *testing.T) {
	// Setup: Agent listens, Gateway dials.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Start Agent (Listener)
	agentListenAddr := "127.0.0.1:0" // Ephemeral port
	agentMode := &ReverseMode{
		Enabled:        true,
		Role:           "rendezvous",
		ServerAddress:  agentListenAddr, // Agent listens
		AuthToken:      "test-token",
		ReconnectDelay: 100 * time.Millisecond,
	}

	// We use RuntimeListener logic manually or just use ReverseDialer directly
	// ReverseDialer in 'listener' or 'rendezvous' mode with ServerAddress works as listener.
	// But NewReverseListener wraps it nicely.

	agentDialer := NewReverseDialer(agentMode, nil)
	// Start listener logic
	if err := agentDialer.Start(ctx); err != nil {
		t.Fatalf("Failed to start agent dialer/listener: %v", err)
	}
	defer agentDialer.Close()

	// Wait a bit for listener to bind (though Start is async for accept loop, the listener binding might be instant if we check)
	// Actually NewReverseDialer.Start -> startRendezvous -> startListener -> net.Listen
	// But startListener is async? No, 'go d.acceptLoop' is async, but 'net.Listen' is synchronous inside startListener.
	// Wait, 'startListener' returns error.
	// Let's check 'uqsp/reverse.go':
	// func (d *ReverseDialer) startListener(ctx context.Context) error {
	//    ln, err := net.Listen("tcp", addr)
	//    ...
	//    go d.acceptLoop(ctx, ln)
	//    return nil
	// }
	// So it binds synchronously. But we passed ":0" so we don't know the port!
	// We need to capture the address.
	// 'ReverseDialer' doesn't expose the listener or address directly easily unless we use 'NewReverseListener'.

	// PROPER WAY: Use NewReverseListener
	// But NewReverseListener takes a string addr.
	// We need the resolved addr.

	// Let's modify the test to bind a predictable port or find a free one first.
	// Or allow NewReverseListener to bind and tell us the port.
	// 'NewReverseListener' logic:
	// func NewReverseListener(...) { ... return &ReverseListener{ ..., addr: ... } }
	// It doesn't actually bind. The binding happens in... wait.
	// 'ReverseListener.Accept' waits for 'connChan'.
	// It is the 'ReverseDialer' that binds.
	// We need to know the port ReverseDialer bound to if we use ":0".

	// Let's find a free port first.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for free port: %v", err)
	}
	freeAddr := l.Addr().String()
	l.Close()

	agentMode.ServerAddress = freeAddr
	t.Logf("Agent listening on %s", freeAddr)

	// Restart agent dialer with concrete address
	agentDialer = NewReverseDialer(agentMode, nil)
	if err := agentDialer.Start(ctx); err != nil {
		t.Fatalf("Failed to start agent listener: %v", err)
	}
	defer agentDialer.Close()

	// 2. Start Gateway (Dialer)
	gatewayMode := &ReverseMode{
		Enabled:          true,
		Role:             "rendezvous",
		ClientAddress:    freeAddr, // Gateway dials Agent
		AuthToken:        "test-token",
		ReconnectBackoff: 100 * time.Millisecond,
		MaxRetries:       3,
	}

	gatewayDialer := NewReverseDialer(gatewayMode, nil)
	if err := gatewayDialer.Start(ctx); err != nil {
		t.Fatalf("Failed to start gateway dialer: %v", err)
	}
	defer gatewayDialer.Close()

	// 3. Establish Connection
	// Gateway attempts to Dial. It should get a connection from its pool once the background loop establishes it.

	// We simulate the "Application" usage.
	// Gateway/Server Application calls 'gatewayDialer.Dial' to get a session to the Agent.
	// Agent/Client Application calls 'agentListener.Accept' to receive the session.

	// Create Agent Listener wrapper
	agentListener, err := NewReverseListener(agentDialer, freeAddr)
	if err != nil {
		t.Fatalf("Failed to create agent listener wrapper: %v", err)
	}
	defer agentListener.Close()

	errCh := make(chan error, 1)

	// Agent accepts
	go func() {
		conn, err := agentListener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		// Echo server
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}
	}()

	// Gateway dials
	// Initial dial might fail if connection not yet established, but Dial implementation waits (see reverse.go line 497)
	conn, err := gatewayDialer.Dial("tcp", freeAddr)
	if err != nil {
		t.Fatalf("Gateway failed to dial: %v", err)
	}
	defer conn.Close()

	// 4. Verify Data Transfer
	secret := []byte("hello reverse world")
	if _, err := conn.Write(secret); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if string(buf[:n]) != string(secret) {
		t.Errorf("Mismatch: got %q, want %q", buf[:n], secret)
	}

	t.Log("Reverse Init connection and data transfer successful")
}

// TestUQSPReverseAuthFail verifies authentication failure
func TestUQSPReverseAuthFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().String()
	l.Close()

	// Agent with token A
	agentMode := &ReverseMode{
		Enabled:       true,
		Role:          "rendezvous",
		ServerAddress: port,
		AuthToken:     "token-A",
	}
	agentDialer := NewReverseDialer(agentMode, nil)
	agentDialer.Start(ctx)
	defer agentDialer.Close()

	agentListener, _ := NewReverseListener(agentDialer, port)

	go func() {
		// Should not receive connection or should error
		agentListener.Accept()
	}()

	// Gateway with token B
	gatewayMode := &ReverseMode{
		Enabled:          true,
		Role:             "rendezvous",
		ClientAddress:    port,
		AuthToken:        "token-B",
		ReconnectBackoff: 100 * time.Millisecond,
	}
	gatewayDialer := NewReverseDialer(gatewayMode, nil)
	gatewayDialer.Start(ctx)
	defer gatewayDialer.Close()

	_, err := gatewayDialer.Dial("tcp", port)
	// Expect timeout or error because auth fails and connection is dropped
	if err == nil {
		t.Error("Expected error due to auth mismatch, got nil")
	} else {
		t.Logf("Got expected error: %v", err)
	}
}

// TestUQSPReverseMux verifies smux over reverse connection
func TestUQSPReverseMux(t *testing.T) {
	// This mirrors how the Session Manager uses the connection
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().String()
	l.Close()

	agentMode := &ReverseMode{
		Enabled:       true,
		Role:          "rendezvous",
		ServerAddress: port,
		AuthToken:     "mux-token",
	}
	agentDialer := NewReverseDialer(agentMode, nil)
	agentDialer.Start(ctx)
	defer agentDialer.Close()

	agentListener, _ := NewReverseListener(agentDialer, port)

	// Gateway dials
	gatewayMode := &ReverseMode{
		Enabled:       true,
		Role:          "rendezvous",
		ClientAddress: port,
		AuthToken:     "mux-token",
	}
	gatewayDialer := NewReverseDialer(gatewayMode, nil)
	gatewayDialer.Start(ctx)
	defer gatewayDialer.Close()

	// Handshake
	done := make(chan struct{})

	go func() {
		conn, err := agentListener.Accept()
		if err != nil {
			t.Errorf("Agent accept fail: %v", err)
			return
		}
		// Agent acts as Smux Server
		sess, err := smux.Server(conn, nil)
		if err != nil {
			t.Errorf("Smux server fail: %v", err)
			return
		}
		stream, _ := sess.AcceptStream()
		io.Copy(stream, stream)
		done <- struct{}{}
	}()

	conn, err := gatewayDialer.Dial("tcp", port)
	if err != nil {
		t.Fatalf("Gateway dial fail: %v", err)
	}

	// Gateway acts as Smux Client
	sess, err := smux.Client(conn, nil)
	if err != nil {
		t.Fatalf("Smux client fail: %v", err)
	}

	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream fail: %v", err)
	}

	stream.Write([]byte("mux-test"))
	buf := make([]byte, 8)
	stream.Read(buf)

	if string(buf) != "mux-test" {
		t.Errorf("Mux echo mismatch")
	}

	<-done
}
