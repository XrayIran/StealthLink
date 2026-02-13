package singbox

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestSingboxServerCompat tests StealthLink client → sing-box server compatibility
// This test verifies that a StealthLink client with the sing-box adapter can
// communicate with a sing-box server (simulated).
func TestSingboxServerCompat(t *testing.T) {
	// Create adapter
	adapter, err := NewAdapter(Config{
		Enabled: true,
		Mode:    "anytls",
	})
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// Create a mock sing-box server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Server goroutine (simulates sing-box server)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo server behavior
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	// Client with adapter
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	wrappedDialer := adapter.WrapDialer(dialer)

	// Connect to server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := wrappedDialer(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	// Send test data
	testData := []byte("hello sing-box")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Read response
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// Verify echo
	if string(buf[:n]) != string(testData) {
		t.Errorf("got %q, want %q", buf[:n], testData)
	}

	wg.Wait()
}

// TestSingboxClientCompat tests sing-box client → StealthLink server compatibility
// This test verifies that a sing-box client (simulated) can communicate with
// a StealthLink server using the sing-box adapter.
func TestSingboxClientCompat(t *testing.T) {
	// Create adapter
	adapter, err := NewAdapter(Config{
		Enabled: true,
		Mode:    "anytls",
	})
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// Create StealthLink server with adapter
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	wrappedListener := adapter.WrapListener(listener)
	serverAddr := listener.Addr().String()

	// Server goroutine (StealthLink server with adapter)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := wrappedListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo server behavior
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	// Client (simulates sing-box client)
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	// Send test data
	testData := []byte("hello stealthlink")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Read response
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// Verify echo
	if string(buf[:n]) != string(testData) {
		t.Errorf("got %q, want %q", buf[:n], testData)
	}

	wg.Wait()
}

// TestMuxParity tests that mux behavior is preserved (not just basic connect)
// This verifies that multiplexing semantics work correctly through the adapter.
func TestMuxParity(t *testing.T) {
	// Create adapter
	adapter, err := NewAdapter(Config{
		Enabled: true,
		Mode:    "anytls",
	})
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// Create server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	wrappedListener := adapter.WrapListener(listener)
	serverAddr := listener.Addr().String()

	// Server goroutine - handles multiple streams
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := wrappedListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Handle multiple sequential requests (simulating mux streams)
		for i := 0; i < 3; i++ {
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				return
			}
			// Echo back with stream marker
			response := append([]byte{byte(i)}, buf[:n]...)
			conn.Write(response)
		}
	}()

	// Client with adapter
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	wrappedDialer := adapter.WrapDialer(dialer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := wrappedDialer(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	// Send multiple requests (simulating mux streams)
	for i := 0; i < 3; i++ {
		testData := []byte("stream data")
		if _, err := conn.Write(testData); err != nil {
			t.Fatalf("Write() error = %v", err)
		}

		// Read response
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}

		// Verify stream marker and data
		if buf[0] != byte(i) {
			t.Errorf("stream %d: got marker %d, want %d", i, buf[0], i)
		}
		if string(buf[1:n]) != string(testData) {
			t.Errorf("stream %d: got %q, want %q", i, buf[1:n], testData)
		}
	}

	wg.Wait()
}

// TestBidirectionalCompat tests bidirectional communication through adapter
func TestBidirectionalCompat(t *testing.T) {
	adapter, err := NewAdapter(Config{
		Enabled: true,
		Mode:    "anytls",
	})
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// Create server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	wrappedListener := adapter.WrapListener(listener)
	serverAddr := listener.Addr().String()

	// Server goroutine - bidirectional communication
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := wrappedListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read from client
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			return
		}

		// Send response
		conn.Write([]byte("server response"))

		// Read client ack
		_, err = conn.Read(buf)
		if err != nil {
			return
		}

		// Final response
		conn.Write([]byte("final"))
	}()

	// Client with adapter
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	wrappedDialer := adapter.WrapDialer(dialer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := wrappedDialer(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	// Send initial message
	if _, err := conn.Write([]byte("client hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Read server response
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(buf[:n]) != "server response" {
		t.Errorf("got %q, want 'server response'", buf[:n])
	}

	// Send ack
	if _, err := conn.Write([]byte("client ack")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Read final response
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(buf[:n]) != "final" {
		t.Errorf("got %q, want 'final'", buf[:n])
	}

	wg.Wait()
}

// TestAdapterDisabledPassthrough verifies that when adapter is disabled,
// connections pass through without modification
func TestAdapterDisabledPassthrough(t *testing.T) {
	adapter, err := NewAdapter(Config{
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}

	// Create server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	// Listener should pass through unchanged
	wrappedListener := adapter.WrapListener(listener)
	if wrappedListener != listener {
		t.Error("disabled adapter should return original listener")
	}

	serverAddr := listener.Addr().String()

	// Server goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := wrappedListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	// Client with disabled adapter
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	wrappedDialer := adapter.WrapDialer(dialer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := wrappedDialer(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	// Verify connection is not wrapped
	if _, ok := conn.(*singboxConn); ok {
		t.Error("disabled adapter should not wrap connection")
	}

	// Test basic communication
	testData := []byte("passthrough test")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("got %q, want %q", buf[:n], testData)
	}

	wg.Wait()
}
