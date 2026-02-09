package masque

import (
	"context"
	"io"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestStandaloneClientConnectTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	c, err := NewClient(&Config{
		Target:     ln.Addr().String(),
		TunnelType: "tcp",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	conn, err := c.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept timeout")
	}
}

func TestStandaloneClientConnectUDP(t *testing.T) {
	udpLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer udpLn.Close()

	server, err := NewServer(&Config{})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	serverAddr := pickTCPAddr(t)
	done := make(chan error, 1)
	go func() { done <- server.Listen(serverAddr) }()
	waitForServer(t, serverAddr)
	defer func() {
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()

	go func() {
		buf := make([]byte, 2048)
		n, src, err := udpLn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = udpLn.WriteTo(buf[:n], src)
	}()

	client, err := NewClient(&Config{
		ServerAddr: serverAddr,
		Target:     udpLn.LocalAddr().String(),
		TunnelType: "udp",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	conn, err := client.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-masque-udp")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("payload mismatch got=%q want=%q", string(buf), string(payload))
	}
}

func TestStandaloneClientConnectIPWithAuth(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	defer tcpLn.Close()
	go func() {
		conn, err := tcpLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	server, err := NewServer(&Config{AuthToken: "token-1"})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	serverAddr := pickTCPAddr(t)
	done := make(chan error, 1)
	go func() { done <- server.Listen(serverAddr) }()
	waitForServer(t, serverAddr)
	defer func() {
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()

	badClient, _ := NewClient(&Config{
		ServerAddr: serverAddr,
		Target:     tcpLn.Addr().String(),
		TunnelType: "ip",
		AuthToken:  "wrong",
	})
	if _, err := badClient.Connect(context.Background()); err == nil {
		t.Fatal("expected auth failure for bad token")
	}

	client, _ := NewClient(&Config{
		ServerAddr: serverAddr,
		Target:     tcpLn.Addr().String(),
		TunnelType: "ip",
		AuthToken:  "token-1",
	})
	conn, err := client.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect with auth: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-masque-ip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("payload mismatch got=%q want=%q", string(buf), string(payload))
	}
}

func pickTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick addr: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server did not start on %s", addr)
}

func TestProxyRequestBuildsMASQUEEndpoint(t *testing.T) {
	target, err := url.Parse("udp://example.com:443/service/path?x=1")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	u, err := ProxyRequest(target, "token-123")
	if err != nil {
		t.Fatalf("ProxyRequest: %v", err)
	}
	if u.Scheme != "https" {
		t.Fatalf("unexpected scheme: %s", u.Scheme)
	}
	if u.Host != "example.com:443" {
		t.Fatalf("unexpected host: %s", u.Host)
	}
	if u.Path != "/.well-known/masque/udp" {
		t.Fatalf("unexpected path: %s", u.Path)
	}
	q := u.Query()
	if q.Get("target") != "example.com:443" {
		t.Fatalf("unexpected target query: %s", q.Get("target"))
	}
	if q.Get("target_path") != "/service/path" {
		t.Fatalf("unexpected target_path query: %s", q.Get("target_path"))
	}
	if q.Get("target_query") != "x=1" {
		t.Fatalf("unexpected target_query: %s", q.Get("target_query"))
	}
	if q.Get("access_token") != "token-123" {
		t.Fatalf("unexpected access_token: %s", q.Get("access_token"))
	}
}

func TestProxyRequestConnectIP(t *testing.T) {
	target, err := url.Parse("connect-ip://10.0.0.1:443")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	u, err := ProxyRequest(target, "")
	if err != nil {
		t.Fatalf("ProxyRequest: %v", err)
	}
	if u.Path != "/.well-known/masque/ip" {
		t.Fatalf("unexpected path: %s", u.Path)
	}
}
