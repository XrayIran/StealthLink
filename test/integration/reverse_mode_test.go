package integration

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	uqsp "stealthlink/internal/transport/uqsp"
)

// UPSTREAM_WIRING: Tunnel

func TestReverseDialerServerInitiatedConnection(t *testing.T) {
	testReverseDialerServerInitiatedConnection(t, false)
}

func TestReverseDialerServerInitiatedConnectionWithHTTPRegistration(t *testing.T) {
	testReverseDialerServerInitiatedConnection(t, true)
}

func testReverseDialerServerInitiatedConnection(t *testing.T, useHTTPRegistration bool) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const token = "reverse-auth-token"
	const registrationPath = "/_reverse_register_test"
	serverDone := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		reader := io.Reader(conn)
		if useHTTPRegistration {
			br := bufio.NewReader(conn)
			req, err := http.ReadRequest(br)
			if err != nil {
				serverDone <- err
				return
			}
			if req.Method != http.MethodPost || req.URL.Path != registrationPath {
				serverDone <- io.ErrUnexpectedEOF
				return
			}
			if got := req.Header.Get("Authorization"); got != "Bearer "+token {
				serverDone <- io.ErrUnexpectedEOF
				return
			}
			req.Body.Close()
			if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok"); err != nil {
				serverDone <- err
				return
			}
			reader = br
		}

		got, err := readReverseAuthToken(reader, len(token))
		if err != nil {
			serverDone <- err
			return
		}
		if got != token {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte{0x00, 0x00})
		serverDone <- err
	}()

	mode := &uqsp.ReverseMode{
		Enabled:             true,
		Role:                "dialer",
		ClientAddress:       ln.Addr().String(),
		AuthToken:           token,
		UseHTTPRegistration: useHTTPRegistration,
		RegistrationPath:    registrationPath,
		ReconnectDelay:      50 * time.Millisecond,
		MaxRetries:          2,
	}

	dialer := uqsp.NewReverseDialer(mode, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer dialer.Close()

	if err := dialer.Start(ctx); err != nil {
		t.Fatalf("start reverse dialer: %v", err)
	}

	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := dialer.Dial("tcp", ln.Addr().String())
		if err != nil {
			errCh <- err
			return
		}
		connCh <- conn
	}()

	select {
	case conn := <-connCh:
		_ = conn.Close()
	case err := <-errCh:
		t.Fatalf("reverse dial: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for reverse connection")
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server handshake failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for server handshake")
	}
}

func readReverseAuthToken(r io.Reader, tokenLen int) (string, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return "", err
	}

	if first[0] == 1 {
		var headerTail [8 + 16]byte
		if _, err := io.ReadFull(r, headerTail[:]); err != nil {
			return "", err
		}
		if tokenLen < 0 || tokenLen > 4096 {
			return "", io.ErrUnexpectedEOF
		}
		token := make([]byte, tokenLen)
		if _, err := io.ReadFull(r, token); err != nil {
			return "", err
		}
		return string(token), nil
	}

	var lengthBuf [4]byte
	lengthBuf[0] = first[0]
	if _, err := io.ReadFull(r, lengthBuf[1:]); err != nil {
		return "", err
	}
	length := binary.BigEndian.Uint32(lengthBuf[:])
	token := make([]byte, int(length))
	if _, err := io.ReadFull(r, token); err != nil {
		return "", err
	}
	return string(token), nil
}
