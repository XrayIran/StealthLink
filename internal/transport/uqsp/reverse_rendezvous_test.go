package uqsp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// UPSTREAM_WIRING: snowflake

func TestReverseRendezvousBrokerEnablesDialWithoutClientAddress(t *testing.T) {
	type rec struct {
		addr string
	}
	var (
		mu   sync.Mutex
		data = map[string]rec{}
	)

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		switch r.URL.Path {
		case "/rv/register":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			addr, _ := req["address"].(string)
			if token == "" || strings.TrimSpace(addr) == "" {
				http.Error(w, "missing token/address", http.StatusBadRequest)
				return
			}
			mu.Lock()
			data[token] = rec{addr: addr}
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case "/rv/poll":
			mu.Lock()
			v, ok := data[token]
			mu.Unlock()
			if token == "" || !ok || strings.TrimSpace(v.addr) == "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"address": v.addr})
		default:
			http.NotFound(w, r)
		}
	}))
	defer broker.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	token := "test-token"
	rv := ReverseRendezvous{
		Enabled:         true,
		BrokerURL:       broker.URL + "/rv",
		UTLSFingerprint: "chrome_auto",
	}

	// Listener side: binds a local port and registers it.
	listenerMode := &ReverseMode{
		Enabled:        true,
		Role:           "listener",
		ServerAddress:  "127.0.0.1:0",
		AuthToken:      token,
		ReconnectDelay: 50 * time.Millisecond,
		Rendezvous:     rv,
	}
	listener := NewReverseDialer(listenerMode, nil)
	if err := listener.Start(ctx); err != nil {
		t.Fatalf("listener Start: %v", err)
	}
	defer listener.Close()

	// Dialer side: has no client_address; it must poll broker to discover it.
	dialerMode := &ReverseMode{
		Enabled:          true,
		Role:             "dialer",
		ClientAddress:    "",
		AuthToken:        token,
		ReconnectBackoff: 50 * time.Millisecond,
		ReconnectDelay:   50 * time.Millisecond,
		MaxRetries:       50,
		Rendezvous:       rv,
	}
	dialer := NewReverseDialer(dialerMode, nil)
	if err := dialer.Start(ctx); err != nil {
		t.Fatalf("dialer Start: %v", err)
	}
	defer dialer.Close()

	// Wait for both sides to see the connection.
	dc, err := dialer.Dial("tcp", "")
	if err != nil {
		t.Fatalf("dialer Dial: %v", err)
	}
	defer dc.Close()

	lc, err := listener.Dial("tcp", "")
	if err != nil {
		t.Fatalf("listener Dial: %v", err)
	}
	defer lc.Close()

	_ = dc.SetDeadline(time.Now().Add(2 * time.Second))
	_ = lc.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := dc.Write([]byte("ping")); err != nil {
		t.Fatalf("dialer write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(lc, buf); err != nil {
		t.Fatalf("listener read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("unexpected payload: %q", string(buf))
	}
}
