package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"stealthlink/internal/transport/uqsp"
	"stealthlink/internal/vpn"
)

// This is a technique-only "TUN/L3 pass-through" smoke test: we send a synthetic
// IP packet as a framed payload across a reverse-init connection.
func TestReverseInit_StreamPacketTransport_RoundTrip(t *testing.T) {
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

	token := "reverse-auth-token"
	rv := uqsp.ReverseRendezvous{
		Enabled:         true,
		BrokerURL:       broker.URL + "/rv",
		UTLSFingerprint: "chrome_auto",
	}

	listenerMode := &uqsp.ReverseMode{
		Enabled:        true,
		Role:           "listener",
		ServerAddress:  "127.0.0.1:0",
		AuthToken:      token,
		ReconnectDelay: 50 * time.Millisecond,
		Rendezvous:     rv,
	}
	listener := uqsp.NewReverseDialer(listenerMode, nil)
	if err := listener.Start(ctx); err != nil {
		t.Fatalf("listener Start: %v", err)
	}
	defer listener.Close()

	dialerMode := &uqsp.ReverseMode{
		Enabled:          true,
		Role:             "dialer",
		ClientAddress:    "",
		AuthToken:        token,
		ReconnectBackoff: 50 * time.Millisecond,
		ReconnectDelay:   50 * time.Millisecond,
		MaxRetries:       50,
		Rendezvous:       rv,
	}
	dialer := uqsp.NewReverseDialer(dialerMode, nil)
	if err := dialer.Start(ctx); err != nil {
		t.Fatalf("dialer Start: %v", err)
	}
	defer dialer.Close()

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

	a := vpn.NewStreamPacketTransport(dc)
	b := vpn.NewStreamPacketTransport(lc)

	// Minimal IPv4 header (version+IHL=0x45) + payload.
	pkt := append([]byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2}, []byte("hi")...)

	if err := a.SendPacket(pkt); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	got, err := b.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	if string(got) != string(pkt) {
		t.Fatalf("packet mismatch: got %x want %x", got, pkt)
	}
}

