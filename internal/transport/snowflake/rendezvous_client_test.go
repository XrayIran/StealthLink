package snowflake

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRendezvousClient_PublishAndPoll_HTTP(t *testing.T) {
	var gotAuth string
	var gotKey string
	var gotHost string
	var stored string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("X-Rendezvous-Key")
		gotHost = r.Host
		switch r.URL.Path {
		case "/rv/register":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			stored, _ = body["address"].(string)
			w.WriteHeader(http.StatusOK)
		case "/rv/poll":
			if strings.TrimSpace(stored) == "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"address": stored})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := NewBrokerRendezvousClient(BrokerRendezvousConfig{
		BrokerURL:   srv.URL + "/rv",
		AuthToken:   "tkn",
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := c.Publish(ctx, "k", "127.0.0.1:1234", 0); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if gotAuth != "Bearer tkn" {
		t.Fatalf("expected Authorization bearer token, got %q", gotAuth)
	}
	if gotHost != strings.TrimPrefix(srv.URL, "http://") {
		t.Fatalf("expected Host=%q, got %q", strings.TrimPrefix(srv.URL, "http://"), gotHost)
	}

	v, err := c.Poll(ctx, "k")
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if v != "127.0.0.1:1234" {
		t.Fatalf("expected value, got %q", v)
	}
	if gotKey != "k" {
		t.Fatalf("expected X-Rendezvous-Key, got %q", gotKey)
	}
}

func TestRendezvousClient_FrontDomainSetsSNI_HTTPS(t *testing.T) {
	wantSNI := "front.example"
	var sawSNI string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			sawSNI = r.TLS.ServerName
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c, err := NewBrokerRendezvousClient(BrokerRendezvousConfig{
		BrokerURL:   ts.URL + "/rv",
		FrontDomain: wantSNI,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Publish(ctx, "", "127.0.0.1:1234", 0); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if sawSNI != wantSNI {
		t.Fatalf("expected SNI %q, got %q", wantSNI, sawSNI)
	}
}

func TestRendezvousClient_Poll_BackoffAndFailures(t *testing.T) {
	var sleeps []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := NewBrokerRendezvousClient(BrokerRendezvousConfig{
		BrokerURL:     srv.URL + "/rv",
		MaxAttempts:   3,
		BaseBackoff:   10 * time.Millisecond,
		MaxBackoff:    20 * time.Millisecond,
		Sleep:         func(d time.Duration) { sleeps = append(sleeps, d) },
		UTLSFingerprint: "chrome_auto",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = c.Poll(ctx, "k")
	if err == nil {
		t.Fatal("expected error")
	}
	if len(sleeps) != 2 {
		t.Fatalf("expected 2 sleeps, got %d", len(sleeps))
	}
	if sleeps[0] <= 0 || sleeps[1] <= 0 {
		t.Fatalf("expected positive sleeps, got %v", sleeps)
	}
	if sleeps[1] < sleeps[0] {
		t.Fatalf("expected non-decreasing backoff, got %v", sleeps)
	}
}

func TestRendezvousClient_Poll_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{"))
	}))
	defer srv.Close()

	c, err := NewBrokerRendezvousClient(BrokerRendezvousConfig{
		BrokerURL:   srv.URL + "/rv",
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = c.Poll(ctx, "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRendezvousClient_Poll_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	c, err := NewBrokerRendezvousClient(BrokerRendezvousConfig{
		BrokerURL:   srv.URL + "/rv",
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = c.Poll(ctx, "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRendezvousClient_Poll_ContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"address": "127.0.0.1:1"})
	}))
	defer srv.Close()

	c, err := NewBrokerRendezvousClient(BrokerRendezvousConfig{
		BrokerURL:   srv.URL + "/rv",
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = c.Poll(ctx, "")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
