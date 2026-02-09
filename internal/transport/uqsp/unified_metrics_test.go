package uqsp

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	appmetrics "stealthlink/internal/metrics"
	"stealthlink/internal/transport/uqsp/behavior"
	"stealthlink/internal/transport/uqsp/carrier"
)

type testMetricsOverlay struct {
	enabled bool
}

func (o *testMetricsOverlay) Apply(conn net.Conn) (net.Conn, error) { return conn, nil }
func (o *testMetricsOverlay) Name() string                          { return "test-overlay" }
func (o *testMetricsOverlay) Enabled() bool                         { return o.enabled }

type testMetricsCarrier struct {
	name     string
	dialFn   func(context.Context, string) (net.Conn, error)
	listenFn func(string) (carrier.Listener, error)
}

func (c *testMetricsCarrier) Network() string { return "tcp" }
func (c *testMetricsCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return c.dialFn(ctx, addr)
}
func (c *testMetricsCarrier) Listen(addr string) (carrier.Listener, error) {
	if c.listenFn == nil {
		return nil, errors.New("listen unsupported")
	}
	return c.listenFn(addr)
}
func (c *testMetricsCarrier) Close() error      { return nil }
func (c *testMetricsCarrier) IsAvailable() bool { return true }
func (c *testMetricsCarrier) Name() string      { return c.name }

var _ behavior.Overlay = (*testMetricsOverlay)(nil)
var _ carrier.Carrier = (*testMetricsCarrier)(nil)

func TestUnifiedProtocolDialEmitsMetrics(t *testing.T) {
	carrierName := "test_uqsp_metrics_carrier_success"
	before := appmetrics.SnapshotData()
	beforeConn, beforeSent, beforeRecv, beforeErrs := carrierSnapshot(before, carrierName)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	serverErr := make(chan error, 1)
	go func() {
		defer close(serverErr)
		defer serverConn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != "ping" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		_, err := serverConn.Write([]byte("pong"))
		serverErr <- err
	}()

	c := &testMetricsCarrier{
		name: carrierName,
		dialFn: func(ctx context.Context, addr string) (net.Conn, error) {
			return clientConn, nil
		},
	}
	u, err := NewUnifiedProtocol(VariantConfig{
		Variant:   VariantXHTTP_TLS,
		Carrier:   c,
		Behaviors: []behavior.Overlay{&testMetricsOverlay{enabled: true}},
	})
	if err != nil {
		t.Fatalf("new unified protocol: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := u.Dial(ctx, "unused")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: %q", string(reply))
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}

	after := appmetrics.SnapshotData()
	afterConn, afterSent, afterRecv, afterErrs := carrierSnapshot(after, carrierName)

	if after.UQSPHandshakeTotal < before.UQSPHandshakeTotal+1 {
		t.Fatalf("uqsp handshakes not incremented: before=%d after=%d", before.UQSPHandshakeTotal, after.UQSPHandshakeTotal)
	}
	if after.UQSPObfuscationOps < before.UQSPObfuscationOps+1 {
		t.Fatalf("uqsp obfuscation ops not incremented: before=%d after=%d", before.UQSPObfuscationOps, after.UQSPObfuscationOps)
	}
	if after.UQSPSessionsTotal < before.UQSPSessionsTotal+1 {
		t.Fatalf("uqsp sessions not incremented: before=%d after=%d", before.UQSPSessionsTotal, after.UQSPSessionsTotal)
	}
	if afterConn < beforeConn+1 {
		t.Fatalf("carrier connections not incremented: before=%d after=%d", beforeConn, afterConn)
	}
	if afterSent <= beforeSent {
		t.Fatalf("carrier bytes sent not incremented: before=%d after=%d", beforeSent, afterSent)
	}
	if afterRecv <= beforeRecv {
		t.Fatalf("carrier bytes recv not incremented: before=%d after=%d", beforeRecv, afterRecv)
	}
	if afterErrs != beforeErrs {
		t.Fatalf("carrier errors changed unexpectedly: before=%d after=%d", beforeErrs, afterErrs)
	}
}

func TestUnifiedProtocolDialFailureEmitsErrorMetrics(t *testing.T) {
	carrierName := "test_uqsp_metrics_carrier_failure"
	before := appmetrics.SnapshotData()
	_, _, _, beforeCarrierErrs := carrierSnapshot(before, carrierName)

	c := &testMetricsCarrier{
		name: carrierName,
		dialFn: func(ctx context.Context, addr string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	}
	u, err := NewUnifiedProtocol(VariantConfig{
		Variant: VariantUDP,
		Carrier: c,
	})
	if err != nil {
		t.Fatalf("new unified protocol: %v", err)
	}

	_, err = u.Dial(context.Background(), "unused")
	if err == nil {
		t.Fatal("expected dial error")
	}

	after := appmetrics.SnapshotData()
	_, _, _, afterCarrierErrs := carrierSnapshot(after, carrierName)

	if after.UQSPHandshakeTotal < before.UQSPHandshakeTotal+1 {
		t.Fatalf("uqsp handshakes not incremented on failure: before=%d after=%d", before.UQSPHandshakeTotal, after.UQSPHandshakeTotal)
	}
	if after.Errors < before.Errors+1 {
		t.Fatalf("global errors not incremented: before=%d after=%d", before.Errors, after.Errors)
	}
	if afterCarrierErrs < beforeCarrierErrs+1 {
		t.Fatalf("carrier errors not incremented: before=%d after=%d", beforeCarrierErrs, afterCarrierErrs)
	}
}

func carrierSnapshot(s appmetrics.Snapshot, carrierName string) (connections, sent, recv, errs int64) {
	if s.Carriers == nil {
		return 0, 0, 0, 0
	}
	cm := s.Carriers[carrierName]
	if cm == nil {
		return 0, 0, 0, 0
	}
	return cm.Connections, cm.BytesSent, cm.BytesRecv, cm.Errors
}
