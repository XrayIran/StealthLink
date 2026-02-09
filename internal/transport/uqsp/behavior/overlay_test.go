package behavior

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type mockOverlay struct {
	name    string
	enabled bool
	order   *[]string
}

func (m *mockOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if m.order != nil {
		*m.order = append(*m.order, m.name)
	}
	return conn, nil
}

func (m *mockOverlay) Name() string  { return m.name }
func (m *mockOverlay) Enabled() bool { return m.enabled }

func TestManagerApplyOrderAndEnablement(t *testing.T) {
	var order []string
	mgr := NewManager()
	mgr.AddOverlay(&mockOverlay{name: "a", enabled: true, order: &order})
	mgr.AddOverlay(&mockOverlay{name: "b", enabled: false, order: &order})
	mgr.AddOverlay(&mockOverlay{name: "c", enabled: true, order: &order})

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	if _, err := mgr.Apply(c1); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if len(order) != 2 || order[0] != "a" || order[1] != "c" {
		t.Fatalf("unexpected order: %v", order)
	}
}

func TestNewManagerFromConfigNil(t *testing.T) {
	mgr := NewManagerFromConfig(nil)
	if mgr == nil {
		t.Fatal("expected manager")
	}
	if got := len(mgr.GetOverlays()); got != 0 {
		t.Fatalf("expected 0 overlays, got %d", got)
	}
}

func TestDomainFrontSelectIPRotation(t *testing.T) {
	o := &DomainFrontOverlay{
		EnabledField: true,
		FrontDomain:  "front.example.com",
		RealHost:     "real.example.com",
		RotateIPs:    true,
		CustomIPs:    []string{"1.1.1.1", "2.2.2.2"},
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	first := o.SelectIP()
	second := o.SelectIP()
	third := o.SelectIP()
	if first != "1.1.1.1" || second != "2.2.2.2" || third != "1.1.1.1" {
		t.Fatalf("unexpected rotation: %q %q %q", first, second, third)
	}
}

type captureConn struct {
	mu     sync.Mutex
	writes [][]byte
	closed bool
}

func (c *captureConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(_ time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *captureConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	c.writes = append(c.writes, cp)
	return len(p), nil
}

func TestTLSFragOverlayFragmentsClientHello(t *testing.T) {
	o := &TLSFragOverlay{
		EnabledField: true,
		Strategy:     "fixed",
		ChunkSize:    40,
		MinDelay:     0,
		MaxDelay:     0,
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	base := &captureConn{}
	conn, err := o.Apply(base)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	hello := make([]byte, 200)
	hello[0] = 0x16
	hello[1] = 0x03
	hello[2] = 0x03
	hello[5] = 0x01
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write: %v", err)
	}

	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.writes) < 4 {
		t.Fatalf("expected multiple fragments, got %d", len(base.writes))
	}
	total := 0
	for _, w := range base.writes {
		total += len(w)
	}
	if total != len(hello) {
		t.Fatalf("fragment bytes=%d want=%d", total, len(hello))
	}
}

func TestTLSMirrorOverlayWrapUnwrap(t *testing.T) {
	o := &TLSMirrorOverlay{EnabledField: true}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	conn, err := o.Apply(a)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	gotRecord := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		record := make([]byte, 5+4)
		if _, err := io.ReadFull(b, record); err != nil {
			errCh <- err
			return
		}
		gotRecord <- record

		reply := make([]byte, 5+5)
		reply[0] = 0x17
		reply[1] = 0x03
		reply[2] = 0x03
		reply[3] = 0x00
		reply[4] = 0x05
		copy(reply[5:], []byte("world"))
		if _, err := b.Write(reply); err != nil {
			errCh <- err
			return
		}
	}()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case rec := <-gotRecord:
		if rec[0] != 0x17 {
			t.Fatalf("unexpected TLS content type: %x", rec[0])
		}
		if string(rec[5:]) != "ping" {
			t.Fatalf("unexpected payload: %q", string(rec[5:]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for mirrored record")
	}

	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "world" {
		t.Fatalf("unexpected unwrapped payload: %q", string(buf[:n]))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("remote side error: %v", err)
		}
	default:
	}
}
