package transport

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type guardFailState struct {
	failures int
	lastFail time.Time
}

var (
	guardFailMu sync.Mutex
	guardFails  = map[string]guardFailState{}
)

// SendGuard writes a short pre-shared token before higher-level handshakes.
// No-op when guard is empty. Token length is 1 byte followed by the token.
func SendGuard(w io.Writer, guard string) error {
	if guard == "" {
		return nil
	}
	if len(guard) > 255 {
		return fmt.Errorf("guard token too long")
	}
	b := []byte(guard)
	if _, err := w.Write([]byte{byte(len(b))}); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// RecvGuard reads and validates the guard token; it honors a 5s read timeout
// when the connection implements SetReadDeadline.
func RecvGuard(r net.Conn, guard string) error {
	if guard == "" {
		return nil
	}
	if isGuardRateLimited(r) {
		return fmt.Errorf("guard validation rate limited")
	}

	_ = r.SetReadDeadline(time.Now().Add(5 * time.Second))
	var lb [1]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		_ = r.SetReadDeadline(time.Time{})
		return err
	}
	n := int(lb[0])
	if n == 0 {
		_ = r.SetReadDeadline(time.Time{})
		recordGuardFailure(r)
		return fmt.Errorf("guard token missing")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		_ = r.SetReadDeadline(time.Time{})
		return err
	}
	_ = r.SetReadDeadline(time.Time{})
	if len(buf) != len(guard) || subtle.ConstantTimeCompare(buf, []byte(guard)) != 1 {
		recordGuardFailure(r)
		return fmt.Errorf("guard token mismatch")
	}
	clearGuardFailures(r)
	return nil
}

func guardPeerKey(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}

func isGuardRateLimited(conn net.Conn) bool {
	key := guardPeerKey(conn)
	if key == "" {
		return false
	}
	guardFailMu.Lock()
	defer guardFailMu.Unlock()
	state, ok := guardFails[key]
	if !ok {
		return false
	}
	if time.Since(state.lastFail) > 2*time.Minute {
		delete(guardFails, key)
		return false
	}
	return state.failures >= 6
}

func recordGuardFailure(conn net.Conn) {
	key := guardPeerKey(conn)
	if key == "" {
		return
	}
	guardFailMu.Lock()
	defer guardFailMu.Unlock()
	state := guardFails[key]
	if time.Since(state.lastFail) > 2*time.Minute {
		state.failures = 0
	}
	state.failures++
	state.lastFail = time.Now()
	guardFails[key] = state
}

func clearGuardFailures(conn net.Conn) {
	key := guardPeerKey(conn)
	if key == "" {
		return
	}
	guardFailMu.Lock()
	delete(guardFails, key)
	guardFailMu.Unlock()
}
