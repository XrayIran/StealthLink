package shadowtls

import (
	"io"
	"net"
	"sync"
	"time"
)

// relay copies data between two connections bidirectionally.
// It's used during the handshake phase to relay TLS traffic.
func relay(conn1, conn2 net.Conn, timeout time.Duration) error {
	errCh := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(conn1, conn2)
		errCh <- err
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(conn2, conn1)
		errCh <- err
	}()

	// Wait for one direction to complete or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-done:
		return nil
	case err := <-errCh:
		return err
	case <-timer.C:
		return nil // Timeout is not an error for handshake relay
	}
}

// relayBuffer is a reusable buffer for relay operations.
var relayBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

// copyWithPool copies data using a pooled buffer.
func copyWithPool(dst, src net.Conn) (int64, error) {
	buf := relayBufferPool.Get().([]byte)
	defer relayBufferPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

// sideChannel wraps a connection after handshake completion.
// It handles the transition from TLS relay to data channel.
type sideChannel struct {
	net.Conn
	readBuf  []byte
	writeBuf []byte
	mu       sync.Mutex
}

// newSideChannel creates a new side channel wrapper.
func newSideChannel(conn net.Conn) *sideChannel {
	return &sideChannel{
		Conn:     conn,
		readBuf:  make([]byte, 0, 65536),
		writeBuf: make([]byte, 0, 65536),
	}
}

// EnableSideChannel switches the connection to side channel mode.
// This should be called after the TLS handshake is complete.
func (sc *shadowConn) EnableSideChannel() *sideChannel {
	return newSideChannel(sc.Conn)
}

// Read reads data from the side channel.
func (sc *sideChannel) Read(p []byte) (n int, err error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// If we have buffered data, return it first
	if len(sc.readBuf) > 0 {
		n = copy(p, sc.readBuf)
		sc.readBuf = sc.readBuf[n:]
		return n, nil
	}

	// Otherwise read from underlying connection
	return sc.Conn.Read(p)
}

// Write writes data to the side channel.
func (sc *sideChannel) Write(p []byte) (n int, err error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	return sc.Conn.Write(p)
}

// BufferedRead adds data to the read buffer.
// This is used for data received during handshake that needs to be
// passed to the application layer.
func (sc *sideChannel) BufferedRead(data []byte) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.readBuf = append(sc.readBuf, data...)
}
