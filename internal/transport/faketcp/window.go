package faketcp

import (
	"container/list"
	"sync"
	"time"
)

// window implements TCP sliding window for flow control.
type window struct {
	size    int       // Window size
	base    uint32    // Base sequence number
	next    uint32    // Next sequence number to send
	acked   uint32    // Last acknowledged sequence
	buffer  *list.List // Out-of-order buffer
	mu      sync.RWMutex
}

// segment represents a segment in the window.
type segment struct {
	seq     uint32
	data    []byte
	sent    time.Time
	retries int
}

// newWindow creates a new window.
func newWindow(size int) *window {
	return &window{
		size:   size,
		buffer: list.New(),
	}
}

// Available returns the available window space.
func (w *window) Available() int {
	w.mu.RLock()
	defer w.mu.RUnlock()

	inFlight := w.next - w.acked
	if inFlight > uint32(w.size) {
		return 0
	}
	return w.size - int(inFlight)
}

// CanSend returns true if data can be sent.
func (w *window) CanSend(bytes int) bool {
	return w.Available() >= bytes
}

// Push adds data to the send window.
func (w *window) Push(data []byte) uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()

	seq := w.next
	w.next += uint32(len(data))
	return seq
}

// Ack acknowledges data up to the given sequence number.
func (w *window) Ack(seq uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq > w.acked {
		w.acked = seq
	}
}

// IsAcked returns true if the sequence number has been acknowledged.
func (w *window) IsAcked(seq uint32) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return seq < w.acked
}

// InFlight returns the number of bytes in flight.
func (w *window) InFlight() int {
	w.mu.RLock()
	defer w.mu.RUnlock()

	inFlight := w.next - w.acked
	return int(inFlight)
}

// receiveWindow implements the receive side of flow control.
type receiveWindow struct {
	next      uint32        // Next expected sequence
	buffer    *list.List    // Out-of-order buffer
	mu        sync.RWMutex
	windowSize int          // Advertised window size
	lastAdvertised time.Time
}

// newReceiveWindow creates a new receive window.
func newReceiveWindow(size int) *receiveWindow {
	return &receiveWindow{
		buffer:     list.New(),
		windowSize: size,
	}
}

// IsExpected returns true if this is the next expected segment.
func (rw *receiveWindow) IsExpected(seq uint32) bool {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	return seq == rw.next
}

// Accept accepts an in-order segment.
func (rw *receiveWindow) Accept(data []byte) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	rw.next += uint32(len(data))
}

// Buffer buffers an out-of-order segment.
func (rw *receiveWindow) Buffer(seq uint32, data []byte) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	seg := &segment{
		seq:  seq,
		data: data,
	}

	// Insert in order
	for e := rw.buffer.Front(); e != nil; e = e.Next() {
		s := e.Value.(*segment)
		if seg.seq < s.seq {
			rw.buffer.InsertBefore(seg, e)
			return
		}
	}
	rw.buffer.PushBack(seg)
}

// ReadBuffered reads buffered segments that are now in order.
func (rw *receiveWindow) ReadBuffered() [][]byte {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	var result [][]byte
	for e := rw.buffer.Front(); e != nil; {
		seg := e.Value.(*segment)
		if seg.seq == rw.next {
			result = append(result, seg.data)
			rw.next += uint32(len(seg.data))
			next := e.Next()
			rw.buffer.Remove(e)
			e = next
		} else if seg.seq < rw.next {
			// Duplicate, remove
			next := e.Next()
			rw.buffer.Remove(e)
			e = next
		} else {
			break
		}
	}

	return result
}

// WindowSize returns the current window size to advertise.
func (rw *receiveWindow) WindowSize() uint16 {
	rw.mu.RLock()
	defer rw.mu.RUnlock()

	// Simple calculation: fixed window minus buffered data
	buffered := 0
	for e := rw.buffer.Front(); e != nil; e = e.Next() {
		seg := e.Value.(*segment)
		buffered += len(seg.data)
	}

	available := rw.windowSize - buffered
	if available < 0 {
		available = 0
	}

	// Cap at max uint16
	if available > 65535 {
		available = 65535
	}

	return uint16(available)
}

// NextExpected returns the next expected sequence number.
func (rw *receiveWindow) NextExpected() uint32 {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	return rw.next
}
