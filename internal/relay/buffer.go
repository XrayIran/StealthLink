// Package relay provides buffer pooling for efficient packet relaying.
package relay

import (
	"sync"
	"sync/atomic"
)

// BufferSize is the default buffer size for relay operations.
const BufferSize = 64 * 1024

// bufferPool is a global pool of byte slices.
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, BufferSize)
		return &b
	},
}

// GetBuffer gets a buffer from the pool.
func GetBuffer() []byte {
	return *(bufferPool.Get().(*[]byte))
}

// PutBuffer returns a buffer to the pool.
func PutBuffer(b []byte) {
	if cap(b) >= BufferSize {
		bufferPool.Put(&b)
	}
}

// PooledBuffer is a buffer with reference counting.
type PooledBuffer struct {
	data []byte
	refs int32
	pool *BufferPool
}

// Retain increments the reference count.
func (b *PooledBuffer) Retain() {
	atomic.AddInt32(&b.refs, 1)
}

// Release decrements the reference count and returns to pool if zero.
func (b *PooledBuffer) Release() {
	if atomic.AddInt32(&b.refs, -1) == 0 {
		b.pool.put(b)
	}
}

// Data returns the underlying data.
func (b *PooledBuffer) Data() []byte {
	return b.data
}

// BufferPool provides pooled buffers with reference counting.
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool.
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &PooledBuffer{
					data: make([]byte, size),
					refs: 1,
				}
			},
		},
		size: size,
	}
}

// Get gets a buffer from the pool.
func (p *BufferPool) Get() *PooledBuffer {
	b := p.pool.Get().(*PooledBuffer)
	b.refs = 1
	b.pool = p
	return b
}

// put returns a buffer to the pool.
func (p *BufferPool) put(b *PooledBuffer) {
	b.data = b.data[:cap(b.data)] // Reset slice
	p.pool.Put(b)
}

// RingBuffer is a circular buffer for zero-copy operations.
type RingBuffer struct {
	data   []byte
	size   int
	head   int
	tail   int
	count  int
	mu     sync.Mutex
}

// NewRingBuffer creates a new ring buffer.
func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		data: make([]byte, size),
		size: size,
	}
}

// Write writes data to the ring buffer.
func (r *RingBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.count == r.size {
		return 0, nil // Full
	}

	n := len(p)
	if n > r.size-r.count {
		n = r.size - r.count
	}

	for i := 0; i < n; i++ {
		r.data[r.tail] = p[i]
		r.tail = (r.tail + 1) % r.size
	}

	r.count += n
	return n, nil
}

// Read reads data from the ring buffer.
func (r *RingBuffer) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.count == 0 {
		return 0, nil // Empty
	}

	n := len(p)
	if n > r.count {
		n = r.count
	}

	for i := 0; i < n; i++ {
		p[i] = r.data[r.head]
		r.head = (r.head + 1) % r.size
	}

	r.count -= n
	return n, nil
}

// Available returns the available space.
func (r *RingBuffer) Available() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size - r.count
}

// Buffered returns the buffered data size.
func (r *RingBuffer) Buffered() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// Reset clears the buffer.
func (r *RingBuffer) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.head = 0
	r.tail = 0
	r.count = 0
}
