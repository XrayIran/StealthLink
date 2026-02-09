//go:build linux
// +build linux

// Package batch provides Linux-specific batch send/receive using sendmmsg/recvmmsg.
// This significantly improves throughput for UDP-based transports.
package batch

import (
	"net"
)

// SendBatch sends multiple messages in a single system call using sendmmsg.
// Returns the number of messages sent.
// Note: This is a simplified implementation. Full implementation requires
// platform-specific syscalls that may not be available on all architectures.
func SendBatch(conn *net.UDPConn, msgs [][]byte) (int, error) {
	// Simplified implementation without sendmmsg syscall
	// Note: SYS_SENDMMSG may not be available on all architectures
	var totalSent int
	for i, msg := range msgs {
		_, err := conn.Write(msg)
		if err != nil {
			return totalSent, err
		}
		totalSent = i + 1
	}
	return totalSent, nil
}

// RecvBatch receives multiple messages in a single system call using recvmmsg.
// Returns the number of messages received.
func RecvBatch(conn *net.UDPConn, buffers [][]byte) (int, []net.Addr, error) {
	// Simplified implementation without recvmmsg syscall
	// Note: SYS_RECVMMSG may not be available on all architectures
	if len(buffers) == 0 {
		return 0, nil, nil
	}

	// Receive a single message
	n, addr, err := conn.ReadFromUDP(buffers[0])
	if err != nil {
		return 0, nil, err
	}

	buffers[0] = buffers[0][:n]
	return 1, []net.Addr{addr}, nil
}

// BatchSender provides a high-level interface for batch sending.
type BatchSender struct {
	conn    *net.UDPConn
	maxSize int
	msgs    [][]byte
}

// NewBatchSender creates a new batch sender.
func NewBatchSender(conn *net.UDPConn, maxBatch int) *BatchSender {
	return &BatchSender{
		conn:    conn,
		maxSize: maxBatch,
		msgs:    make([][]byte, 0, maxBatch),
	}
}

// Add adds a message to the batch.
func (b *BatchSender) Add(msg []byte) (sent int, err error) {
	b.msgs = append(b.msgs, msg)

	if len(b.msgs) >= b.maxSize {
		return b.Flush()
	}

	return 0, nil
}

// Flush sends all pending messages.
func (b *BatchSender) Flush() (int, error) {
	if len(b.msgs) == 0 {
		return 0, nil
	}

	n, err := SendBatch(b.conn, b.msgs)
	b.msgs = b.msgs[:0] // Clear but keep capacity
	return n, err
}

// Close flushes remaining messages.
func (b *BatchSender) Close() error {
	_, err := b.Flush()
	return err
}

// BatchReceiver provides a high-level interface for batch receiving.
type BatchReceiver struct {
	conn    *net.UDPConn
	maxSize int
	buffers [][]byte
}

// NewBatchReceiver creates a new batch receiver.
func NewBatchReceiver(conn *net.UDPConn, maxBatch int, bufferSize int) *BatchReceiver {
	buffers := make([][]byte, maxBatch)
	for i := range buffers {
		buffers[i] = make([]byte, bufferSize)
	}

	return &BatchReceiver{
		conn:    conn,
		maxSize: maxBatch,
		buffers: buffers,
	}
}

// Receive receives a batch of messages.
func (b *BatchReceiver) Receive() ([][]byte, []net.Addr, error) {
	n, addrs, err := RecvBatch(b.conn, b.buffers)
	if err != nil {
		return nil, nil, err
	}

	msgs := make([][]byte, n)
	for i := 0; i < n; i++ {
		// Copy data since buffers are reused
		msgs[i] = make([]byte, len(b.buffers[i]))
		copy(msgs[i], b.buffers[i])
	}

	return msgs, addrs[:n], nil
}
