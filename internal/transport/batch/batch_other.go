//go:build !linux
// +build !linux

// Package batch provides fallback implementations for non-Linux platforms.
package batch

import (
	"fmt"
	"net"
)

// SendBatch falls back to individual sends on non-Linux platforms.
func SendBatch(conn *net.UDPConn, msgs [][]byte) (int, error) {
	sent := 0
	for _, msg := range msgs {
		if _, err := conn.Write(msg); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// RecvBatch falls back to individual receives on non-Linux platforms.
func RecvBatch(conn *net.UDPConn, buffers [][]byte) (int, []net.Addr, error) {
	if len(buffers) == 0 {
		return 0, nil, nil
	}

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

	sent := 0
	for _, msg := range b.msgs {
		if _, err := b.conn.Write(msg); err != nil {
			b.msgs = b.msgs[:0]
			return sent, err
		}
		sent++
	}

	b.msgs = b.msgs[:0]
	return sent, nil
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
	n, addr, err := b.conn.ReadFromUDP(b.buffers[0])
	if err != nil {
		return nil, nil, err
	}

	msg := make([]byte, n)
	copy(msg, b.buffers[0])

	return [][]byte{msg}, []net.Addr{addr}, nil
}
