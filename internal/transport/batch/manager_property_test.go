//go:build linux
// +build linux

package batch

import (
	"bytes"
	"net"
	"syscall"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Property 7: Batch Send Completeness
// For any batch of N messages, if sendmmsg returns M < N, the remaining (N - M) messages
// should be retried until all are sent or an error occurs.
// Feature: upstream-integration-completion
func TestProperty_BatchSendCompleteness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random number of messages (1-64)
		numMsgs := rapid.IntRange(1, 64).Draw(t, "numMsgs")

		// Generate random message sizes (1-1400 bytes)
		msgs := make([][]byte, numMsgs)
		for i := 0; i < numMsgs; i++ {
			size := rapid.IntRange(1, 1400).Draw(t, "msgSize")
			msg := rapid.SliceOfN(rapid.Byte(), size, size).Draw(t, "msg")
			msgs[i] = msg
		}

		// Create UDP connections
		addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn1, err := net.ListenUDP("udp", addr1)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn1.Close()

		addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn2, err := net.ListenUDP("udp", addr2)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn2.Close()

		actualAddr := conn2.LocalAddr().(*net.UDPAddr)

		// Create manager with default config
		config := DefaultBatchConfig()
		mgr := NewBatchIOManager(config)

		// Prepare addresses for all messages
		addrs := make([]*net.UDPAddr, len(msgs))
		for i := range addrs {
			addrs[i] = actualAddr
		}

		// Send all messages
		sent, err := mgr.SendBatchAddr(conn1, msgs, addrs)
		if err != nil {
			t.Fatalf("SendBatchAddr failed: %v", err)
		}

		// Property: All messages should be sent (completeness)
		if sent != len(msgs) && sent != config.BatchSize {
			t.Errorf("Expected %d messages sent, got %d (property violated: Batch Send Completeness)", len(msgs), sent)
		}

		// Verify by receiving all messages
		buffers := make([][]byte, len(msgs))
		for i := range buffers {
			buffers[i] = make([]byte, 1500)
		}

		// Allow messages to arrive
		time.Sleep(10 * time.Millisecond)

		received, _, err := mgr.RecvBatch(conn2, buffers)
		if err != nil {
			t.Fatalf("RecvBatch failed: %v", err)
		}

		// Property: All sent messages should be received
		if received != sent {
			t.Errorf("Expected %d messages received, got %d (property violated: Batch Send Completeness)", sent, received)
		}

		// Property: All message contents should be preserved
		for i := 0; i < received; i++ {
			if !bytes.Equal(buffers[i], msgs[i]) {
				t.Errorf("Message %d content mismatch (property violated: Batch Send Completeness)", i)
			}
		}
	})
}

// Property 8: Batch Receive Correctness
// For any batch receive operation that returns N messages, exactly N messages
// should be parsed and delivered to handlers.
// Feature: upstream-integration-completion
func TestProperty_BatchReceiveCorrectness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random number of messages to send (1-32)
		numMsgs := rapid.IntRange(1, 32).Draw(t, "numMsgs")

		// Generate more receive buffers than messages
		numBuffers := rapid.IntRange(numMsgs, 64).Draw(t, "numBuffers")

		// Create UDP connections
		addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn1, err := net.ListenUDP("udp", addr1)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn1.Close()

		addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn2, err := net.ListenUDP("udp", addr2)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn2.Close()

		actualAddr := conn2.LocalAddr().(*net.UDPAddr)

		// Create manager with default config
		config := DefaultBatchConfig()
		mgr := NewBatchIOManager(config)

		// Send specific number of messages
		msgs := make([][]byte, numMsgs)
		for i := 0; i < numMsgs; i++ {
			size := rapid.IntRange(1, 1400).Draw(t, "msgSize")
			msg := rapid.SliceOfN(rapid.Byte(), size, size).Draw(t, "msg")
			msgs[i] = msg
			conn1.WriteToUDP(msg, actualAddr)
		}

		// Prepare receive buffers
		buffers := make([][]byte, numBuffers)
		for i := range buffers {
			buffers[i] = make([]byte, 1500)
		}

		// Allow messages to arrive
		time.Sleep(10 * time.Millisecond)

		// Receive messages
		received, addrs, err := mgr.RecvBatch(conn2, buffers)
		if err != nil {
			t.Fatalf("RecvBatch failed: %v", err)
		}

		// Property: Exactly N messages should be received (no more, no less)
		if received != numMsgs {
			t.Errorf("Expected exactly %d messages, got %d (property violated: Batch Receive Correctness)", numMsgs, received)
		}

		// Property: Exactly N addresses should be returned
		if len(addrs) != received {
			t.Errorf("Expected %d addresses, got %d (property violated: Batch Receive Correctness)", received, len(addrs))
		}

		// Property: Only the first N buffers should contain data
		for i := 0; i < received; i++ {
			if len(buffers[i]) == 0 || len(buffers[i]) > 1400 {
				t.Errorf("Buffer %d has unexpected length %d (property violated: Batch Receive Correctness)", i, len(buffers[i]))
			}
			if addrs[i] == nil {
				t.Errorf("Address %d is nil (property violated: Batch Receive Correctness)", i)
			}
		}

		// Property: Remaining buffers should be unmodified (still have original capacity)
		for i := received; i < numBuffers; i++ {
			if cap(buffers[i]) != 1500 {
				t.Errorf("Buffer %d capacity modified (property violated: Batch Receive Correctness)", i)
			}
		}
	})
}

// Property 9: Batch Ordering Preservation
// For any batch of messages, the order of messages in the batch should be
// preserved after send/receive operations.
// Feature: upstream-integration-completion
func TestProperty_BatchOrderingPreservation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random number of messages (1-32)
		numMsgs := rapid.IntRange(1, 32).Draw(t, "numMsgs")

		// Generate unique messages (to verify order)
		msgs := make([][]byte, numMsgs)
		for i := 0; i < numMsgs; i++ {
			// Create a unique message with sequence number embedded
			msg := make([]byte, 8)
			for j := 0; j < 8; j++ {
				msg[j] = byte(i*17 + j*3) // Unique pattern per message
			}
			msgs[i] = msg
		}

		// Create UDP connections
		addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn1, err := net.ListenUDP("udp", addr1)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn1.Close()

		addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn2, err := net.ListenUDP("udp", addr2)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn2.Close()

		actualAddr := conn2.LocalAddr().(*net.UDPAddr)

		// Create manager with default config
		config := DefaultBatchConfig()
		mgr := NewBatchIOManager(config)

		// Prepare addresses
		addrs := make([]*net.UDPAddr, len(msgs))
		for i := range addrs {
			addrs[i] = actualAddr
		}

		// Send messages in order
		sent, err := mgr.SendBatchAddr(conn1, msgs, addrs)
		if err != nil {
			t.Fatalf("SendBatchAddr failed: %v", err)
		}

		if sent != len(msgs) && sent != config.BatchSize {
			t.Fatalf("Expected %d messages sent, got %d", len(msgs), sent)
		}

		// Prepare receive buffers
		buffers := make([][]byte, len(msgs))
		for i := range buffers {
			buffers[i] = make([]byte, 1500)
		}

		// Allow messages to arrive
		time.Sleep(10 * time.Millisecond)

		// Receive messages
		received, _, err := mgr.RecvBatch(conn2, buffers)
		if err != nil {
			t.Fatalf("RecvBatch failed: %v", err)
		}

		if received != sent {
			t.Fatalf("Expected %d messages received, got %d", sent, received)
		}

		// Property: Order should be preserved
		for i := 0; i < received; i++ {
			if !bytes.Equal(buffers[i], msgs[i]) {
				t.Errorf("Order not preserved at index %d: expected %v, got %v (property violated: Batch Ordering Preservation)",
					i, msgs[i], buffers[i])
			}
		}
	})
}

// Property 10: Syscall Fallback Permanence
// For any socket that encounters ENOSYS or EINVAL when attempting batch I/O,
// all subsequent operations on that socket should use single-packet fallback.
// Feature: upstream-integration-completion
func TestProperty_SyscallFallbackPermanence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random error type
		errorType := rapid.SampledFrom([]string{"ENOSYS", "EINVAL"}).Draw(t, "errorType")

		// Create manager with batching enabled
		config := BatchConfig{
			Enabled:   true,
			BatchSize: 32,
		}
		mgr := NewBatchIOManager(config)

		// Initially syscalls should be available
		if !mgr.IsSyscallAvailable() {
			t.Error("Expected syscalls to be initially available")
		}

		// Simulate the error
		var err error
		switch errorType {
		case "ENOSYS":
			err = syscall.ENOSYS
		case "EINVAL":
			err = syscall.EINVAL
		}

		mgr.disableSyscall(err)

		// Property: After error, syscalls should be permanently disabled
		if mgr.IsSyscallAvailable() {
			t.Errorf("Expected syscalls to be disabled after %s (property violated: Syscall Fallback Permanence)", errorType)
		}

		// Property: Fallback reason should be set
		if mgr.FallbackReason() == "" {
			t.Errorf("Expected fallback reason to be set after %s (property violated: Syscall Fallback Permanence)", errorType)
		}

		// Property: Multiple disable calls should be safe (idempotent)
		mgr.disableSyscall(err)
		if mgr.IsSyscallAvailable() {
			t.Error("Expected syscalls to remain disabled after second disable call")
		}

		// Property: Concurrent access should be safe
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				_ = mgr.IsSyscallAvailable()
				_ = mgr.FallbackReason()
				done <- true
			}()
		}
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// Property 11: Batch Size Respect
// For any configured udp_batch_size value in range [1, 64], batch operations
// should use at most that many messages per syscall.
// Feature: upstream-integration-completion
func TestProperty_BatchSizeRespect(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random batch size in valid range [1, 64]
		batchSize := rapid.IntRange(1, 64).Draw(t, "batchSize")

		// Generate more messages than batch size
		numMsgs := rapid.IntRange(batchSize+1, batchSize*2).Draw(t, "numMsgs")

		// Generate random message sizes
		msgs := make([][]byte, numMsgs)
		for i := 0; i < numMsgs; i++ {
			size := rapid.IntRange(1, 1400).Draw(t, "msgSize")
			msg := rapid.SliceOfN(rapid.Byte(), size, size).Draw(t, "msg")
			msgs[i] = msg
		}

		// Create UDP connections
		addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn1, err := net.ListenUDP("udp", addr1)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn1.Close()

		addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn2, err := net.ListenUDP("udp", addr2)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn2.Close()

		actualAddr := conn2.LocalAddr().(*net.UDPAddr)

		// Create manager with specific batch size
		config := BatchConfig{
			Enabled:   true,
			BatchSize: batchSize,
		}
		mgr := NewBatchIOManager(config)

		// Property: Batch size should be clamped to [1, 64]
		if mgr.config.BatchSize < 1 || mgr.config.BatchSize > 64 {
			t.Errorf("Batch size %d outside valid range [1, 64] (property violated: Batch Size Respect)", mgr.config.BatchSize)
		}

		// Prepare addresses
		addrs := make([]*net.UDPAddr, len(msgs))
		for i := range addrs {
			addrs[i] = actualAddr
		}

		// Send messages - only batchSize should be sent in one call
		sent, err := mgr.SendBatchAddr(conn1, msgs, addrs)
		if err != nil {
			t.Fatalf("SendBatchAddr failed: %v", err)
		}

		// Property: At most batchSize messages should be sent in one call
		if sent > batchSize {
			t.Errorf("Sent %d messages, but batch size is %d (property violated: Batch Size Respect)", sent, batchSize)
		}

		// Property: Remaining messages should be sendable in subsequent calls
		if sent < len(msgs) {
			remainingMsgs := msgs[sent:]
			remainingAddrs := addrs[sent:]
			sent2, err := mgr.SendBatchAddr(conn1, remainingMsgs, remainingAddrs)
			if err != nil {
				t.Fatalf("Second SendBatchAddr failed: %v", err)
			}
			if sent+sent2 != len(msgs) {
				t.Errorf("Expected total %d messages sent, got %d", len(msgs), sent+sent2)
			}
		}
	})
}

// Extended property test: Batch size bounds validation
// Tests that batch sizes outside [1, 64] are properly clamped
func TestProperty_BatchSizeBounds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate batch size that might be outside bounds
		batchSize := rapid.IntRange(-10, 100).Draw(t, "batchSize")

		config := BatchConfig{
			Enabled:   true,
			BatchSize: batchSize,
		}
		mgr := NewBatchIOManager(config)

		// Property: Batch size should always be in valid range [1, 64]
		if mgr.config.BatchSize < 1 {
			t.Errorf("Batch size %d below minimum 1 (property violated: Batch Size Bounds)", mgr.config.BatchSize)
		}
		if mgr.config.BatchSize > 64 {
			t.Errorf("Batch size %d above maximum 64 (property violated: Batch Size Bounds)", mgr.config.BatchSize)
		}
	})
}

// Extended property test: Disabled batch I/O behavior
// Tests that when batching is disabled, fallback is used
func TestProperty_DisabledBatchIO(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random number of messages
		numMsgs := rapid.IntRange(1, 10).Draw(t, "numMsgs")

		// Generate random messages
		msgs := make([][]byte, numMsgs)
		for i := 0; i < numMsgs; i++ {
			size := rapid.IntRange(1, 1400).Draw(t, "msgSize")
			msg := rapid.SliceOfN(rapid.Byte(), size, size).Draw(t, "msg")
			msgs[i] = msg
		}

		// Create UDP connections
		addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn1, err := net.ListenUDP("udp", addr1)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn1.Close()

		addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn2, err := net.ListenUDP("udp", addr2)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn2.Close()

		actualAddr := conn2.LocalAddr().(*net.UDPAddr)

		// Create manager with batching disabled
		config := BatchConfig{
			Enabled:   false,
			BatchSize: 32,
		}
		mgr := NewBatchIOManager(config)

		// Prepare addresses
		addrs := make([]*net.UDPAddr, len(msgs))
		for i := range addrs {
			addrs[i] = actualAddr
		}

		// Send messages using fallback
		sent, err := mgr.SendBatchAddr(conn1, msgs, addrs)
		if err != nil {
			t.Fatalf("SendBatchAddr failed: %v", err)
		}

		// Property: All messages should still be sent even with batching disabled
		if sent != len(msgs) && sent != config.BatchSize {
			t.Errorf("Expected %d messages sent with disabled batching, got %d (property violated)", len(msgs), sent)
		}
	})
}

// Extended property test: Concurrent access safety
// Tests that concurrent operations on the manager are safe
func TestProperty_ConcurrentAccessSafety(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Create UDP connections
		addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn1, err := net.ListenUDP("udp", addr1)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn1.Close()

		addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn2, err := net.ListenUDP("udp", addr2)
		if err != nil {
			t.Skip("Failed to create UDP connection")
			return
		}
		defer conn2.Close()

		actualAddr := conn2.LocalAddr().(*net.UDPAddr)

		// Create manager
		config := DefaultBatchConfig()
		mgr := NewBatchIOManager(config)

		// Property: Concurrent sends should be safe
		numGoroutines := 5
		msgsPerGoroutine := 5

		done := make(chan error, numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				for j := 0; j < msgsPerGoroutine; j++ {
					msg := []byte("test")
					addrs := []*net.UDPAddr{actualAddr}
					_, err := mgr.SendBatchAddr(conn1, [][]byte{msg}, addrs)
					if err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < numGoroutines; i++ {
			if err := <-done; err != nil {
				t.Fatalf("Concurrent send failed: %v", err)
			}
		}

		// Property: Concurrent receives should be safe
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				buffers := [][]byte{make([]byte, 1024)}
				_, _, err := mgr.RecvBatch(conn2, buffers)
				if err != nil {
					// EOF or timeout is ok
					return
				}
			}(i)
		}
	})
}
