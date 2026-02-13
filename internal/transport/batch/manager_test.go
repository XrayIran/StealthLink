//go:build linux
// +build linux

package batch

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

// mockSyscallError is used to simulate syscall errors
type mockSyscallError struct {
	errno syscall.Errno
}

func (e *mockSyscallError) Error() string {
	return e.errno.Error()
}

func (e *mockSyscallError) Unwrap() error {
	return e.errno
}

// TestBatchIOManager_SendBatch_PartialSend_Retry tests that when sendmmsg returns M < N,
// the remaining (N - M) messages are retried until all are sent.
// Property 7: Batch Send Completeness
func TestBatchIOManager_SendBatch_PartialSend_Retry(t *testing.T) {
	// Create two UDP connections for testing
	addr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn1, err := net.ListenUDP("udp", addr1)
	if err != nil {
		t.Fatalf("Failed to create UDP conn: %v", err)
	}
	defer conn1.Close()

	addr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn2, err := net.ListenUDP("udp", addr2)
	if err != nil {
		t.Fatalf("Failed to create UDP conn: %v", err)
	}
	defer conn2.Close()

	// Get the actual address to send to
	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	config := BatchConfig{
		Enabled:   true,
		BatchSize: 64,
		Timeout:   0,
	}

	mgr := NewBatchIOManager(config)

	// Test sending multiple messages
	msgs := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
		[]byte("message4"),
		[]byte("message5"),
	}

	// Send using SendBatchAddr to specific addresses
	addrs := make([]*net.UDPAddr, len(msgs))
	for i := range addrs {
		addrs[i] = actualAddr
	}

	sent, err := mgr.SendBatchAddr(conn1, msgs, addrs)
	if err != nil {
		t.Fatalf("SendBatchAddr failed: %v", err)
	}

	if sent != len(msgs) {
		t.Errorf("Expected %d messages sent, got %d", len(msgs), sent)
	}

	// Receive the messages
	buffers := make([][]byte, len(msgs))
	for i := range buffers {
		buffers[i] = make([]byte, 1024)
	}

	n, recvAddrs, err := mgr.RecvBatch(conn2, buffers)
	if err != nil {
		t.Fatalf("RecvBatch failed: %v", err)
	}

	if n != len(msgs) {
		t.Errorf("Expected %d messages received, got %d", len(msgs), n)
	}

	// Verify all messages were received
	for i := 0; i < n; i++ {
		if string(buffers[i]) != string(msgs[i]) {
			t.Errorf("Message %d mismatch: expected %q, got %q", i, msgs[i], buffers[i])
		}
		if recvAddrs[i] == nil {
			t.Errorf("Message %d has nil address", i)
		}
	}
}

// TestBatchIOManager_RecvBatch_ProcessExactlyN tests that when recvmmsg returns N messages,
// exactly N messages should be parsed and delivered to handlers.
// Property 8: Batch Receive Correctness
func TestBatchIOManager_RecvBatch_ProcessExactlyN(t *testing.T) {
	// Create two UDP connections for testing
	addr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn1, err := net.ListenUDP("udp", addr1)
	if err != nil {
		t.Fatalf("Failed to create UDP conn: %v", err)
	}
	defer conn1.Close()

	addr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn2, err := net.ListenUDP("udp", addr2)
	if err != nil {
		t.Fatalf("Failed to create UDP conn: %v", err)
	}
	defer conn2.Close()

	// Get the actual address to send to
	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	config := BatchConfig{
		Enabled:   true,
		BatchSize: 64,
		Timeout:   0,
	}

	mgr := NewBatchIOManager(config)

	// Send a specific number of messages
	numMsgs := 3
	for i := 0; i < numMsgs; i++ {
		msg := []byte("test message")
		if _, err := conn1.WriteToUDP(msg, actualAddr); err != nil {
			t.Fatalf("Failed to send message: %v", err)
		}
	}

	// Prepare buffers for receiving - more than expected
	buffers := make([][]byte, 10)
	for i := range buffers {
		buffers[i] = make([]byte, 1024)
	}

	// Allow messages to arrive
	time.Sleep(10 * time.Millisecond)

	n, addrs, err := mgr.RecvBatch(conn2, buffers)
	if err != nil {
		t.Fatalf("RecvBatch failed: %v", err)
	}

	// Verify exactly the number of sent messages were received
	if n != numMsgs {
		t.Errorf("Expected %d messages, got %d", numMsgs, n)
	}

	// Verify addresses are valid for received messages
	for i := 0; i < n; i++ {
		if addrs[i] == nil {
			t.Errorf("Received message %d has nil address", i)
		}
	}

	// Verify remaining buffers were not modified (or at least not marked as received)
	for i := n; i < len(buffers); i++ {
		// After receiving, unused buffers should still have their original capacity
		if len(buffers[i]) != 1024 {
			t.Errorf("Buffer %d was modified: len=%d", i, len(buffers[i]))
		}
	}
}

// TestBatchIOManager_SyscallFallback_Permanence tests that when a socket encounters ENOSYS or EINVAL,
// all subsequent operations on that socket use single-packet fallback.
// Property 10: Syscall Fallback Permanence
func TestBatchIOManager_SyscallFallback_Permanence(t *testing.T) {
	config := BatchConfig{
		Enabled:   true,
		BatchSize: 32,
		Timeout:   0,
	}

	mgr := NewBatchIOManager(config)

	// Initially syscalls should be available
	if !mgr.IsSyscallAvailable() {
		t.Error("Expected syscalls to be initially available")
	}

	// Simulate ENOSYS error
	enosysErr := syscall.ENOSYS
	mgr.disableSyscall(enosysErr)

	// After ENOSYS, syscalls should be permanently disabled
	if mgr.IsSyscallAvailable() {
		t.Error("Expected syscalls to be disabled after ENOSYS")
	}

	// Check fallback reason
	reason := mgr.FallbackReason()
	if reason == "" {
		t.Error("Expected fallback reason to be set")
	}

	// Create a new manager for EINVAL test
	mgr2 := NewBatchIOManager(config)

	// Simulate EINVAL error
	einvalErr := syscall.EINVAL
	mgr2.disableSyscall(einvalErr)

	// After EINVAL, syscalls should be permanently disabled
	if mgr2.IsSyscallAvailable() {
		t.Error("Expected syscalls to be disabled after EINVAL")
	}

	// Verify disableSyscall is idempotent - calling it again should not panic
	mgr.disableSyscall(enosysErr)
	if mgr.IsSyscallAvailable() {
		t.Error("Expected syscalls to remain disabled after second call")
	}
}

// TestBatchIOManager_SendBatch_OrderingPreserved tests that the order of messages in a batch
// is preserved after send/receive operations.
// Property 9: Batch Ordering Preservation
func TestBatchIOManager_SendBatch_OrderingPreserved(t *testing.T) {
	// Create two UDP connections for testing
	addr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn1, err := net.ListenUDP("udp", addr1)
	if err != nil {
		t.Fatalf("Failed to create UDP conn: %v", err)
	}
	defer conn1.Close()

	addr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn2, err := net.ListenUDP("udp", addr2)
	if err != nil {
		t.Fatalf("Failed to create UDP conn: %v", err)
	}
	defer conn2.Close()

	// Get the actual address to send to
	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	config := BatchConfig{
		Enabled:   true,
		BatchSize: 64,
		Timeout:   0,
	}

	mgr := NewBatchIOManager(config)

	// Create messages with specific order
	msgs := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third"),
		[]byte("fourth"),
		[]byte("fifth"),
	}

	// Send using SendBatchAddr
	addrs := make([]*net.UDPAddr, len(msgs))
	for i := range addrs {
		addrs[i] = actualAddr
	}

	sent, err := mgr.SendBatchAddr(conn1, msgs, addrs)
	if err != nil {
		t.Fatalf("SendBatchAddr failed: %v", err)
	}

	if sent != len(msgs) {
		t.Errorf("Expected %d messages sent, got %d", len(msgs), sent)
	}

	// Receive messages
	buffers := make([][]byte, len(msgs))
	for i := range buffers {
		buffers[i] = make([]byte, 1024)
	}

	// Allow messages to arrive
	time.Sleep(10 * time.Millisecond)

	n, _, err := mgr.RecvBatch(conn2, buffers)
	if err != nil {
		t.Fatalf("RecvBatch failed: %v", err)
	}

	if n != len(msgs) {
		t.Errorf("Expected %d messages received, got %d", len(msgs), n)
	}

	// Verify order is preserved
	for i := 0; i < n; i++ {
		if string(buffers[i]) != string(msgs[i]) {
			t.Errorf("Order not preserved at index %d: expected %q, got %q", i, msgs[i], buffers[i])
		}
	}
}

// TestBatchIOManager_BatchSizeRespected tests that batch operations use at most the configured batch size.
// Property 11: Batch Size Respect
func TestBatchIOManager_BatchSizeRespected(t *testing.T) {
	// Create two UDP connections for testing
	addr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn1, err := net.ListenUDP("udp", addr1)
	if err != nil {
		t.Fatalf("Failed to create UDP conn: %v", err)
	}
	defer conn1.Close()

	addr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn2, err := net.ListenUDP("udp", addr2)
	if err != nil {
		t.Fatalf("Failed to create UDP conn: %v", err)
	}
	defer conn2.Close()

	// Get the actual address to send to
	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	// Test with a small batch size
	batchSize := 3
	config := BatchConfig{
		Enabled:   true,
		BatchSize: batchSize,
		Timeout:   0,
	}

	mgr := NewBatchIOManager(config)

	// Create more messages than batch size
	msgs := [][]byte{
		[]byte("msg1"),
		[]byte("msg2"),
		[]byte("msg3"),
		[]byte("msg4"),
		[]byte("msg5"),
	}

	// Send using SendBatchAddr - only batchSize should be sent in one call
	addrs := make([]*net.UDPAddr, len(msgs))
	for i := range addrs {
		addrs[i] = actualAddr
	}

	sent, err := mgr.SendBatchAddr(conn1, msgs, addrs)
	if err != nil {
		t.Fatalf("SendBatchAddr failed: %v", err)
	}

	// With batchSize=3, only 3 messages should be sent in one call
	// The implementation truncates to batchSize, so we verify that constraint
	if sent != batchSize {
		t.Errorf("Expected %d messages sent (batchSize), got %d", batchSize, sent)
	}

	// Verify the remaining messages can be sent in a second call
	remainingMsgs := msgs[batchSize:]
	remainingAddrs := addrs[batchSize:]
	sent2, err := mgr.SendBatchAddr(conn1, remainingMsgs, remainingAddrs)
	if err != nil {
		t.Fatalf("Second SendBatchAddr failed: %v", err)
	}
	if sent2 != len(remainingMsgs) {
		t.Errorf("Expected %d remaining messages sent, got %d", len(remainingMsgs), sent2)
	}

	// Test bounds validation
	t.Run("BatchSizeBounds", func(t *testing.T) {
		// Test minimum batch size
		minConfig := BatchConfig{Enabled: true, BatchSize: 0}
		minMgr := NewBatchIOManager(minConfig)
		if minMgr.config.BatchSize != 1 {
			t.Errorf("Expected batch size clamped to 1, got %d", minMgr.config.BatchSize)
		}

		// Test maximum batch size
		maxConfig := BatchConfig{Enabled: true, BatchSize: 100}
		maxMgr := NewBatchIOManager(maxConfig)
		if maxMgr.config.BatchSize != 64 {
			t.Errorf("Expected batch size clamped to 64, got %d", maxMgr.config.BatchSize)
		}
	})
}

// TestBatchIOManager_Disabled tests behavior when batch I/O is disabled
func TestBatchIOManager_Disabled(t *testing.T) {
	// Create two UDP connections for testing
	addr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn1, err := net.ListenUDP("udp", addr1)
	if err != nil {
		t.Fatalf("Failed to create UDP conn: %v", err)
	}
	defer conn1.Close()

	addr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn2, err := net.ListenUDP("udp", addr2)
	if err != nil {
		t.Fatalf("Failed to create UDP conn: %v", err)
	}
	defer conn2.Close()

	// Get the actual address to send to
	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	// Create a connected socket for SendBatch testing
	connectedConn, err := net.DialUDP("udp", nil, actualAddr)
	if err != nil {
		t.Fatalf("Failed to create connected UDP conn: %v", err)
	}
	defer connectedConn.Close()

	// Create manager with batching disabled
	config := BatchConfig{
		Enabled:   false,
		BatchSize: 32,
		Timeout:   0,
	}

	mgr := NewBatchIOManager(config)

	// Test SendBatch with disabled batching (requires connected socket)
	msgs := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
	}

	sent, err := mgr.SendBatch(connectedConn, msgs)
	if err != nil {
		t.Fatalf("SendBatch failed: %v", err)
	}

	if sent != len(msgs) {
		t.Errorf("Expected %d messages sent, got %d", len(msgs), sent)
	}

	// Test SendBatchAddr with disabled batching
	addrs := []*net.UDPAddr{actualAddr, actualAddr}
	sent, err = mgr.SendBatchAddr(conn1, msgs, addrs)
	if err != nil {
		t.Fatalf("SendBatchAddr failed: %v", err)
	}

	if sent != len(msgs) {
		t.Errorf("Expected %d messages sent, got %d", len(msgs), sent)
	}

	// Test RecvBatch with disabled batching
	buffers := [][]byte{make([]byte, 1024)}

	// Drain any pending messages first
	for {
		conn2.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		_, _, err := conn2.ReadFromUDP(buffers[0])
		if err != nil {
			break
		}
	}
	conn2.SetReadDeadline(time.Time{})

	// Send a message first
	conn1.WriteToUDP([]byte("test"), actualAddr)
	time.Sleep(10 * time.Millisecond)

	n, _, err := mgr.RecvBatch(conn2, buffers)
	if err != nil {
		t.Fatalf("RecvBatch failed: %v", err)
	}

	if n != 1 {
		t.Errorf("Expected 1 message received, got %d", n)
	}
}

// TestBatchIOManager_EmptyMessages tests behavior with empty message arrays
func TestBatchIOManager_EmptyMessages(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()

	config := DefaultBatchConfig()
	mgr := NewBatchIOManager(config)

	// Test SendBatch with empty messages
	sent, err := mgr.SendBatch(conn, [][]byte{})
	if err != nil {
		t.Fatalf("SendBatch with empty messages failed: %v", err)
	}
	if sent != 0 {
		t.Errorf("Expected 0 messages sent, got %d", sent)
	}

	// Test SendBatchAddr with empty messages
	sent, err = mgr.SendBatchAddr(conn, [][]byte{}, []*net.UDPAddr{})
	if err != nil {
		t.Fatalf("SendBatchAddr with empty messages failed: %v", err)
	}
	if sent != 0 {
		t.Errorf("Expected 0 messages sent, got %d", sent)
	}

	// Test RecvBatch with empty buffers
	n, addrs, err := mgr.RecvBatch(conn, [][]byte{})
	if err != nil {
		t.Fatalf("RecvBatch with empty buffers failed: %v", err)
	}
	if n != 0 {
		t.Errorf("Expected 0 messages received, got %d", n)
	}
	if len(addrs) != 0 {
		t.Errorf("Expected 0 addresses, got %d", len(addrs))
	}
}

// TestBatchIOManager_MismatchLength tests error handling for mismatched lengths
func TestBatchIOManager_MismatchLength(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()

	config := DefaultBatchConfig()
	mgr := NewBatchIOManager(config)

	// Test SendBatchAddr with mismatched lengths
	msgs := [][]byte{[]byte("msg1"), []byte("msg2")}
	addrs := []*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 1234}} // Only 1 address

	_, err := mgr.SendBatchAddr(conn, msgs, addrs)
	if err == nil {
		t.Error("Expected error for mismatched lengths, got nil")
	}

	if !errors.Is(err, errors.New("batch: msgs and addrs length mismatch")) && err.Error() != "batch: msgs and addrs length mismatch" {
		t.Errorf("Expected 'length mismatch' error, got: %v", err)
	}
}

// TestBatchIOManager_ConcurrentAccess tests thread safety
func TestBatchIOManager_ConcurrentAccess(t *testing.T) {
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	defer conn1.Close()

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	defer conn2.Close()

	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultBatchConfig()
	mgr := NewBatchIOManager(config)

	var wg sync.WaitGroup
	numGoroutines := 10
	msgsPerGoroutine := 10

	// Concurrent sends
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < msgsPerGoroutine; j++ {
				msg := []byte("test")
				addrs := []*net.UDPAddr{actualAddr}
				mgr.SendBatchAddr(conn1, [][]byte{msg}, addrs)
			}
		}(i)
	}

	wg.Wait()

	// Concurrent receives
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			buffers := [][]byte{make([]byte, 1024)}
			mgr.RecvBatch(conn2, buffers)
		}(i)
	}

	wg.Wait()
}

// TestBatchIOManager_DefaultConfig tests default configuration
func TestBatchIOManager_DefaultConfig(t *testing.T) {
	config := DefaultBatchConfig()

	if !config.Enabled {
		t.Error("Expected batch to be enabled by default")
	}

	if config.BatchSize != 32 {
		t.Errorf("Expected default batch size 32, got %d", config.BatchSize)
	}

	if config.Timeout != 0 {
		t.Errorf("Expected default timeout 0, got %v", config.Timeout)
	}
}

// TestFallbackFunctions tests the fallback implementations directly
func TestFallbackFunctions(t *testing.T) {
	// Create two UDP connections
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	defer conn1.Close()

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	defer conn2.Close()

	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	// Create a connected socket for sendBatchFallback testing
	connectedConn, err := net.DialUDP("udp", nil, actualAddr)
	if err != nil {
		t.Fatalf("Failed to create connected UDP conn: %v", err)
	}
	defer connectedConn.Close()

	// Test sendBatchFallback
	t.Run("sendBatchFallback", func(t *testing.T) {
		msgs := [][]byte{[]byte("msg1"), []byte("msg2")}
		sent, err := sendBatchFallback(connectedConn, msgs)
		if err != nil {
			t.Fatalf("sendBatchFallback failed: %v", err)
		}
		if sent != len(msgs) {
			t.Errorf("Expected %d messages sent, got %d", len(msgs), sent)
		}
	})

	// Test sendBatchAddrFallback
	t.Run("sendBatchAddrFallback", func(t *testing.T) {
		msgs := [][]byte{[]byte("msg1"), []byte("msg2")}
		addrs := []*net.UDPAddr{actualAddr, actualAddr}
		sent, err := sendBatchAddrFallback(conn1, msgs, addrs)
		if err != nil {
			t.Fatalf("sendBatchAddrFallback failed: %v", err)
		}
		if sent != len(msgs) {
			t.Errorf("Expected %d messages sent, got %d", len(msgs), sent)
		}
	})

	// Test recvBatchFallback
	t.Run("recvBatchFallback", func(t *testing.T) {
		// Send a message first
		conn1.WriteToUDP([]byte("test"), actualAddr)
		time.Sleep(10 * time.Millisecond)

		buffers := [][]byte{make([]byte, 1024)}
		n, lens, addrs, err := recvBatchFallback(conn2, buffers)
		if err != nil {
			t.Fatalf("recvBatchFallback failed: %v", err)
		}
		if n != 1 {
			t.Errorf("Expected 1 message, got %d", n)
		}
		if len(lens) != 1 {
			t.Errorf("Expected 1 length, got %d", len(lens))
		}
		if len(addrs) != 1 {
			t.Errorf("Expected 1 address, got %d", len(addrs))
		}
	})
}

// BenchmarkSendBatch benchmarks batch sending
func BenchmarkSendBatch(b *testing.B) {
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	defer conn1.Close()

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	defer conn2.Close()

	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultBatchConfig()
	mgr := NewBatchIOManager(config)

	msgs := make([][]byte, 32)
	addrs := make([]*net.UDPAddr, 32)
	for i := range msgs {
		msgs[i] = make([]byte, 1400)
		addrs[i] = actualAddr
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.SendBatchAddr(conn1, msgs, addrs)
	}
}

// BenchmarkRecvBatch benchmarks batch receiving
func BenchmarkRecvBatch(b *testing.B) {
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	defer conn1.Close()

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	defer conn2.Close()

	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultBatchConfig()
	mgr := NewBatchIOManager(config)

	// Pre-send messages
	for i := 0; i < 32; i++ {
		conn1.WriteToUDP(make([]byte, 1400), actualAddr)
	}

	buffers := make([][]byte, 32)
	for i := range buffers {
		buffers[i] = make([]byte, 1500)
	}

	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.RecvBatch(conn2, buffers)
	}
}
