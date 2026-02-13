package mux

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockConn struct {
	net.Conn
	buf bytes.Buffer
	mu  sync.Mutex
}

func (m *mockConn) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.Write(p)
}

func (m *mockConn) Close() error { return nil }

func makeFrame(cmd byte, sid uint32, payload []byte) []byte {
	f := make([]byte, 8+len(payload))
	f[0] = 1 // version
	f[1] = cmd
	binary.LittleEndian.PutUint16(f[2:4], uint16(len(payload)))
	binary.LittleEndian.PutUint32(f[4:8], sid)
	copy(f[8:], payload)
	return f
}

func TestPriorityShaper_Priority(t *testing.T) {
	mock := &mockConn{}
	config := ShaperConfig{
		Enabled:         true,
		MaxControlBurst: 16,
		QueueSize:       1024,
	}
	shaper := NewPriorityShaper(mock, config)
	defer shaper.Close()

	// Write data then control
	dataFrame := makeFrame(smuxCmdPSH, 1, []byte("data"))
	controlFrame := makeFrame(smuxCmdSYN, 1, []byte("syn"))

	// We need to write them fast so they are both in queue together
	shaper.Write(dataFrame)
	shaper.Write(controlFrame)

	// Wait for loop
	time.Sleep(200 * time.Millisecond)

	mock.mu.Lock()
	res := mock.buf.Bytes()
	mock.mu.Unlock()

	// Control (SYN) should come first despite being written second
	assert.Equal(t, controlFrame, res[:len(controlFrame)])
	assert.Equal(t, dataFrame, res[len(controlFrame):len(controlFrame)+len(dataFrame)])
}

func TestPriorityShaper_Starvation(t *testing.T) {
	mock := &mockConn{}
	config := ShaperConfig{
		Enabled:         true,
		MaxControlBurst: 2, // Small burst for easier testing
		QueueSize:       1024,
	}
	shaper := NewPriorityShaper(mock, config)
	defer shaper.Close()

	// Write 4 control then 1 data
	cf1 := makeFrame(smuxCmdSYN, 1, []byte("c1"))
	cf2 := makeFrame(smuxCmdSYN, 1, []byte("c2"))
	cf3 := makeFrame(smuxCmdSYN, 1, []byte("c3"))
	cf4 := makeFrame(smuxCmdSYN, 1, []byte("c4"))
	df1 := makeFrame(smuxCmdPSH, 1, []byte("d1"))

	shaper.Write(cf1)
	shaper.Write(cf2)
	shaper.Write(cf3)
	shaper.Write(cf4)
	shaper.Write(df1)

	time.Sleep(200 * time.Millisecond)

	mock.mu.Lock()
	res := mock.buf.Bytes()
	mock.mu.Unlock()

	// Should be: c1, c2, d1, c3, c4
	// Because MaxControlBurst is 2
	expected := append(cf1, cf2...)
	expected = append(expected, df1...)
	expected = append(expected, cf3...)
	expected = append(expected, cf4...)
	
	assert.Equal(t, expected, res)
}

func TestPriorityShaper_RoundRobin(t *testing.T) {
	mock := &mockConn{}
	config := ShaperConfig{
		Enabled:         true,
		MaxControlBurst: 1, 
		QueueSize:       1024,
	}
	shaper := NewPriorityShaper(mock, config)
	defer shaper.Close()

	// Multiple streams with data only
	df1_1 := makeFrame(smuxCmdPSH, 1, []byte("d1-1"))
	df1_2 := makeFrame(smuxCmdPSH, 1, []byte("d1-2"))
	df2_1 := makeFrame(smuxCmdPSH, 2, []byte("d2-1"))
	df2_2 := makeFrame(smuxCmdPSH, 2, []byte("d2-2"))

	shaper.Write(df1_1)
	shaper.Write(df1_2)
	shaper.Write(df2_1)
	shaper.Write(df2_2)

	time.Sleep(200 * time.Millisecond)

	mock.mu.Lock()
	res := mock.buf.Bytes()
	mock.mu.Unlock()

	// Should be: d1-1, d2-1, d1-2, d2-2 (RR between stream 1 and 2)
	expected := append(df1_1, df2_1...)
	expected = append(expected, df1_2...)
	expected = append(expected, df2_2...)
	
	assert.Equal(t, expected, res)
}

func TestPriorityShaper_Backpressure(t *testing.T) {
	// Let's just block the write loop using blockingConn.
}

type blockingConn struct {
	net.Conn
	block chan struct{}
}

func (b *blockingConn) Write(p []byte) (n int, err error) {
	<-b.block
	return len(p), nil
}

func (b *blockingConn) Close() error { return nil }

func TestPriorityShaper_QueueFull(t *testing.T) {
	block := make(chan struct{})
	bc := &blockingConn{block: block}
	config := ShaperConfig{
		Enabled:   true,
		QueueSize: 2,
	}
	shaper := NewPriorityShaper(bc, config)
	defer shaper.Close()

	df1 := makeFrame(smuxCmdPSH, 1, []byte("d1"))
	df2 := makeFrame(smuxCmdPSH, 2, []byte("d2"))
	df3 := makeFrame(smuxCmdPSH, 3, []byte("d3"))

	// Write 2 frames (one goes to writeLoop, one to queue) - wait, writeLoop pulls one immediately.
	// Actually:
	// 1. Write d1 -> totalFrames=1 -> writeLoop pulls d1, totalFrames=0.
	// 2. Write d2 -> totalFrames=1.
	// 3. Write d3 -> totalFrames=2.
	// 4. Write d4 -> blocks.

	shaper.Write(df1)
	shaper.Write(df2)
	shaper.Write(df3)
	
	done := make(chan struct{})
	go func() {
		shaper.Write(makeFrame(smuxCmdPSH, 4, []byte("d4")))
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("Write should have blocked")
	case <-time.After(100 * time.Millisecond):
		// Success
	}

	// Release one
	block <- struct{}{}
	
	select {
	case <-done:
		// Success
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Write should have unblocked")
	}
}
