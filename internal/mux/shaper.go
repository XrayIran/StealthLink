package mux

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"stealthlink/internal/metrics"
)

// smux frame types
const (
	smuxCmdSYN byte = iota
	smuxCmdFIN
	smuxCmdPSH
	smuxCmdNOP
	smuxCmdUPD
)

// ShaperConfig defines the configuration for the priority shaper.
type ShaperConfig struct {
	Enabled         bool
	MaxControlBurst int // default: 16
	QueueSize       int // default: 1024
}

// PriorityShaper implements priority-based scheduling for smux frames.
type PriorityShaper struct {
	net.Conn
	config ShaperConfig

	mu           sync.Mutex
	cond         *sync.Cond
	controlMap   map[uint32][][]byte
	dataMap      map[uint32][][]byte
	controlOrder []uint32 // SIDs in round-robin order
	dataOrder    []uint32 // SIDs in round-robin order

	totalFrames  int
	controlBurst int
	writeBuf     []byte
	isProcessing bool

	die       chan struct{}
	closeOnce sync.Once
}

// NewPriorityShaper creates a new PriorityShaper.
func NewPriorityShaper(conn net.Conn, config ShaperConfig) *PriorityShaper {
	if config.MaxControlBurst <= 0 {
		config.MaxControlBurst = 16
	}
	if config.QueueSize <= 0 {
		config.QueueSize = 1024
	}

	ps := &PriorityShaper{
		Conn:       conn,
		config:     config,
		controlMap: make(map[uint32][][]byte),
		dataMap:    make(map[uint32][][]byte),
		die:        make(chan struct{}),
	}
	ps.cond = sync.NewCond(&ps.mu)

	go ps.writeLoop()
	return ps
}

// Write intercepts smux frames and queues them by priority.
func (ps *PriorityShaper) Write(p []byte) (n int, err error) {
	if !ps.config.Enabled {
		return ps.Conn.Write(p)
	}

	ps.mu.Lock()
	ps.writeBuf = append(ps.writeBuf, p...)
	if ps.isProcessing {
		ps.mu.Unlock()
		return len(p), nil
	}
	ps.isProcessing = true

	for {
		if len(ps.writeBuf) < 8 {
			ps.isProcessing = false
			ps.mu.Unlock()
			return len(p), nil
		}

		// Re-align if version is invalid
		if ps.writeBuf[0] != 1 && ps.writeBuf[0] != 2 {
			ps.writeBuf = ps.writeBuf[1:]
			continue
		}

		length := int(binary.LittleEndian.Uint16(ps.writeBuf[2:4]))
		totalLen := 8 + length
		if len(ps.writeBuf) < totalLen {
			ps.isProcessing = false
			ps.mu.Unlock()
			return len(p), nil
		}

		// Header is complete and frame is complete
		cmd := ps.writeBuf[1]
		sid := binary.LittleEndian.Uint32(ps.writeBuf[4:8])
		frame := make([]byte, totalLen)
		copy(frame, ps.writeBuf[:totalLen])
		ps.writeBuf = ps.writeBuf[totalLen:]

		// Wait if full
		for ps.totalFrames >= ps.config.QueueSize {
			select {
			case <-ps.die:
				ps.isProcessing = false
				ps.mu.Unlock()
				return len(p), io.ErrClosedPipe
			default:
			}
			ps.cond.Wait()
		}

		switch cmd {
		case smuxCmdSYN, smuxCmdFIN, smuxCmdNOP, smuxCmdUPD:
			if len(ps.controlMap[sid]) == 0 {
				ps.controlOrder = append(ps.controlOrder, sid)
			}
			ps.controlMap[sid] = append(ps.controlMap[sid], frame)
			metrics.IncSmuxShaperControlFrames()
		default:
			if len(ps.dataMap[sid]) == 0 {
				ps.dataOrder = append(ps.dataOrder, sid)
			}
			ps.dataMap[sid] = append(ps.dataMap[sid], frame)
			metrics.IncSmuxShaperDataFrames()
		}

		ps.totalFrames++
		metrics.SetSmuxShaperQueueSize(int64(ps.totalFrames))
		ps.cond.Broadcast()
		// We stay locked for the next iteration
	}
}

// RemoveStream removes all pending frames for a specific stream.
func (ps *PriorityShaper) RemoveStream(sid uint32) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if frames, ok := ps.controlMap[sid]; ok {
		ps.totalFrames -= len(frames)
		delete(ps.controlMap, sid)
		// Remove from order slice (inefficient but rare)
		for i, s := range ps.controlOrder {
			if s == sid {
				ps.controlOrder = append(ps.controlOrder[:i], ps.controlOrder[i+1:]...)
				break
			}
		}
	}

	if frames, ok := ps.dataMap[sid]; ok {
		ps.totalFrames -= len(frames)
		delete(ps.dataMap, sid)
		// Remove from order slice
		for i, s := range ps.dataOrder {
			if s == sid {
				ps.dataOrder = append(ps.dataOrder[:i], ps.dataOrder[i+1:]...)
				break
			}
		}
	}

	metrics.SetSmuxShaperQueueSize(int64(ps.totalFrames))
	ps.cond.Broadcast()
}

func (ps *PriorityShaper) writeLoop() {
	for {
		ps.mu.Lock()
		for ps.totalFrames == 0 {
			select {
			case <-ps.die:
				ps.mu.Unlock()
				return
			default:
			}
			ps.cond.Wait()
		}

		var frame []byte
		var useControl bool

		// Scheduling Policy
		if ps.controlBurst < ps.config.MaxControlBurst && len(ps.controlOrder) > 0 {
			useControl = true
		} else if len(ps.dataOrder) == 0 && len(ps.controlOrder) > 0 {
			useControl = true
		} else if len(ps.dataOrder) > 0 {
			useControl = false
			if ps.controlBurst >= ps.config.MaxControlBurst {
				metrics.IncSmuxShaperStarvationPreventions()
			}
		}

		if useControl {
			sid := ps.controlOrder[0]
			ps.controlOrder = ps.controlOrder[1:]
			frames := ps.controlMap[sid]
			frame = frames[0]
			if len(frames) > 1 {
				ps.controlMap[sid] = frames[1:]
				ps.controlOrder = append(ps.controlOrder, sid)
			} else {
				delete(ps.controlMap, sid)
			}
			ps.controlBurst++
		} else {
			sid := ps.dataOrder[0]
			ps.dataOrder = ps.dataOrder[1:]
			frames := ps.dataMap[sid]
			frame = frames[0]
			if len(frames) > 1 {
				ps.dataMap[sid] = frames[1:]
				ps.dataOrder = append(ps.dataOrder, sid)
			} else {
				delete(ps.dataMap, sid)
			}
			ps.controlBurst = 0
		}

		ps.totalFrames--
		metrics.SetSmuxShaperQueueSize(int64(ps.totalFrames))
		ps.cond.Broadcast()
		ps.mu.Unlock()

		_, err := ps.Conn.Write(frame)
		if err != nil {
			ps.Close()
			return
		}
	}
}

// Close closes the shaper and the underlying connection.
func (ps *PriorityShaper) Close() error {
	ps.closeOnce.Do(func() {
		ps.mu.Lock()
		close(ps.die)
		ps.cond.Broadcast()
		ps.mu.Unlock()
	})
	return ps.Conn.Close()
}
