package rawpacket

import (
	"fmt"
	"sync"
	"time"
)

// TCPState represents the TCP connection state
type TCPState int

const (
	TCPStateClosed TCPState = iota
	TCPStateListen
	TCPStateSynSent
	TCPStateSynReceived
	TCPStateEstablished
	TCPStateFinWait1
	TCPStateFinWait2
	TCPStateCloseWait
	TCPStateClosing
	TCPStateLastAck
	TCPStateTimeWait
)

// String returns the string representation of a TCP state
func (s TCPState) String() string {
	switch s {
	case TCPStateClosed:
		return "CLOSED"
	case TCPStateListen:
		return "LISTEN"
	case TCPStateSynSent:
		return "SYN_SENT"
	case TCPStateSynReceived:
		return "SYN_RECEIVED"
	case TCPStateEstablished:
		return "ESTABLISHED"
	case TCPStateFinWait1:
		return "FIN_WAIT_1"
	case TCPStateFinWait2:
		return "FIN_WAIT_2"
	case TCPStateCloseWait:
		return "CLOSE_WAIT"
	case TCPStateClosing:
		return "CLOSING"
	case TCPStateLastAck:
		return "LAST_ACK"
	case TCPStateTimeWait:
		return "TIME_WAIT"
	default:
		return "UNKNOWN"
	}
}

// TCPStateMachine implements a userspace TCP state machine for FakeTCP
type TCPStateMachine struct {
	state     TCPState
	stateMu   sync.RWMutex

	// Sequence numbers
	sndUna    uint32 // Send unacknowledged
	sndNxt    uint32 // Send next
	sndWnd    uint32 // Send window
	rcvNxt    uint32 // Receive next
	rcvWnd    uint32 // Receive window

	// Timestamps
	lastAckTime   time.Time
	lastRecvTime  time.Time

	// Options
	mss       uint16
	windowScale uint8
	tsEnabled bool
	tsRecent  uint32
	tsValue   uint32

	// Congestion control
	cwnd      uint32
	ssthresh  uint32

	mu        sync.RWMutex
}

// NewTCPStateMachine creates a new TCP state machine
func NewTCPStateMachine() *TCPStateMachine {
	return &TCPStateMachine{
		state:     TCPStateClosed,
		sndWnd:    65535,
		rcvWnd:    65535,
		mss:       1460,
		cwnd:      1460,
		ssthresh:  65535,
	}
}

// GetState returns the current TCP state
func (sm *TCPStateMachine) GetState() TCPState {
	sm.stateMu.RLock()
	defer sm.stateMu.RUnlock()
	return sm.state
}

// SetState sets the TCP state
func (sm *TCPStateMachine) SetState(state TCPState) {
	sm.stateMu.Lock()
	defer sm.stateMu.Unlock()
	sm.state = state
}

// ProcessSYN processes a SYN packet
func (sm *TCPStateMachine) ProcessSYN(seq uint32, options *TCPOptions) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	switch sm.state {
	case TCPStateClosed:
		// Active open - SYN sent
		sm.sndNxt = generateISN()
		sm.sndUna = sm.sndNxt
		sm.rcvNxt = seq + 1
		sm.state = TCPStateSynSent

	case TCPStateListen:
		// Passive open - SYN received
		sm.rcvNxt = seq + 1
		sm.sndNxt = generateISN()
		sm.sndUna = sm.sndNxt
		sm.state = TCPStateSynReceived

	default:
		return fmt.Errorf("invalid state for SYN: %s", sm.state)
	}

	if options != nil {
		sm.applyOptions(options)
	}

	return nil
}

// ProcessSYNACK processes a SYN-ACK packet
func (sm *TCPStateMachine) ProcessSYNACK(seq, ack uint32, options *TCPOptions) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state != TCPStateSynSent {
		return fmt.Errorf("invalid state for SYN-ACK: %s", sm.state)
	}

	// Verify ACK
	if ack != sm.sndNxt+1 {
		return fmt.Errorf("invalid ACK number")
	}

	sm.sndUna = ack
	sm.rcvNxt = seq + 1
	sm.state = TCPStateEstablished

	if options != nil {
		sm.applyOptions(options)
	}

	return nil
}

// ProcessACK processes an ACK packet
func (sm *TCPStateMachine) ProcessACK(ack uint32) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.lastAckTime = time.Now()

	// Update send window
	if ack > sm.sndUna {
		sm.sndUna = ack
	}

	switch sm.state {
	case TCPStateSynReceived:
		sm.state = TCPStateEstablished

	case TCPStateFinWait1:
		if ack == sm.sndNxt+1 {
			sm.state = TCPStateFinWait2
		}

	case TCPStateClosing:
		sm.state = TCPStateTimeWait

	case TCPStateLastAck:
		sm.state = TCPStateClosed
	}

	return nil
}

// ProcessFIN processes a FIN packet
func (sm *TCPStateMachine) ProcessFIN(seq uint32) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.rcvNxt = seq + 1

	switch sm.state {
	case TCPStateEstablished:
		sm.state = TCPStateCloseWait

	case TCPStateFinWait1:
		sm.state = TCPStateClosing

	case TCPStateFinWait2:
		sm.state = TCPStateTimeWait
	}

	return nil
}

// SendSYN prepares to send a SYN packet
func (sm *TCPStateMachine) SendSYN() (*TCPPacketInfo, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state != TCPStateClosed && sm.state != TCPStateListen {
		return nil, fmt.Errorf("invalid state for sending SYN: %s", sm.state)
	}

	seq := sm.sndNxt
	if sm.state == TCPStateClosed {
		seq = generateISN()
		sm.sndNxt = seq
		sm.sndUna = seq
	}

	return &TCPPacketInfo{
		Seq:   seq,
		Flags: TCPFlagSYN,
		Options: sm.buildOptions(),
	}, nil
}

// SendSYNACK prepares to send a SYN-ACK packet
func (sm *TCPStateMachine) SendSYNACK() (*TCPPacketInfo, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state != TCPStateSynReceived {
		return nil, fmt.Errorf("invalid state for sending SYN-ACK: %s", sm.state)
	}

	return &TCPPacketInfo{
		Seq:   sm.sndNxt,
		Ack:   sm.rcvNxt,
		Flags: TCPFlagSYN | TCPFlagACK,
		Options: sm.buildOptions(),
	}, nil
}

// SendACK prepares to send an ACK packet
func (sm *TCPStateMachine) SendACK() (*TCPPacketInfo, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	return &TCPPacketInfo{
		Seq:   sm.sndNxt,
		Ack:   sm.rcvNxt,
		Flags: TCPFlagACK,
		Window: uint16(sm.rcvWnd),
	}, nil
}

// SendFIN prepares to send a FIN packet
func (sm *TCPStateMachine) SendFIN() (*TCPPacketInfo, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.sndNxt++

	switch sm.state {
	case TCPStateEstablished:
		sm.state = TCPStateFinWait1

	case TCPStateCloseWait:
		sm.state = TCPStateLastAck
	}

	return &TCPPacketInfo{
		Seq:   sm.sndNxt,
		Ack:   sm.rcvNxt,
		Flags: TCPFlagFIN | TCPFlagACK,
	}, nil
}

// SendData prepares to send data
func (sm *TCPStateMachine) SendData(data []byte) (*TCPPacketInfo, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state != TCPStateEstablished {
		return nil, fmt.Errorf("cannot send data in state: %s", sm.state)
	}

	seq := sm.sndNxt
	sm.sndNxt += uint32(len(data))

	return &TCPPacketInfo{
		Seq:    seq,
		Ack:    sm.rcvNxt,
		Flags:  TCPFlagPSH | TCPFlagACK,
		Data:   data,
		Window: uint16(sm.rcvWnd),
	}, nil
}

// CanReceiveData checks if we can receive data in current state
func (sm *TCPStateMachine) CanReceiveData() bool {
	state := sm.GetState()
	return state == TCPStateEstablished ||
		state == TCPStateFinWait1 ||
		state == TCPStateFinWait2
}

// CanSendData checks if we can send data in current state
func (sm *TCPStateMachine) CanSendData() bool {
	return sm.GetState() == TCPStateEstablished
}

// applyOptions applies TCP options
func (sm *TCPStateMachine) applyOptions(options *TCPOptions) {
	if options.MSS > 0 {
		sm.mss = options.MSS
	}
	if options.WindowScale > 0 {
		sm.windowScale = options.WindowScale
	}
	sm.tsEnabled = options.TSEnabled
}

// buildOptions builds TCP options for outgoing packets
func (sm *TCPStateMachine) buildOptions() []TCPOption {
	var options []TCPOption

	// MSS option
	options = append(options, TCPOption{
		Type:   2,
		Length: 4,
		Data:   []byte{byte(sm.mss >> 8), byte(sm.mss)},
	})

	// Window scale option
	options = append(options, TCPOption{
		Type:   3,
		Length: 3,
		Data:   []byte{sm.windowScale},
	})

	// Timestamp option
	if sm.tsEnabled {
		now := uint32(time.Now().Unix())
		options = append(options, TCPOption{
			Type:   8,
			Length: 10,
			Data: []byte{
				byte(now >> 24), byte(now >> 16), byte(now >> 8), byte(now),
				byte(sm.tsRecent >> 24), byte(sm.tsRecent >> 16), byte(sm.tsRecent >> 8), byte(sm.tsRecent),
			},
		})
	}

	// SACK permitted
	options = append(options, TCPOption{
		Type:   4,
		Length: 2,
		Data:   []byte{},
	})

	return options
}

// TCPOptions contains parsed TCP options
type TCPOptions struct {
	MSS         uint16
	WindowScale uint8
	TSEnabled   bool
	TSValue     uint32
	TSRecent    uint32
	SACKPermitted bool
}

// TCPPacketInfo contains information for building a TCP packet
type TCPPacketInfo struct {
	Seq     uint32
	Ack     uint32
	Flags   TCPFlag
	Window  uint16
	Data    []byte
	Options []TCPOption
}

// generateISN generates an initial sequence number
func generateISN() uint32 {
	// RFC 793 recommends ISN be a random value
	// In practice, it's often based on a clock
	return uint32(time.Now().UnixNano())
}

// StateSummary returns a summary of the current state
func (sm *TCPStateMachine) StateSummary() map[string]interface{} {
	sm.mu.RLock()
	sm.stateMu.RLock()
	defer sm.mu.RUnlock()
	defer sm.stateMu.RUnlock()

	return map[string]interface{}{
		"state":       sm.state.String(),
		"snd_una":     sm.sndUna,
		"snd_nxt":     sm.sndNxt,
		"snd_wnd":     sm.sndWnd,
		"rcv_nxt":     sm.rcvNxt,
		"rcv_wnd":     sm.rcvWnd,
		"mss":         sm.mss,
		"window_scale": sm.windowScale,
		"cwnd":        sm.cwnd,
		"ssthresh":    sm.ssthresh,
	}
}
