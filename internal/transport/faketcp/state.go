package faketcp

// State represents the TCP connection state.
type State uint8

const (
	StateClosed       State = 0
	StateListen       State = 1
	StateSynSent      State = 2
	StateSynReceived  State = 3
	StateEstablished  State = 4
	StateFinWait1     State = 5
	StateFinWait2     State = 6
	StateCloseWait    State = 7
	StateClosing      State = 8
	StateLastAck      State = 9
	StateTimeWait     State = 10
)

// String returns the state name.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateListen:
		return "LISTEN"
	case StateSynSent:
		return "SYN-SENT"
	case StateSynReceived:
		return "SYN-RECEIVED"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait1:
		return "FIN-WAIT-1"
	case StateFinWait2:
		return "FIN-WAIT-2"
	case StateCloseWait:
		return "CLOSE-WAIT"
	case StateClosing:
		return "CLOSING"
	case StateLastAck:
		return "LAST-ACK"
	case StateTimeWait:
		return "TIME-WAIT"
	default:
		return "UNKNOWN"
	}
}

// IsActive returns true if the connection is in an active state.
func (s State) IsActive() bool {
	return s == StateEstablished || s == StateCloseWait
}

// IsClosing returns true if the connection is in a closing state.
func (s State) IsClosing() bool {
	return s == StateFinWait1 || s == StateFinWait2 ||
		s == StateClosing || s == StateLastAck || s == StateTimeWait
}

// CanSend returns true if data can be sent in this state.
func (s State) CanSend() bool {
	return s == StateEstablished
}

// CanReceive returns true if data can be received in this state.
func (s State) CanReceive() bool {
	return s == StateEstablished || s == StateFinWait1 || s == StateFinWait2
}
