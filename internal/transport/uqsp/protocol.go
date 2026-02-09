// Package uqsp implements the Unified QUIC Superset Protocol.
//
// UQSP is a unified QUIC-based transport protocol that consolidates features from:
// - QUIC (stream transport, 0-RTT)
// - Hysteria2 (UDP datagrams, salamander obfuscation, brutal congestion)
// - TUIC (control frames, UDP session semantics)
// - MASQUE/CONNECT-UDP (capsule semantics for UDP/IP tunneling)
// - AmneziaWG (junk schedules, packet shaping, timing noise)
// - FinalMask (header morphing, pluggable camouflage)
package uqsp

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	// ProtocolVersion is the current UQSP protocol version
	ProtocolVersion = 1

	// DefaultALPN is the default ALPN for UQSP
	DefaultALPN = "uqsp/1"

	// MaxFrameSize is the maximum frame size
	MaxFrameSize = 65535

	// MaxDatagramSize is the maximum datagram size
	MaxDatagramSize = 1350

	// DefaultHandshakeTimeout is the default handshake timeout
	DefaultHandshakeTimeout = 10 * time.Second

	// DefaultMaxIdleTimeout is the default max idle timeout
	DefaultMaxIdleTimeout = 45 * time.Second

	// DefaultKeepAlivePeriod is the default keepalive period
	DefaultKeepAlivePeriod = 15 * time.Second
)

// FrameType represents UQSP frame types
type FrameType uint8

const (
	// FrameTypeHandshake is used for handshake messages
	FrameTypeHandshake FrameType = 0x01

	// FrameTypeControl is used for control messages (stream/UDP session mgmt)
	FrameTypeControl FrameType = 0x02

	// FrameTypeData is used for data streams
	FrameTypeData FrameType = 0x03

	// FrameTypeDatagram is used for UDP datagrams
	FrameTypeDatagram FrameType = 0x04

	// FrameTypeCapsule is used for CONNECT-UDP/IP capsules
	FrameTypeCapsule FrameType = 0x05

	// FrameTypeHeartbeat is used for keepalive heartbeats
	FrameTypeHeartbeat FrameType = 0x06

	// FrameTypeClose is used for graceful close
	FrameTypeClose FrameType = 0x07
)

// String returns the string representation of a frame type
func (f FrameType) String() string {
	switch f {
	case FrameTypeHandshake:
		return "HANDSHAKE"
	case FrameTypeControl:
		return "CONTROL"
	case FrameTypeData:
		return "DATA"
	case FrameTypeDatagram:
		return "DATAGRAM"
	case FrameTypeCapsule:
		return "CAPSULE"
	case FrameTypeHeartbeat:
		return "HEARTBEAT"
	case FrameTypeClose:
		return "CLOSE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", f)
	}
}

// ControlType represents control frame subtypes
type ControlType uint8

const (
	// ControlTypeOpenStream requests opening a new stream
	ControlTypeOpenStream ControlType = 0x01

	// ControlTypeCloseStream closes a stream
	ControlTypeCloseStream ControlType = 0x02

	// ControlTypeOpenUDPSession opens a UDP relay session
	ControlTypeOpenUDPSession ControlType = 0x03

	// ControlTypeCloseUDPSession closes a UDP relay session
	ControlTypeCloseUDPSession ControlType = 0x04

	// ControlTypeUDPSessionAssoc associates a UDP session with an ID
	ControlTypeUDPSessionAssoc ControlType = 0x05

	// ControlTypeWindowUpdate updates flow control window
	ControlTypeWindowUpdate ControlType = 0x06

	// ControlTypeError signals an error condition
	ControlTypeError ControlType = 0x07
)

// String returns the string representation of a control type
func (c ControlType) String() string {
	switch c {
	case ControlTypeOpenStream:
		return "OPEN_STREAM"
	case ControlTypeCloseStream:
		return "CLOSE_STREAM"
	case ControlTypeOpenUDPSession:
		return "OPEN_UDP_SESSION"
	case ControlTypeCloseUDPSession:
		return "CLOSE_UDP_SESSION"
	case ControlTypeUDPSessionAssoc:
		return "UDP_SESSION_ASSOC"
	case ControlTypeWindowUpdate:
		return "WINDOW_UPDATE"
	case ControlTypeError:
		return "ERROR"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", c)
	}
}

// CapsuleType represents capsule types for CONNECT-UDP/IP
type CapsuleType uint64

const (
	// CapsuleTypeDatagram is a UDP datagram capsule (RFC 9298)
	CapsuleTypeDatagram CapsuleType = 0x00

	// CapsuleTypeAddressAssign assigns an address (RFC 9298)
	CapsuleTypeAddressAssign CapsuleType = 0x01

	// CapsuleTypeAddressRequest requests an address (RFC 9298)
	CapsuleTypeAddressRequest CapsuleType = 0x02

	// CapsuleTypeRouteAdvertisement advertises routes (RFC 9298)
	CapsuleTypeRouteAdvertisement CapsuleType = 0x03

	// CapsuleTypeConnectUDPContext is a CONNECT-UDP context ID
	CapsuleTypeConnectUDPContext CapsuleType = 0x04

	// CapsuleTypeConnectIPContext is a CONNECT-IP context ID
	CapsuleTypeConnectIPContext CapsuleType = 0x05

	// CapsuleTypeJunk is a junk/padding capsule for AWG-style obfuscation
	CapsuleTypeJunk CapsuleType = 0xFF
)

// String returns the string representation of a capsule type
func (c CapsuleType) String() string {
	switch c {
	case CapsuleTypeDatagram:
		return "DATAGRAM"
	case CapsuleTypeAddressAssign:
		return "ADDRESS_ASSIGN"
	case CapsuleTypeAddressRequest:
		return "ADDRESS_REQUEST"
	case CapsuleTypeRouteAdvertisement:
		return "ROUTE_ADVERTISEMENT"
	case CapsuleTypeConnectUDPContext:
		return "CONNECT_UDP_CONTEXT"
	case CapsuleTypeConnectIPContext:
		return "CONNECT_IP_CONTEXT"
	case CapsuleTypeJunk:
		return "JUNK"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", c)
	}
}

// CapabilityFlag represents UQSP capability flags
type CapabilityFlag uint32

const (
	// CapabilityDatagram indicates native QUIC datagram support
	CapabilityDatagram CapabilityFlag = 0x0001

	// CapabilityCapsule indicates CONNECT-UDP/IP capsule support
	CapabilityCapsule CapabilityFlag = 0x0002

	// Capability0RTT indicates 0-RTT support
	Capability0RTT CapabilityFlag = 0x0004

	// CapabilityBrutalCC indicates Brutal congestion control support
	CapabilityBrutalCC CapabilityFlag = 0x0008

	// CapabilitySalamander indicates Salamander obfuscation support
	CapabilitySalamander CapabilityFlag = 0x0010

	// CapabilityAWG indicates AWG-style junk/padding support
	CapabilityAWG CapabilityFlag = 0x0020

	// CapabilityKeyRotation indicates key rotation support
	CapabilityKeyRotation CapabilityFlag = 0x0040

	// CapabilityPostQuantum indicates post-quantum KEM support
	CapabilityPostQuantum CapabilityFlag = 0x0080
)

// Has returns true if the capability flag is set
func (c CapabilityFlag) Has(flag CapabilityFlag) bool {
	return c&flag != 0
}

// String returns the string representation of capability flags
func (c CapabilityFlag) String() string {
	var flags []string
	if c.Has(CapabilityDatagram) {
		flags = append(flags, "DATAGRAM")
	}
	if c.Has(CapabilityCapsule) {
		flags = append(flags, "CAPSULE")
	}
	if c.Has(Capability0RTT) {
		flags = append(flags, "0RTT")
	}
	if c.Has(CapabilityBrutalCC) {
		flags = append(flags, "BRUTAL_CC")
	}
	if c.Has(CapabilitySalamander) {
		flags = append(flags, "SALAMANDER")
	}
	if c.Has(CapabilityAWG) {
		flags = append(flags, "AWG")
	}
	if c.Has(CapabilityKeyRotation) {
		flags = append(flags, "KEY_ROTATION")
	}
	if c.Has(CapabilityPostQuantum) {
		flags = append(flags, "POST_QUANTUM")
	}
	if len(flags) == 0 {
		return "NONE"
	}
	return fmt.Sprintf("%v", flags)
}

// ErrorCode represents UQSP error codes
type ErrorCode uint32

const (
	// ErrorCodeNone indicates no error
	ErrorCodeNone ErrorCode = 0x00

	// ErrorCodeProtocol indicates a protocol error
	ErrorCodeProtocol ErrorCode = 0x01

	// ErrorCodeAuth indicates an authentication error
	ErrorCodeAuth ErrorCode = 0x02

	// ErrorCodeCapacity indicates a capacity/capability mismatch
	ErrorCodeCapacity ErrorCode = 0x03

	// ErrorCodeTimeout indicates a timeout
	ErrorCodeTimeout ErrorCode = 0x04

	// ErrorCodeClosed indicates graceful close
	ErrorCodeClosed ErrorCode = 0x05
)

// String returns the string representation of an error code
func (e ErrorCode) String() string {
	switch e {
	case ErrorCodeNone:
		return "NONE"
	case ErrorCodeProtocol:
		return "PROTOCOL"
	case ErrorCodeAuth:
		return "AUTH"
	case ErrorCodeCapacity:
		return "CAPACITY"
	case ErrorCodeTimeout:
		return "TIMEOUT"
	case ErrorCodeClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", e)
	}
}

// FrameHeader is the header for all UQSP frames
type FrameHeader struct {
	Type       FrameType
	Length     uint16
	StreamID   uint32 // For stream-associated frames
	SessionID  uint32 // For UDP session-associated frames
}

// Encode encodes the frame header to bytes
func (h *FrameHeader) Encode() []byte {
	buf := make([]byte, 11)
	buf[0] = byte(h.Type)
	binary.BigEndian.PutUint16(buf[1:3], h.Length)
	binary.BigEndian.PutUint32(buf[3:7], h.StreamID)
	binary.BigEndian.PutUint32(buf[7:11], h.SessionID)
	return buf
}

// Decode decodes the frame header from bytes
func (h *FrameHeader) Decode(data []byte) error {
	if len(data) < 11 {
		return fmt.Errorf("frame header too short: %d bytes", len(data))
	}
	h.Type = FrameType(data[0])
	h.Length = binary.BigEndian.Uint16(data[1:3])
	h.StreamID = binary.BigEndian.Uint32(data[3:7])
	h.SessionID = binary.BigEndian.Uint32(data[7:11])
	return nil
}

// HandshakePayload contains handshake data
type HandshakePayload struct {
	Version      uint8
	Capabilities CapabilityFlag
	AuthMode     string
	AuthData     []byte
}

// Encode encodes the handshake payload to bytes
func (h *HandshakePayload) Encode() []byte {
	authModeLen := len(h.AuthMode)
	buf := make([]byte, 6+authModeLen+len(h.AuthData))
	buf[0] = h.Version
	binary.BigEndian.PutUint32(buf[1:5], uint32(h.Capabilities))
	buf[5] = byte(authModeLen)
	copy(buf[6:], h.AuthMode)
	copy(buf[6+authModeLen:], h.AuthData)
	return buf
}

// Decode decodes the handshake payload from bytes
func (h *HandshakePayload) Decode(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("handshake payload too short: %d bytes", len(data))
	}
	h.Version = data[0]
	h.Capabilities = CapabilityFlag(binary.BigEndian.Uint32(data[1:5]))
	authModeLen := int(data[5])
	if len(data) < 6+authModeLen {
		return fmt.Errorf("handshake payload too short for auth mode")
	}
	h.AuthMode = string(data[6 : 6+authModeLen])
	h.AuthData = data[6+authModeLen:]
	return nil
}

// ControlPayload contains control frame data
type ControlPayload struct {
	ControlType ControlType
	Data        []byte
}

// Encode encodes the control payload to bytes
func (c *ControlPayload) Encode() []byte {
	buf := make([]byte, 1+len(c.Data))
	buf[0] = byte(c.ControlType)
	copy(buf[1:], c.Data)
	return buf
}

// Decode decodes the control payload from bytes
func (c *ControlPayload) Decode(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("control payload too short")
	}
	c.ControlType = ControlType(data[0])
	c.Data = data[1:]
	return nil
}

// UDPSessionInfo contains UDP session information
type UDPSessionInfo struct {
	SessionID   uint32
	TargetAddr  string
	ContextID   uint64
}

// Encode encodes the UDP session info to bytes
func (u *UDPSessionInfo) Encode() []byte {
	addrLen := len(u.TargetAddr)
	buf := make([]byte, 13+addrLen)
	binary.BigEndian.PutUint32(buf[0:4], u.SessionID)
	binary.BigEndian.PutUint64(buf[4:12], u.ContextID)
	buf[12] = byte(addrLen)
	copy(buf[13:], u.TargetAddr)
	return buf
}

// Decode decodes the UDP session info from bytes
func (u *UDPSessionInfo) Decode(data []byte) error {
	if len(data) < 13 {
		return fmt.Errorf("UDP session info too short")
	}
	u.SessionID = binary.BigEndian.Uint32(data[0:4])
	u.ContextID = binary.BigEndian.Uint64(data[4:12])
	addrLen := int(data[12])
	if len(data) < 13+addrLen {
		return fmt.Errorf("UDP session info too short for address")
	}
	u.TargetAddr = string(data[13 : 13+addrLen])
	return nil
}
