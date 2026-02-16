package uqsp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

// ControlFrameHandler handles control frames
type ControlFrameHandler struct {
	handlers map[ControlType]ControlHandler
	mu       sync.RWMutex
}

// ControlHandler is a function that handles a control frame
type ControlHandler func(payload *ControlPayload) error

// NewControlFrameHandler creates a new control frame handler
func NewControlFrameHandler() *ControlFrameHandler {
	return &ControlFrameHandler{
		handlers: make(map[ControlType]ControlHandler),
	}
}

// RegisterHandler registers a handler for a control type
func (c *ControlFrameHandler) RegisterHandler(controlType ControlType, handler ControlHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[controlType] = handler
}

// HandleControl handles a control frame
func (c *ControlFrameHandler) HandleControl(payload *ControlPayload) error {
	c.mu.RLock()
	handler, ok := c.handlers[payload.ControlType]
	c.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no handler for control type: %s", payload.ControlType)
	}

	return handler(payload)
}

// OpenStreamRequest is a request to open a stream
type OpenStreamRequest struct {
	StreamID uint32
}

// Encode encodes the request
func (r *OpenStreamRequest) Encode() []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, r.StreamID)
	return buf
}

// Decode decodes the request
func (r *OpenStreamRequest) Decode(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("data too short")
	}
	r.StreamID = binary.BigEndian.Uint32(data)
	return nil
}

// CloseStreamRequest is a request to close a stream
type CloseStreamRequest struct {
	StreamID  uint32
	ErrorCode uint32
}

// Encode encodes the request
func (r *CloseStreamRequest) Encode() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], r.StreamID)
	binary.BigEndian.PutUint32(buf[4:8], r.ErrorCode)
	return buf
}

// Decode decodes the request
func (r *CloseStreamRequest) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("data too short")
	}
	r.StreamID = binary.BigEndian.Uint32(data[0:4])
	r.ErrorCode = binary.BigEndian.Uint32(data[4:8])
	return nil
}

// WindowUpdateFrame is a flow control window update
type WindowUpdateFrame struct {
	StreamID    uint32
	WindowDelta uint32
}

// Encode encodes the frame
func (w *WindowUpdateFrame) Encode() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], w.StreamID)
	binary.BigEndian.PutUint32(buf[4:8], w.WindowDelta)
	return buf
}

// Decode decodes the frame
func (w *WindowUpdateFrame) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("data too short")
	}
	w.StreamID = binary.BigEndian.Uint32(data[0:4])
	w.WindowDelta = binary.BigEndian.Uint32(data[4:8])
	return nil
}

// ErrorFrame is an error notification
type ErrorFrame struct {
	ErrorCode ErrorCode
	Message   string
}

// Encode encodes the frame
func (e *ErrorFrame) Encode() []byte {
	msgLen := len(e.Message)
	buf := make([]byte, 5+msgLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(e.ErrorCode))
	buf[4] = byte(msgLen)
	copy(buf[5:], e.Message)
	return buf
}

// Decode decodes the frame
func (e *ErrorFrame) Decode(data []byte) error {
	if len(data) < 5 {
		return fmt.Errorf("data too short")
	}
	e.ErrorCode = ErrorCode(binary.BigEndian.Uint32(data[0:4]))
	msgLen := int(data[4])
	if len(data) < 5+msgLen {
		return fmt.Errorf("data too short for message")
	}
	e.Message = string(data[5 : 5+msgLen])
	return nil
}

// ControlStreamReader reads control frames from a stream
type ControlStreamReader struct {
	reader io.Reader
	mu     sync.Mutex
}

// NewControlStreamReader creates a new control stream reader
func NewControlStreamReader(r io.Reader) *ControlStreamReader {
	return &ControlStreamReader{reader: r}
}

// ReadFrame reads a control frame
func (c *ControlStreamReader) ReadFrame() (*FrameHeader, *ControlPayload, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Read header
	headerBuf := make([]byte, 11)
	if _, err := io.ReadFull(c.reader, headerBuf); err != nil {
		return nil, nil, err
	}

	header := &FrameHeader{}
	if err := header.Decode(headerBuf); err != nil {
		return nil, nil, err
	}

	// Read payload
	payloadBuf := make([]byte, header.Length)
	if _, err := io.ReadFull(c.reader, payloadBuf); err != nil {
		return nil, nil, err
	}

	payload := &ControlPayload{}
	if err := payload.Decode(payloadBuf); err != nil {
		return nil, nil, err
	}

	return header, payload, nil
}

// ControlStreamWriter writes control frames to a stream
type ControlStreamWriter struct {
	writer io.Writer
	mu     sync.Mutex
}

// NewControlStreamWriter creates a new control stream writer
func NewControlStreamWriter(w io.Writer) *ControlStreamWriter {
	return &ControlStreamWriter{writer: w}
}

// WriteFrame writes a control frame
func (c *ControlStreamWriter) WriteFrame(payload *ControlPayload) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data := payload.Encode()
	header := &FrameHeader{
		Type:   FrameTypeControl,
		Length: uint16(len(data)),
	}

	if _, err := c.writer.Write(header.Encode()); err != nil {
		return err
	}
	_, err := c.writer.Write(data)
	return err
}

// WriteHeartbeat writes a heartbeat frame
func (c *ControlStreamWriter) WriteHeartbeat() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	header := &FrameHeader{
		Type:   FrameTypeHeartbeat,
		Length: 0,
	}

	_, err := c.writer.Write(header.Encode())
	return err
}

// WriteClose writes a close frame
func (c *ControlStreamWriter) WriteClose(code ErrorCode, message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	errFrame := &ErrorFrame{
		ErrorCode: code,
		Message:   message,
	}
	data := errFrame.Encode()

	payload := &ControlPayload{
		ControlType: ControlTypeError,
		Data:        data,
	}

	payloadData := payload.Encode()
	header := &FrameHeader{
		Type:   FrameTypeClose,
		Length: uint16(len(payloadData)),
	}

	if _, err := c.writer.Write(header.Encode()); err != nil {
		return err
	}
	_, err := c.writer.Write(payloadData)
	return err
}

// TUIC 0-RTT Support - Extended Control Frames

// ZeroRTTToken represents a 0-RTT session token for fast resumption
type ZeroRTTToken struct {
	Token        [32]byte
	SessionID    uint64
	CreatedAt    int64
	ExpiresAt    int64
	Capabilities CapabilityFlag
}

// Encode encodes the 0-RTT token
func (z *ZeroRTTToken) Encode() []byte {
	buf := make([]byte, 64)
	copy(buf[0:32], z.Token[:])
	binary.BigEndian.PutUint64(buf[32:40], z.SessionID)
	binary.BigEndian.PutUint64(buf[40:48], uint64(z.CreatedAt))
	binary.BigEndian.PutUint64(buf[48:56], uint64(z.ExpiresAt))
	binary.BigEndian.PutUint32(buf[56:60], uint32(z.Capabilities))
	return buf
}

// Decode decodes the 0-RTT token
func (z *ZeroRTTToken) Decode(data []byte) error {
	if len(data) < 60 {
		return fmt.Errorf("token data too short")
	}
	copy(z.Token[:], data[0:32])
	z.SessionID = binary.BigEndian.Uint64(data[32:40])
	z.CreatedAt = int64(binary.BigEndian.Uint64(data[40:48]))
	z.ExpiresAt = int64(binary.BigEndian.Uint64(data[48:56]))
	z.Capabilities = CapabilityFlag(binary.BigEndian.Uint32(data[56:60]))
	return nil
}

// IsValid checks if the token is still valid
func (z *ZeroRTTToken) IsValid() bool {
	now := time.Now().Unix()
	return now >= z.CreatedAt && now < z.ExpiresAt
}

// UDPSessionRequest requests to open a UDP session (TUIC-style)
type UDPSessionRequest struct {
	SessionID  uint32
	TargetAddr string
	TargetPort uint16
}

// Encode encodes the UDP session request
func (u *UDPSessionRequest) Encode() []byte {
	addrLen := len(u.TargetAddr)
	buf := make([]byte, 10+addrLen)
	binary.BigEndian.PutUint32(buf[0:4], u.SessionID)
	binary.BigEndian.PutUint16(buf[4:6], u.TargetPort)
	buf[6] = byte(addrLen)
	copy(buf[7:7+addrLen], u.TargetAddr)
	return buf
}

// Decode decodes the UDP session request
func (u *UDPSessionRequest) Decode(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("data too short")
	}
	u.SessionID = binary.BigEndian.Uint32(data[0:4])
	u.TargetPort = binary.BigEndian.Uint16(data[4:6])
	addrLen := int(data[6])
	if len(data) < 7+addrLen {
		return fmt.Errorf("data too short for address")
	}
	u.TargetAddr = string(data[7 : 7+addrLen])
	return nil
}

// UDPSessionResponse responds to a UDP session request
type UDPSessionResponse struct {
	SessionID uint32
	Accepted  bool
	ErrorCode uint32
}

// Encode encodes the UDP session response
func (u *UDPSessionResponse) Encode() []byte {
	buf := make([]byte, 9)
	binary.BigEndian.PutUint32(buf[0:4], u.SessionID)
	if u.Accepted {
		buf[4] = 1
	} else {
		buf[4] = 0
	}
	binary.BigEndian.PutUint32(buf[5:9], u.ErrorCode)
	return buf
}

// Decode decodes the UDP session response
func (u *UDPSessionResponse) Decode(data []byte) error {
	if len(data) < 9 {
		return fmt.Errorf("data too short")
	}
	u.SessionID = binary.BigEndian.Uint32(data[0:4])
	u.Accepted = data[4] != 0
	u.ErrorCode = binary.BigEndian.Uint32(data[5:9])
	return nil
}

// UDPSessionClose closes a UDP session
type UDPSessionClose struct {
	SessionID uint32
	ErrorCode uint32
}

// Encode encodes the UDP session close
func (u *UDPSessionClose) Encode() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], u.SessionID)
	binary.BigEndian.PutUint32(buf[4:8], u.ErrorCode)
	return buf
}

// Decode decodes the UDP session close
func (u *UDPSessionClose) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("data too short")
	}
	u.SessionID = binary.BigEndian.Uint32(data[0:4])
	u.ErrorCode = binary.BigEndian.Uint32(data[4:8])
	return nil
}

// UDPSessionAssoc associates a UDP session with a context
type UDPSessionAssoc struct {
	SessionID uint32
	ContextID uint64
}

// Encode encodes the UDP session association
func (u *UDPSessionAssoc) Encode() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:4], u.SessionID)
	binary.BigEndian.PutUint64(buf[4:12], u.ContextID)
	return buf
}

// Decode decodes the UDP session association
func (u *UDPSessionAssoc) Decode(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("data too short")
	}
	u.SessionID = binary.BigEndian.Uint32(data[0:4])
	u.ContextID = binary.BigEndian.Uint64(data[4:12])
	return nil
}

// HeartbeatFrame is a TUIC-style heartbeat with timestamp
type HeartbeatFrame struct {
	Timestamp int64
	SentBytes uint64
	RecvBytes uint64
}

// Encode encodes the heartbeat frame
func (h *HeartbeatFrame) Encode() []byte {
	buf := make([]byte, 24)
	binary.BigEndian.PutUint64(buf[0:8], uint64(h.Timestamp))
	binary.BigEndian.PutUint64(buf[8:16], h.SentBytes)
	binary.BigEndian.PutUint64(buf[16:24], h.RecvBytes)
	return buf
}

// Decode decodes the heartbeat frame
func (h *HeartbeatFrame) Decode(data []byte) error {
	if len(data) < 24 {
		return fmt.Errorf("data too short")
	}
	h.Timestamp = int64(binary.BigEndian.Uint64(data[0:8]))
	h.SentBytes = binary.BigEndian.Uint64(data[8:16])
	h.RecvBytes = binary.BigEndian.Uint64(data[16:24])
	return nil
}

// TokenManager manages 0-RTT tokens for session resumption
type TokenManager struct {
	tokens map[uint64]*ZeroRTTToken
	mu     sync.RWMutex
}

// NewTokenManager creates a new token manager
func NewTokenManager() *TokenManager {
	return &TokenManager{
		tokens: make(map[uint64]*ZeroRTTToken),
	}
}

// GenerateToken generates a new 0-RTT token
func (tm *TokenManager) GenerateToken(sessionID uint64, caps CapabilityFlag) *ZeroRTTToken {
	token := &ZeroRTTToken{
		SessionID:    sessionID,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(24 * time.Hour).Unix(),
		Capabilities: caps,
	}
	// Generate random token
	rand.Read(token.Token[:])

	tm.mu.Lock()
	tm.tokens[sessionID] = token
	tm.mu.Unlock()

	return token
}

// ValidateToken validates a 0-RTT token
func (tm *TokenManager) ValidateToken(sessionID uint64, tokenData [32]byte) bool {
	tm.mu.RLock()
	token, ok := tm.tokens[sessionID]
	tm.mu.RUnlock()

	if !ok {
		return false
	}

	if !token.IsValid() {
		return false
	}

	return token.Token == tokenData
}

// RemoveToken removes a token
func (tm *TokenManager) RemoveToken(sessionID uint64) {
	tm.mu.Lock()
	delete(tm.tokens, sessionID)
	tm.mu.Unlock()
}

// Cleanup removes expired tokens
func (tm *TokenManager) Cleanup() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now().Unix()
	for id, token := range tm.tokens {
		if now >= token.ExpiresAt {
			delete(tm.tokens, id)
		}
	}
}
