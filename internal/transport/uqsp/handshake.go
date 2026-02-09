package uqsp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"stealthlink/internal/transport"

	quic "github.com/quic-go/quic-go"
)

// HandshakeConfig configures the UQSP handshake
type HandshakeConfig struct {
	// AuthMode is the authentication mode: token, cert, psk
	AuthMode string

	// AuthToken is the shared authentication token
	AuthToken string

	// PSK is the pre-shared key for PSK mode
	PSK string

	// Enable0RTT enables 0-RTT handshake
	Enable0RTT bool

	// AntiReplayWindow is the replay protection window size
	AntiReplayWindow int

	// Capabilities are the supported capabilities
	Capabilities CapabilityFlag

	// Timeout is the handshake timeout
	Timeout time.Duration
}

// HandshakeResult contains the result of a handshake
type HandshakeResult struct {
	// Capabilities are the negotiated capabilities
	Capabilities CapabilityFlag

	// AuthSuccess indicates if authentication succeeded
	AuthSuccess bool

	// ProtocolVersion is the negotiated protocol version
	ProtocolVersion uint8
}

// HandshakeHandler handles UQSP handshakes
type HandshakeHandler struct {
	config *HandshakeConfig
}

// NewHandshakeHandler creates a new handshake handler
func NewHandshakeHandler(config *HandshakeConfig) *HandshakeHandler {
	if config == nil {
		config = &HandshakeConfig{
			AuthMode:     "token",
			Capabilities: CapabilityDatagram | CapabilityCapsule | Capability0RTT,
			Timeout:      DefaultHandshakeTimeout,
		}
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultHandshakeTimeout
	}
	return &HandshakeHandler{config: config}
}

// ClientHandshake performs the client side of the handshake
func (h *HandshakeHandler) ClientHandshake(ctx context.Context, conn *quic.Conn) (*HandshakeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, h.config.Timeout)
	defer cancel()

	// Open a stream for handshake
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open handshake stream: %w", err)
	}
	defer stream.Close()

	// Build handshake payload
	payload := &HandshakePayload{
		Version:      ProtocolVersion,
		Capabilities: h.config.Capabilities,
		AuthMode:     h.config.AuthMode,
		AuthData:     h.buildAuthData(),
	}

	// Send handshake
	header := &FrameHeader{
		Type:   FrameTypeHandshake,
		Length: uint16(len(payload.Encode())),
	}

	if _, err := stream.Write(header.Encode()); err != nil {
		return nil, fmt.Errorf("write handshake header: %w", err)
	}
	if _, err := stream.Write(payload.Encode()); err != nil {
		return nil, fmt.Errorf("write handshake payload: %w", err)
	}

	// Receive server response
	respHeader := &FrameHeader{}
	headerBuf := make([]byte, 11)
	if _, err := stream.Read(headerBuf); err != nil {
		return nil, fmt.Errorf("read handshake response header: %w", err)
	}
	if err := respHeader.Decode(headerBuf); err != nil {
		return nil, fmt.Errorf("decode handshake response header: %w", err)
	}

	if respHeader.Type != FrameTypeHandshake {
		return nil, fmt.Errorf("unexpected frame type: %s", respHeader.Type)
	}

	respPayload := make([]byte, respHeader.Length)
	if _, err := stream.Read(respPayload); err != nil {
		return nil, fmt.Errorf("read handshake response payload: %w", err)
	}

	resp := &HandshakePayload{}
	if err := resp.Decode(respPayload); err != nil {
		return nil, fmt.Errorf("decode handshake response: %w", err)
	}

	// Validate response
	if resp.Version != ProtocolVersion {
		return nil, fmt.Errorf("protocol version mismatch: got %d, want %d", resp.Version, ProtocolVersion)
	}

	// Negotiate capabilities
	negotiated := h.config.Capabilities & resp.Capabilities

	// Check authentication
	authSuccess := h.verifyAuthData(resp.AuthMode, resp.AuthData)

	return &HandshakeResult{
		Capabilities:    negotiated,
		AuthSuccess:     authSuccess,
		ProtocolVersion: resp.Version,
	}, nil
}

// ServerHandshake performs the server side of the handshake
func (h *HandshakeHandler) ServerHandshake(ctx context.Context, conn *quic.Conn) (*HandshakeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, h.config.Timeout)
	defer cancel()

	// Accept handshake stream
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept handshake stream: %w", err)
	}
	defer stream.Close()

	// Read client handshake
	headerBuf := make([]byte, 11)
	if _, err := stream.Read(headerBuf); err != nil {
		return nil, fmt.Errorf("read handshake header: %w", err)
	}

	header := &FrameHeader{}
	if err := header.Decode(headerBuf); err != nil {
		return nil, fmt.Errorf("decode handshake header: %w", err)
	}

	if header.Type != FrameTypeHandshake {
		return nil, fmt.Errorf("unexpected frame type: %s", header.Type)
	}

	payloadBuf := make([]byte, header.Length)
	if _, err := stream.Read(payloadBuf); err != nil {
		return nil, fmt.Errorf("read handshake payload: %w", err)
	}

	payload := &HandshakePayload{}
	if err := payload.Decode(payloadBuf); err != nil {
		return nil, fmt.Errorf("decode handshake payload: %w", err)
	}

	// Validate version
	if payload.Version != ProtocolVersion {
		// Send error response
		h.sendErrorResponse(stream, ErrorCodeProtocol)
		return nil, fmt.Errorf("protocol version mismatch: got %d, want %d", payload.Version, ProtocolVersion)
	}

	// Verify authentication
	authSuccess := h.verifyAuthData(payload.AuthMode, payload.AuthData)
	if !authSuccess {
		h.sendErrorResponse(stream, ErrorCodeAuth)
		return nil, fmt.Errorf("authentication failed")
	}

	// Negotiate capabilities
	negotiated := h.config.Capabilities & payload.Capabilities

	// Send response
	respPayload := &HandshakePayload{
		Version:      ProtocolVersion,
		Capabilities: negotiated,
		AuthMode:     h.config.AuthMode,
		AuthData:     h.buildAuthData(),
	}

	respHeader := &FrameHeader{
		Type:   FrameTypeHandshake,
		Length: uint16(len(respPayload.Encode())),
	}

	if _, err := stream.Write(respHeader.Encode()); err != nil {
		return nil, fmt.Errorf("write handshake response header: %w", err)
	}
	if _, err := stream.Write(respPayload.Encode()); err != nil {
		return nil, fmt.Errorf("write handshake response payload: %w", err)
	}

	return &HandshakeResult{
		Capabilities:    negotiated,
		AuthSuccess:     true,
		ProtocolVersion: payload.Version,
	}, nil
}

// buildAuthData builds authentication data based on mode
func (h *HandshakeHandler) buildAuthData() []byte {
	switch h.config.AuthMode {
	case "token":
		if h.config.AuthToken == "" {
			return nil
		}
		// Hash the token for transmission
		hash := sha256.Sum256([]byte(h.config.AuthToken))
		return hash[:]
	case "psk":
		if h.config.PSK == "" {
			return nil
		}
		// Hash the PSK for transmission
		hash := sha256.Sum256([]byte(h.config.PSK))
		return hash[:]
	case "cert":
		// Certificate-based auth - no data needed in handshake
		return nil
	default:
		return nil
	}
}

// verifyAuthData verifies authentication data
func (h *HandshakeHandler) verifyAuthData(mode string, data []byte) bool {
	switch mode {
	case "token":
		if h.config.AuthToken == "" {
			return false
		}
		expected := sha256.Sum256([]byte(h.config.AuthToken))
		return len(data) == len(expected) && subtle.ConstantTimeCompare(expected[:], data) == 1
	case "psk":
		if h.config.PSK == "" {
			return false
		}
		expected := sha256.Sum256([]byte(h.config.PSK))
		return len(data) == len(expected) && subtle.ConstantTimeCompare(expected[:], data) == 1
	case "cert":
		// Certificate-based auth is handled at TLS layer
		return true
	default:
		return false
	}
}

// sendErrorResponse sends an error response
func (h *HandshakeHandler) sendErrorResponse(stream *quic.Stream, code ErrorCode) {
	payload := &ControlPayload{
		ControlType: ControlTypeError,
		Data:        []byte{byte(code)},
	}
	header := &FrameHeader{
		Type:   FrameTypeControl,
		Length: uint16(len(payload.Encode())),
	}
	_, _ = stream.Write(header.Encode())
	_, _ = stream.Write(payload.Encode())
}

// GuardHandshake performs a simple guard token handshake
// This is used for backward compatibility with existing guard mechanism
func GuardHandshake(conn *quic.Stream, token string, timeout time.Duration, isServer bool) error {
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	if isServer {
		return transport.RecvGuard(&quicStreamConn{stream: conn}, token)
	}
	return transport.SendGuard(&quicStreamConn{stream: conn}, token)
}

// IsValidBase64Key32 checks if a string is a valid base64-encoded 32-byte key
func IsValidBase64Key32(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}
