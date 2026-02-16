package vpn

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/songgao/water"
	"stealthlink/internal/tun"
)

// Session represents a VPN session over a network connection.
type Session struct {
	config  Config
	iface   *water.Interface
	control net.Conn
	packets PacketTransport
	netcfg  NetworkConfig
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex
	closed  bool
	onError func(error)
}

// NewSession creates a new VPN session using stream-framed packets.
func NewSession(cfg Config, stream net.Conn) (*Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Session{
		config:  cfg,
		control: stream,
		packets: NewStreamPacketTransport(stream),
		ctx:     ctx,
		cancel:  cancel,
	}

	return s, nil
}

// NewSessionWithPacketTransport creates a new VPN session using an explicit packet transport.
// controlConn is kept open for the lifetime of the session (even if packet transport is datagram-based).
func NewSessionWithPacketTransport(cfg Config, controlConn net.Conn, pt PacketTransport) (*Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if pt == nil {
		return nil, fmt.Errorf("packet transport is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		config:  cfg,
		control: controlConn,
		packets: pt,
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

// SetErrorHandler sets a callback for error handling.
func (s *Session) SetErrorHandler(fn func(error)) {
	s.onError = fn
}

// Start initializes the VPN interface and starts bridging.
func (s *Session) Start() error {
	// Create TUN interface (L3 only)
	iface, err := tun.OpenWithMode(tun.Config{
		Name: s.config.Name,
		MTU:  s.config.MTU,
		Mode: s.config.Mode,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSetupFailed, err)
	}
	s.iface = iface

	// Setup network (IP assignment, routes, etc.)
	if err := s.setupNetwork(); err != nil {
		_ = iface.Close()
		return fmt.Errorf("%w: %v", ErrSetupFailed, err)
	}

	// Start bridging in background
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.bridge(); err != nil {
			if s.onError != nil {
				s.onError(err)
			}
		}
	}()

	return nil
}

// setupNetwork configures the interface with IP and routes.
func (s *Session) setupNetwork() error {
	cfg := NetworkConfig{
		InterfaceName: s.iface.Name(),
		InterfaceIP:   s.config.InterfaceIP,
		PeerIP:        s.config.PeerIP,
		MTU:           s.config.MTU,
		Routes:        s.config.Routes,
		DNS:           s.config.DNS,
	}

	s.netcfg = cfg
	return SetupInterface(cfg)
}

// bridge forwards packets between TUN and the packet transport.
func (s *Session) bridge() error {
	errCh := make(chan error, 2)

	// TUN -> Peer
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 64*1024)
		for {
			select {
			case <-s.ctx.Done():
				errCh <- s.ctx.Err()
				return
			default:
			}

			n, err := s.iface.Read(buf)
			if err != nil {
				errCh <- err
				return
			}

			if err := s.packets.SendPacket(buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Peer -> TUN
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-s.ctx.Done():
				errCh <- s.ctx.Err()
				return
			default:
			}

			pkt, err := s.packets.ReceivePacket()
			if err != nil {
				errCh <- err
				return
			}

			if _, err := s.iface.Write(pkt); err != nil {
				errCh <- err
				return
			}
		}
	}()

	return <-errCh
}

// Close shuts down the VPN session.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.cancel()

	// Unblock ReceivePacket() first.
	if s.packets != nil {
		_ = s.packets.Close()
	}

	// Best-effort rollback of host config (addresses/routes) for systemd restarts.
	if s.netcfg.InterfaceName != "" {
		_ = RemoveInterface(s.netcfg)
	}

	if s.control != nil {
		_ = s.control.Close()
	}

	if s.iface != nil {
		_ = s.iface.Close()
	}

	s.wg.Wait()

	return nil
}

// InterfaceName returns the name of the TUN interface.
func (s *Session) InterfaceName() string {
	if s.iface == nil {
		return ""
	}
	return s.iface.Name()
}

// IsClosed returns true if the session is closed.
func (s *Session) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// Bridge is a standalone function that bridges a TUN interface with a stream.
// This is a lower-level function for cases where Session management isn't needed.
func Bridge(ctx context.Context, iface io.ReadWriteCloser, stream net.Conn) error {
	errCh := make(chan error, 2)
	pt := NewStreamPacketTransport(stream)

	// Interface -> Stream
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := iface.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if err := pt.SendPacket(buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Stream -> Interface
	go func() {
		for {
			pkt, err := pt.ReceivePacket()
			if err != nil {
				errCh <- err
				return
			}
			if _, err := iface.Write(pkt); err != nil {
				errCh <- err
				return
			}
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		_ = stream.Close()
		_ = iface.Close()
		return ctx.Err()
	}
}
