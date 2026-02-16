// Package uqsp — runtime session adapters.
// RuntimeSession bridges UnifiedProtocol (which operates on net.Conn) into the
// transport.Session interface required by the agent and gateway via smux
// multiplexing.  This replaces the direct Dialer/Listener code paths so that
// all production traffic flows through the variant-compiled overlay chain.
package uqsp

import (
	"net"
	"sync/atomic"

	"stealthlink/internal/mux"
	"stealthlink/internal/transport"

	"github.com/xtaci/smux"
)

// RuntimeSession wraps a single UnifiedProtocol connection (net.Conn) and
// multiplexes it with smux to satisfy transport.Session.
type RuntimeSession struct {
	conn      net.Conn
	smuxSess  *smux.Session
	variant   ProtocolVariant
	shaperCfg mux.ShaperConfig
	shaper    *mux.PriorityShaper
	closed    atomic.Bool

	// Optional callbacks
	onStreamOpened func()
	onStreamClosed func()
}

// NewRuntimeSession creates a RuntimeSession from a raw net.Conn produced by
// UnifiedProtocol.Dial.  The caller chooses whether this end is the smux
// client or server (isServer=true for the accept side).
func NewRuntimeSession(conn net.Conn, smuxCfg *smux.Config, shaperCfg mux.ShaperConfig, variant ProtocolVariant, isServer bool) (*RuntimeSession, error) {
	if smuxCfg == nil {
		smuxCfg = smux.DefaultConfig()
	}

	var (
		sess   *smux.Session
		err    error
		shaper *mux.PriorityShaper
	)
	if shaperCfg.Enabled {
		shaper = mux.NewPriorityShaper(conn, shaperCfg)
		conn = shaper
	}

	if isServer {
		sess, err = smux.Server(conn, smuxCfg)
	} else {
		sess, err = smux.Client(conn, smuxCfg)
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &RuntimeSession{
		conn:      conn,
		smuxSess:  sess,
		variant:   variant,
		shaperCfg: shaperCfg,
		shaper:    shaper,
	}, nil
}

// SetMetricsCallbacks installs optional stream open/close hooks.
func (rs *RuntimeSession) SetMetricsCallbacks(opened, closed func()) {
	rs.onStreamOpened = opened
	rs.onStreamClosed = closed
}

// --- transport.Session implementation ---

func (rs *RuntimeSession) OpenStream() (net.Conn, error) {
	if rs.closed.Load() {
		return nil, ErrSessionClosed
	}
	stream, err := rs.smuxSess.OpenStream()
	if err != nil {
		return nil, err
	}
	if rs.onStreamOpened != nil {
		rs.onStreamOpened()
	}
	return &runtimeStreamWrapper{Stream: stream, session: rs}, nil
}

func (rs *RuntimeSession) AcceptStream() (net.Conn, error) {
	if rs.closed.Load() {
		return nil, ErrSessionClosed
	}
	stream, err := rs.smuxSess.AcceptStream()
	if err != nil {
		return nil, err
	}
	if rs.onStreamOpened != nil {
		rs.onStreamOpened()
	}
	return &runtimeStreamWrapper{Stream: stream, session: rs}, nil
}

func (rs *RuntimeSession) Close() error {
	if !rs.closed.CompareAndSwap(false, true) {
		return nil
	}
	if rs.smuxSess != nil {
		_ = rs.smuxSess.Close()
	}
	if rs.conn != nil {
		return rs.conn.Close()
	}
	return nil
}

func (rs *RuntimeSession) LocalAddr() net.Addr {
	if rs.conn == nil {
		return nil
	}
	return rs.conn.LocalAddr()
}

func (rs *RuntimeSession) RemoteAddr() net.Addr {
	if rs.conn == nil {
		return nil
	}
	return rs.conn.RemoteAddr()
}

// Session returns a transport.Session view of this RuntimeSession.
// This is a convenience wrapper for callers that already hold a *RuntimeSession.
func (rs *RuntimeSession) Session() transport.Session {
	return rs
}

// runtimeStreamWrapper wraps smux.Stream with a close callback.
type runtimeStreamWrapper struct {
	*smux.Stream
	session *RuntimeSession
	closed  atomic.Bool
}

func (s *runtimeStreamWrapper) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return s.Stream.Close()
	}
	if s.session.onStreamClosed != nil {
		s.session.onStreamClosed()
	}
	if s.session.shaper != nil {
		s.session.shaper.RemoveStream(s.Stream.ID())
	}
	return s.Stream.Close()
}
