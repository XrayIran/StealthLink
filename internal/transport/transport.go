package transport

import (
	"context"
	"errors"
	"net"
)

// ErrPoolClosed is returned when attempting to use a closed connection pool.
var ErrPoolClosed = errors.New("connection pool is closed")

type Session interface {
	OpenStream() (net.Conn, error)
	AcceptStream() (net.Conn, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// DatagramSession is an optional capability for transports that support
// unordered / unreliable datagrams alongside streams (e.g. UQSP over QUIC).
//
// Callers must type-assert a transport.Session to DatagramSession before use.
// Implementations should ensure CloseDatagramSession unblocks ReceiveDatagram.
type DatagramSession interface {
	// SupportsNativeDatagrams returns true when the underlying transport supports
	// "native" datagrams (e.g. QUIC DATAGRAM frames) without tunneling them over
	// a reliable stream.
	SupportsNativeDatagrams() bool

	// OpenDatagramSession opens a bidirectional datagram channel to the peer and
	// returns the session ID.
	OpenDatagramSession() (uint32, error)

	// WaitDatagramSession blocks until the session exists locally (i.e. the peer
	// has processed the open request) or ctx is canceled.
	WaitDatagramSession(ctx context.Context, sessionID uint32) error

	// CloseDatagramSession closes the datagram channel.
	CloseDatagramSession(sessionID uint32) error

	// SendDatagram sends a single datagram on the channel.
	SendDatagram(sessionID uint32, payload []byte) error

	// ReceiveDatagram receives a single datagram on the channel.
	ReceiveDatagram(sessionID uint32) ([]byte, error)
}

type Dialer interface {
	Dial(ctx context.Context, addr string) (Session, error)
}

type Listener interface {
	Accept() (Session, error)
	Close() error
	Addr() net.Addr
}
