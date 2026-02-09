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

type Dialer interface {
	Dial(ctx context.Context, addr string) (Session, error)
}

type Listener interface {
	Accept() (Session, error)
	Close() error
	Addr() net.Addr
}
