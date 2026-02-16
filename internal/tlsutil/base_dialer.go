package tlsutil

import (
	"context"
	"net"
)

// BaseDialFunc allows callers to override how TCP connections are established.
// This is used to route dials through underlay dialers (e.g. SOCKS/WARP).
type BaseDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type baseDialerKey struct{}

// WithBaseDialFunc stores a dial function in the context.
func WithBaseDialFunc(ctx context.Context, fn BaseDialFunc) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, baseDialerKey{}, fn)
}

// BaseDialFuncFromContext returns the dial function stored in ctx, if any.
func BaseDialFuncFromContext(ctx context.Context) (BaseDialFunc, bool) {
	if ctx == nil {
		return nil, false
	}
	v := ctx.Value(baseDialerKey{})
	fn, ok := v.(BaseDialFunc)
	return fn, ok && fn != nil
}
