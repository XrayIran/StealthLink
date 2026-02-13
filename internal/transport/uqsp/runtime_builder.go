// Package uqsp — runtime adapters for transport.Dialer and transport.Listener.
// RuntimeDialer and RuntimeListener route all production traffic through
// BuildVariantForRole → UnifiedProtocol, replacing the legacy NewDialer /
// NewListener entrypoints.
package uqsp

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/mux"
	"stealthlink/internal/transport"

	"crypto/tls"

	"github.com/xtaci/smux"
	"stealthlink/internal/transport/pool"
)

// ---------------------------------------------------------------------------
// RuntimeDialer — implements transport.Dialer
// ---------------------------------------------------------------------------

// RuntimeDialer dials a UQSP connection using the unified variant runtime.
// The variant (4a–4e) is detected from config, and all overlays, WARP, and
// reverse mode are handled by the underlying UnifiedProtocol.
type RuntimeDialer struct {
	proto     *UnifiedProtocol
	variant   ProtocolVariant
	smuxCfg   *smux.Config
	shaperCfg mux.ShaperConfig
	authToken string
	mu        sync.Mutex

	poolEnabled bool
	poolConfig  pool.PoolConfig
	pools       sync.Map // addr -> *pool.AdaptivePool
}

type runtimeBaseDialer struct {
	rd   *RuntimeDialer
	addr string
}

func (d *runtimeBaseDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	return d.rd.dialOne(ctx, addr)
}

// NewRuntimeDialer creates a transport.Dialer backed by the unified variant
// runtime.  It calls BuildVariantForRole to compile the variant overlay chain.
func NewRuntimeDialer(cfg *config.Config, tlsCfg *tls.Config, smuxCfg *smux.Config, authToken string) (*RuntimeDialer, error) {
	// Apply per-variant config defaults before building.
	ApplyVariantProfile(cfg)

	proto, variant, err := BuildVariantForRole(cfg, tlsCfg, smuxCfg, authToken)
	if err != nil {
		return nil, fmt.Errorf("runtime dialer: %w", err)
	}

	log.Printf("UQSP runtime dialer ready: variant=%s (%s)",
		VariantName(variant), VariantDescription(variant))

	return &RuntimeDialer{
		proto:     proto,
		variant:   variant,
		smuxCfg:   smuxCfg,
		shaperCfg: mux.ShaperConfig{
			Enabled:         cfg.Mux.Shaper.Enabled,
			MaxControlBurst: cfg.Mux.Shaper.MaxControlBurst,
			QueueSize:       cfg.Mux.Shaper.QueueSize,
		},
		authToken: authToken,
		poolEnabled: cfg.Transport.Pool.Enabled,
		poolConfig: pool.PoolConfig{
			Mode:         pool.PoolMode(cfg.Transport.Pool.Mode),
			MinSize:      cfg.Transport.Pool.MinSize,
			MaxSize:      cfg.Transport.Pool.MaxSize,
			CooldownSecs: cfg.Transport.Pool.CooldownSecs,
		},
	}, nil
}

// Dial implements transport.Dialer.  It calls UnifiedProtocol.Dial (which
// applies all overlays + WARP + reverse handling), performs the guard handshake,
// then wraps the resulting net.Conn with smux to produce a transport.Session.
func (rd *RuntimeDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	if rd.poolEnabled {
		p, ok := rd.pools.Load(addr)
		if !ok {
			p, _ = rd.pools.LoadOrStore(addr, pool.NewAdaptivePool(rd.poolConfig, &runtimeBaseDialer{rd: rd, addr: addr}, addr))
		}
		return p.(*pool.AdaptivePool).Get(ctx)
	}

	return rd.dialOne(ctx, addr)
}

func (rd *RuntimeDialer) dialOne(ctx context.Context, addr string) (transport.Session, error) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	conn, err := rd.proto.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("variant dial: %w", err)
	}

	// Guard handshake
	if rd.authToken != "" {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := transport.SendGuard(conn, rd.authToken); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("guard send: %w", err)
		}
		_ = conn.SetDeadline(time.Time{})
	}

	rs, err := NewRuntimeSession(conn, rd.smuxCfg, rd.shaperCfg, rd.variant, false)
	if err != nil {
		return nil, fmt.Errorf("runtime session: %w", err)
	}

	return rs.Session(), nil
}

// Proto returns the underlying UnifiedProtocol for callers that need
// direct access (e.g. AttachSessionManager).
func (rd *RuntimeDialer) Proto() *UnifiedProtocol { return rd.proto }

// Variant returns which variant was detected and compiled.
func (rd *RuntimeDialer) Variant() ProtocolVariant { return rd.variant }

// Close releases resources owned by the underlying unified protocol (WARP/underlay/carrier).
func (rd *RuntimeDialer) Close() error {
	if rd.proto != nil {
		return rd.proto.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// RuntimeListener — implements transport.Listener
// ---------------------------------------------------------------------------

// RuntimeListener accepts UQSP connections using the unified variant runtime.
type RuntimeListener struct {
	proto     *UnifiedProtocol
	variant   ProtocolVariant
	smuxCfg   *smux.Config
	shaperCfg mux.ShaperConfig
	authToken string
	ln        net.Listener
	closed    chan struct{}
	closeOnce sync.Once
}

// NewRuntimeListener creates a transport.Listener backed by the unified variant
// runtime.  It calls BuildVariantForRole to compile the variant overlay chain and
// starts listening on the given address.
func NewRuntimeListener(listenAddr string, cfg *config.Config, tlsCfg *tls.Config, smuxCfg *smux.Config, authToken string) (*RuntimeListener, error) {
	// Apply per-variant config defaults before building.
	ApplyVariantProfile(cfg)

	proto, variant, err := BuildVariantForRole(cfg, tlsCfg, smuxCfg, authToken)
	if err != nil {
		return nil, fmt.Errorf("runtime listener: %w", err)
	}

	ln, err := proto.Listen(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("variant listen %s: %w", listenAddr, err)
	}

	log.Printf("UQSP runtime listener started: variant=%s addr=%s (%s)",
		VariantName(variant), listenAddr, VariantDescription(variant))

	return &RuntimeListener{
		proto:     proto,
		variant:   variant,
		smuxCfg:   smuxCfg,
		shaperCfg: mux.ShaperConfig{
			Enabled:         cfg.Mux.Shaper.Enabled,
			MaxControlBurst: cfg.Mux.Shaper.MaxControlBurst,
			QueueSize:       cfg.Mux.Shaper.QueueSize,
		},
		authToken: authToken,
		ln:        ln,
		closed:    make(chan struct{}),
	}, nil
}

// Accept implements transport.Listener.  Each accepted net.Conn goes through
// guard verification and smux server setup to produce a transport.Session.
// Guard and session setup failures are logged and retried so that probes or
// malformed connections don't break the accept loop.
func (rl *RuntimeListener) Accept() (transport.Session, error) {
	for {
		conn, err := rl.ln.Accept()
		if err != nil {
			return nil, err
		}

		// Guard verification
		if rl.authToken != "" {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if err := transport.RecvGuard(conn, rl.authToken); err != nil {
				_ = conn.Close()
				log.Printf("runtime listener: guard verify failed from %v: %v", conn.RemoteAddr(), err)
				continue
			}
			_ = conn.SetDeadline(time.Time{})
		}

		rs, err := NewRuntimeSession(conn, rl.smuxCfg, rl.shaperCfg, rl.variant, true)
		if err != nil {
			_ = conn.Close()
			log.Printf("runtime listener: session setup failed: %v", err)
			continue
		}

		return rs.Session(), nil
	}
}

// Close closes the listener and stops accepting connections.
func (rl *RuntimeListener) Close() error {
	var err error
	rl.closeOnce.Do(func() {
		close(rl.closed)
		if rl.ln != nil {
			err = rl.ln.Close()
		}
		if rl.proto != nil {
			if e := rl.proto.Close(); err == nil {
				err = e
			}
		}
	})
	return err
}

// Addr returns the listener's network address.
func (rl *RuntimeListener) Addr() net.Addr {
	if rl.ln != nil {
		return rl.ln.Addr()
	}
	return nil
}

// Proto returns the underlying UnifiedProtocol.
func (rl *RuntimeListener) Proto() *UnifiedProtocol { return rl.proto }

// Variant returns which variant was detected and compiled.
func (rl *RuntimeListener) Variant() ProtocolVariant { return rl.variant }
