package netutil

import (
	"net"
	"time"

	"stealthlink/internal/config"
)

// ApplyTCPRuntimeOptions applies safe per-connection TCP options that do not
// require raw file descriptor manipulation.
func ApplyTCPRuntimeOptions(conn net.Conn, cfg config.TCPOptimizationConfig) {
	if !cfg.Enabled {
		return
	}
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if cfg.NoDelay {
		_ = tc.SetNoDelay(true)
	}
	if cfg.ReadBufferSize > 0 {
		_ = tc.SetReadBuffer(cfg.ReadBufferSize)
	}
	if cfg.WriteBufferSize > 0 {
		_ = tc.SetWriteBuffer(cfg.WriteBufferSize)
	}
	if cfg.KeepAlive {
		_ = tc.SetKeepAlive(true)
		if cfg.KeepAliveIdle > 0 {
			_ = tc.SetKeepAlivePeriod(time.Duration(cfg.KeepAliveIdle) * time.Second)
		}
	}
}
