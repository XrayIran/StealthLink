package mux

import (
	"net"
	"time"

	"github.com/xtaci/smux"
)

func Config(keepAliveInterval, keepAliveTimeout time.Duration, maxStreams int, maxStreamBuf, maxRecvBuf int) *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveInterval = keepAliveInterval
	cfg.KeepAliveTimeout = keepAliveTimeout
	if maxStreamBuf > 0 {
		cfg.MaxStreamBuffer = maxStreamBuf
	}
	if maxRecvBuf > 0 {
		cfg.MaxReceiveBuffer = maxRecvBuf
	}
	return cfg
}

// NewClient creates a new smux client session with optional priority shaper.
func NewClient(conn net.Conn, smuxCfg *smux.Config, shaperCfg ShaperConfig) (*smux.Session, error) {
	if shaperCfg.Enabled {
		conn = NewPriorityShaper(conn, shaperCfg)
	}
	return smux.Client(conn, smuxCfg)
}

// NewServer creates a new smux server session with optional priority shaper.
func NewServer(conn net.Conn, smuxCfg *smux.Config, shaperCfg ShaperConfig) (*smux.Session, error) {
	if shaperCfg.Enabled {
		conn = NewPriorityShaper(conn, shaperCfg)
	}
	return smux.Server(conn, smuxCfg)
}
