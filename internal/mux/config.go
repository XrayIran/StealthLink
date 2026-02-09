package mux

import (
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
