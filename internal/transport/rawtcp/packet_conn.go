package rawtcp

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync/atomic"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/metrics"
	"stealthlink/internal/transport/transportutil"
)

type packetConfig struct {
	iface              *net.Interface
	guid               string
	ipv4Addr           *net.UDPAddr
	ipv4Router         net.HardwareAddr
	ipv6Addr           *net.UDPAddr
	ipv6Router         net.HardwareAddr
	port               int
	sockbuf            int
	snaplen            int
	promisc            bool
	immediate          bool
	timeoutMs          int
	tcpLocal           []config.TCPFlags
	dscp               int
	fingerprintProfile string // TCP option mimicry profile
	bpfProfile         string // BPF filter profile: basic, strict, stealth
}

type PacketConn struct {
	cfg           *packetConfig
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	ctx    context.Context
	cancel context.CancelFunc
}

func newPacketConn(ctx context.Context, raw config.RawTCPConfig) (*PacketConn, error) {
	cfg, err := buildPacketConfig(raw)
	if err != nil {
		return nil, err
	}
	if cfg.port == 0 {
		cfg.port = 32768 + rand.Intn(32768)
	}

	sendHandle, err := NewSendHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("rawtcp send handle on %s: %v", cfg.iface.Name, err)
	}
	recvHandle, err := NewRecvHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("rawtcp recv handle on %s: %v", cfg.iface.Name, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	return &PacketConn{
		cfg:        cfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

func (c *PacketConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-c.ctx.Done():
		return 0, nil, c.ctx.Err()
	case <-deadline:
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}

	payload, addr, err := c.recvHandle.Read()
	if err != nil {
		return 0, nil, err
	}
	n = copy(data, payload)
	return n, addr, nil
}

func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	default:
	}

	daddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.InvalidAddrError("invalid address")
	}

	cfg := transportutil.DefaultTransientBufferConfig()
	err = transportutil.RetryWithBackoff(
		cfg,
		transportutil.IsTransientBufferError,
		func(attempt int) {
			metrics.IncRawWriteRetry()
			// Check for cancellation between retries
			select {
			case <-c.ctx.Done():
				return
			case <-deadline:
				return
			default:
			}
		},
		func() { metrics.IncRawDrop() },
		func() error {
			werr := c.sendHandle.Write(data, daddr)
			if werr != nil && transportutil.IsTransientBufferError(werr) {
				metrics.IncRawENOBUFS()
			}
			return werr
		},
	)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *PacketConn) Close() error {
	c.cancel()
	if c.sendHandle != nil {
		go c.sendHandle.Close()
	}
	if c.recvHandle != nil {
		go c.recvHandle.Close()
	}
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	if c.cfg != nil && c.cfg.ipv4Addr != nil {
		return &net.TCPAddr{
			IP:   c.cfg.ipv4Addr.IP,
			Port: c.cfg.port,
		}
	}
	if c.cfg != nil && c.cfg.ipv6Addr != nil {
		return &net.TCPAddr{
			IP:   c.cfg.ipv6Addr.IP,
			Port: c.cfg.port,
		}
	}
	return &net.TCPAddr{Port: c.cfg.port}
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetDSCP(dscp int) error {
	// DSCP is set at the IP layer via raw socket.
	// For pcap-based raw TCP, DSCP is embedded in the crafted IP header
	// by the send handle. Store the value for use in packet construction.
	if c.cfg != nil {
		c.cfg.dscp = dscp
	}
	return nil
}

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []config.TCPFlags) {
	c.sendHandle.setClientTCPF(addr, f)
}

func buildPacketConfig(raw config.RawTCPConfig) (*packetConfig, error) {
	if raw.InterfaceObj() == nil {
		return nil, fmt.Errorf("rawtcp interface not resolved")
	}
	cfg := &packetConfig{
		iface:              raw.InterfaceObj(),
		guid:               raw.GUID,
		ipv4Addr:           raw.IPv4.UDPAddr(),
		ipv6Addr:           raw.IPv6.UDPAddr(),
		port:               raw.Port(),
		sockbuf:            raw.PCAP.Sockbuf,
		snaplen:            raw.PCAP.Snaplen,
		promisc:            raw.PCAP.Promisc,
		immediate:          raw.PCAP.Immediate,
		timeoutMs:          raw.PCAP.TimeoutMs,
		tcpLocal:           raw.TCP.LocalParsed(),
		fingerprintProfile: raw.FingerprintProfile,
		bpfProfile:         raw.BPFProfile,
	}
	if raw.IPv4.UDPAddr() != nil {
		cfg.ipv4Router = raw.IPv4.Router()
	}
	if raw.IPv6.UDPAddr() != nil {
		cfg.ipv6Router = raw.IPv6.Router()
	}
	if len(cfg.tcpLocal) == 0 {
		cfg.tcpLocal = []config.TCPFlags{{PSH: true, ACK: true}}
	}
	return cfg, nil
}
