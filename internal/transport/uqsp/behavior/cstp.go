package behavior

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
)

const (
	cstpFrameData byte = iota
	cstpFrameDPDPing
	cstpFrameDPDPong
	cstpFrameMeta
)

type CSTPOverlay struct {
	EnabledField     bool
	DPDInterval      time.Duration
	MTU              int
	EnableSplitTunn  bool
	SplitIncludeCIDR []string
	SplitExcludeCIDR []string
}

func NewCSTPOverlay(cfg config.CSTPBehaviorConfig) *CSTPOverlay {
	return &CSTPOverlay{
		EnabledField:     cfg.Enabled,
		DPDInterval:      cfg.DPDInterval,
		MTU:              cfg.MTU,
		EnableSplitTunn:  cfg.EnableSplitTunn,
		SplitIncludeCIDR: append([]string(nil), cfg.SplitInclude...),
		SplitExcludeCIDR: append([]string(nil), cfg.SplitExclude...),
	}
}

func (o *CSTPOverlay) Name() string  { return "cstp" }
func (o *CSTPOverlay) Enabled() bool { return o.EnabledField }
func (o *CSTPOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}

	out := &cstpConn{
		Conn: conn,
		mtu:  o.MTU,
		stop: make(chan struct{}),
	}
	if out.mtu <= 0 {
		out.mtu = 1300
	}

	meta := map[string]any{
		"mtu":          out.mtu,
		"split_enable": o.EnableSplitTunn,
		"split_inc":    o.SplitIncludeCIDR,
		"split_exc":    o.SplitExcludeCIDR,
	}
	if raw, err := json.Marshal(meta); err == nil {
		go func() {
			_ = out.writeFrame(cstpFrameMeta, raw)
		}()
	}

	if o.DPDInterval > 0 {
		go out.dpdLoop(o.DPDInterval)
	}

	return out, nil
}

type cstpConn struct {
	net.Conn
	mtu   int
	read  []byte
	wmu   sync.Mutex
	cmu   sync.Mutex
	stop  chan struct{}
	close bool
}

func (c *cstpConn) Read(p []byte) (int, error) {
	if len(c.read) > 0 {
		n := copy(p, c.read)
		c.read = c.read[n:]
		return n, nil
	}

	for {
		ft, payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch ft {
		case cstpFrameData:
			n := copy(p, payload)
			if n < len(payload) {
				c.read = append(c.read, payload[n:]...)
			}
			return n, nil
		case cstpFrameDPDPing:
			_ = c.writeFrame(cstpFrameDPDPong, payload)
		case cstpFrameDPDPong:
			// keepalive ack
		case cstpFrameMeta:
			// peer metadata is optional and advisory only.
		default:
			return 0, fmt.Errorf("unknown CSTP frame type: %d", ft)
		}
	}
}

func (c *cstpConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := len(p)
		if chunk > c.mtu {
			chunk = c.mtu
		}
		if err := c.writeFrame(cstpFrameData, p[:chunk]); err != nil {
			return written, err
		}
		written += chunk
		p = p[chunk:]
	}
	return written, nil
}

func (c *cstpConn) Close() error {
	c.cmu.Lock()
	if c.close {
		c.cmu.Unlock()
		return nil
	}
	c.close = true
	close(c.stop)
	c.cmu.Unlock()
	return c.Conn.Close()
}

func (c *cstpConn) writeFrame(ft byte, payload []byte) error {
	if len(payload) > 0xFFFF {
		return fmt.Errorf("CSTP payload too large: %d", len(payload))
	}
	frame := make([]byte, 3+len(payload))
	frame[0] = ft
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(payload)))
	copy(frame[3:], payload)

	c.wmu.Lock()
	defer c.wmu.Unlock()
	// Check if connection is closed before writing
	select {
	case <-c.stop:
		return fmt.Errorf("cstp: connection closed")
	default:
	}
	if c.Conn == nil {
		return fmt.Errorf("cstp: underlying connection is nil")
	}
	_, err := c.Conn.Write(frame)
	return err
}

func (c *cstpConn) readFrame() (byte, []byte, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, nil, err
	}
	size := int(binary.BigEndian.Uint16(header[1:3]))
	payload := make([]byte, size)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}

func (c *cstpConn) dpdLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			payload := binary.BigEndian.AppendUint64(nil, uint64(time.Now().UnixNano()))
			_ = c.writeFrame(cstpFrameDPDPing, payload)
		}
	}
}
