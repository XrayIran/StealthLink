//go:build linux

package underlay

import (
	"syscall"
)

func (d *WARPDialer) socketControl(network, address string, c syscall.RawConn) error {
	if d.config.RoutingPolicy != "socket_mark" {
		return nil
	}

	var ctrlErr error
	err := c.Control(func(fd uintptr) {
		ctrlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, d.config.Mark)
	})
	if err != nil {
		return err
	}
	if ctrlErr != nil {
		return ctrlErr
	}
	return nil
}
