//go:build !linux

package underlay

import (
	"syscall"
)

func (d *WARPDialer) socketControl(network, address string, c syscall.RawConn) error {
	return nil
}
