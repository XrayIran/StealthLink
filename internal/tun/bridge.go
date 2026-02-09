package tun

import (
	"context"
	"io"
	"net"
	"time"

	"stealthlink/internal/relay"
)

func Bridge(ctx context.Context, iface io.ReadWriteCloser, stream net.Conn) error {
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := iface.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if err := relay.WriteFrame(stream, buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		for {
			pkt, err := relay.ReadFrame(stream)
			if err != nil {
				errCh <- err
				return
			}
			if _, err := iface.Write(pkt); err != nil {
				errCh <- err
				return
			}
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		_ = stream.SetDeadline(time.Now())
		_ = iface.Close()
		return ctx.Err()
	}
}
