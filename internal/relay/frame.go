package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

const maxFrameSize = 64 * 1024

var framePool = sync.Pool{
	New: func() any {
		b := make([]byte, maxFrameSize)
		return &b
	},
}

func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 || n > maxFrameSize {
		return nil, fmt.Errorf("invalid frame size: %d", n)
	}
	bufp := framePool.Get().(*[]byte)
	buf := *bufp
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		framePool.Put(bufp)
		return nil, err
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	framePool.Put(bufp)
	return out, nil
}
