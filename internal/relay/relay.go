package relay

import (
	"io"
	"sync"

	"stealthlink/internal/metrics"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

func Pipe(a io.ReadWriter, b io.ReadWriter) error {
	return PipeCounted(a, b, nil, nil)
}

// PipeCounted relays traffic in both directions and reports copied bytes.
func PipeCounted(a io.ReadWriter, b io.ReadWriter, aToB func(int64), bToA func(int64)) error {
	errCh := make(chan error, 2)
	go func() {
		errCh <- copyBufferCounted(a, b, bToA)
	}()
	go func() {
		errCh <- copyBufferCounted(b, a, aToB)
	}()
	err := <-errCh
	return err
}

func copyBufferCounted(dst io.Writer, src io.Reader, onBytes func(int64)) error {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	buf := *bufp
	n, err := io.CopyBuffer(dst, src, buf)
	if onBytes != nil {
		onBytes(n)
	} else {
		metrics.AddTraffic(n)
	}
	return err
}
