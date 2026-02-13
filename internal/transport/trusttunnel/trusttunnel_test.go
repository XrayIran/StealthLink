package trusttunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

func TestTTStreamWriteUsesTxChannel(t *testing.T) {
	tunnel := &TrustTunnel{streams: map[uint32]*ttStream{}}
	stream := &ttStream{
		id:      1,
		tunnel:  tunnel,
		txCh:    make(chan []byte, 1),
		rxCh:    make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}

	payload := []byte("hello")
	if n, err := stream.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write() n=%d err=%v", n, err)
	}

	select {
	case got := <-stream.txCh:
		if !bytes.Equal(got, payload) {
			t.Fatalf("tx payload mismatch: got=%q want=%q", got, payload)
		}
	default:
		t.Fatalf("expected payload on tx channel")
	}

	select {
	case <-stream.rxCh:
		t.Fatalf("unexpected payload on rx channel")
	default:
	}
}

func TestGetRequestBodyAndReadResponseFraming(t *testing.T) {
	tunnel := &TrustTunnel{
		config: &Config{
			PaddingMin: 2,
			PaddingMax: 2,
		},
		streams: make(map[uint32]*ttStream),
		closeCh: make(chan struct{}),
	}
	stream := &ttStream{
		id:      42,
		tunnel:  tunnel,
		txCh:    make(chan []byte, 1),
		rxCh:    make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	tunnel.streams[stream.id] = stream

	bodyReader := tunnel.getRequestBody(stream)

	want := []byte("payload")
	stream.txCh <- want

	frame := make([]byte, 7+len(want)+2)
	if _, err := io.ReadFull(bodyReader, frame); err != nil {
		t.Fatalf("read frame: %v", err)
	}

	if frame[0] != 0x01 {
		t.Fatalf("unexpected frame type: %d", frame[0])
	}
	if got := int(binary.BigEndian.Uint32(frame[1:5])); got != len(want) {
		t.Fatalf("unexpected payload len: %d", got)
	}
	if gotPad := int(binary.BigEndian.Uint16(frame[5:7])); gotPad != 2 {
		t.Fatalf("unexpected pad len: %d", gotPad)
	}
	if gotPayload := frame[7 : 7+len(want)]; !bytes.Equal(gotPayload, want) {
		t.Fatalf("unexpected payload: got=%q want=%q", gotPayload, want)
	}

	_ = stream.Close()

	// Feed a framed response and ensure payload is delivered to rx channel.
	respFrame := make([]byte, 7+len(want)+2)
	respFrame[0] = 0x01
	binary.BigEndian.PutUint32(respFrame[1:5], uint32(len(want)))
	binary.BigEndian.PutUint16(respFrame[5:7], 2)
	copy(respFrame[7:], want)

	stream2 := &ttStream{
		id:      43,
		tunnel:  tunnel,
		txCh:    make(chan []byte, 1),
		rxCh:    make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	tunnel.streams[stream2.id] = stream2
	rc := io.NopCloser(bytes.NewReader(respFrame))

	done := make(chan struct{})
	go func() {
		tunnel.readResponse(stream2, rc)
		close(done)
	}()

	select {
	case got := <-stream2.rxCh:
		if !bytes.Equal(got, want) {
			t.Fatalf("rx payload mismatch: got=%q want=%q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for rx payload")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("readResponse did not finish")
	}
}

func TestGeneratePaddingRange(t *testing.T) {
	tunnel := &TrustTunnel{
		config: &Config{
			PaddingMin: 3,
			PaddingMax: 7,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			p := tunnel.generatePadding()
			if p < 3 || p > 7 {
				t.Fatalf("padding out of range: %d", p)
			}
		}
	}
}
