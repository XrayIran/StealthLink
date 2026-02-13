package carrier

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

func TestSimpleHpackEncodeProducesDecodableHeaders(t *testing.T) {
	c := &WebTunnelCarrier{}
	block := c.simpleHpackEncode(
		":method CONNECT\r\n" +
			":scheme https\r\n" +
			":authority example.com\r\n" +
			":path /tunnel\r\n" +
			"user-agent: stealthlink-test\r\n",
	)
	if len(block) == 0 {
		t.Fatal("empty HPACK block")
	}

	got := map[string]string{}
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		got[f.Name] = f.Value
	})
	if _, err := dec.Write(block); err != nil {
		t.Fatalf("decode HPACK: %v", err)
	}

	if got[":method"] != "CONNECT" {
		t.Fatalf("missing :method CONNECT, got=%q", got[":method"])
	}
	if got[":path"] != "/tunnel" {
		t.Fatalf("missing :path /tunnel, got=%q", got[":path"])
	}
	if got["user-agent"] != "stealthlink-test" {
		t.Fatalf("missing user-agent, got=%q", got["user-agent"])
	}
}

func TestDecodeStatusFromHeadersFrame(t *testing.T) {
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
		t.Fatalf("write :status: %v", err)
	}
	if err := enc.WriteField(hpack.HeaderField{Name: "server", Value: "test"}); err != nil {
		t.Fatalf("write server: %v", err)
	}

	status, err := decodeStatusFromHeadersFrame(b.Bytes(), 0)
	if err != nil {
		t.Fatalf("decodeStatusFromHeadersFrame: %v", err)
	}
	if status != "200" {
		t.Fatalf("unexpected status: %s", status)
	}
}

func TestDecodeStatusFromPaddedPriorityHeadersFrame(t *testing.T) {
	var hpackBlock bytes.Buffer
	enc := hpack.NewEncoder(&hpackBlock)
	if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
		t.Fatalf("write :status: %v", err)
	}

	padLen := byte(3)
	payload := make([]byte, 0, 1+5+hpackBlock.Len()+int(padLen))
	payload = append(payload, padLen)                // PADDED
	payload = append(payload, make([]byte, 5)...)    // PRIORITY
	payload = append(payload, hpackBlock.Bytes()...) // header block
	payload = append(payload, 0, 0, 0)               // padding

	status, err := decodeStatusFromHeadersFrame(payload, 0x08|0x20)
	if err != nil {
		t.Fatalf("decodeStatusFromHeadersFrame: %v", err)
	}
	if status != "200" {
		t.Fatalf("unexpected status: %s", status)
	}
}

func TestReadH2Frame(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	frame := make([]byte, 9+len(payload))
	frame[0] = 0
	frame[1] = 0
	frame[2] = byte(len(payload))
	frame[3] = 0x00 // DATA
	frame[4] = 0x01 // END_STREAM
	binary.BigEndian.PutUint32(frame[5:9], 0x00000001)
	copy(frame[9:], payload)

	ft, flags, sid, gotPayload, err := readH2Frame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("readH2Frame: %v", err)
	}
	if ft != 0x00 || flags != 0x01 || sid != 1 {
		t.Fatalf("unexpected frame header: type=%d flags=%d sid=%d", ft, flags, sid)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("unexpected payload: %x", gotPayload)
	}
}

func TestReadResponseHeaderBlockWithContinuation(t *testing.T) {
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
		t.Fatalf("encode status: %v", err)
	}
	if err := enc.WriteField(hpack.HeaderField{Name: "server", Value: "test"}); err != nil {
		t.Fatalf("encode server: %v", err)
	}
	block := b.Bytes()
	if len(block) < 2 {
		t.Fatalf("unexpectedly short HPACK block")
	}
	split := len(block) / 2
	first := block[:split]
	second := block[split:]

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		done <- writeH2Frame(server, 0x09, 0x04, 1, second) // CONTINUATION + END_HEADERS
	}()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	gotBlock, err := readResponseHeaderBlock(client, 1, first, 0x00)
	if err != nil {
		t.Fatalf("readResponseHeaderBlock: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("write continuation: %v", err)
	}

	status, err := decodeStatusFromHeaderBlock(gotBlock)
	if err != nil {
		t.Fatalf("decodeStatusFromHeaderBlock: %v", err)
	}
	if status != "200" {
		t.Fatalf("unexpected status=%q", status)
	}
}

func TestExtractDataPayloadPadded(t *testing.T) {
	payload := []byte{2, 'a', 'b', 'c', 0, 0}
	got, err := extractDataPayload(payload, 0x08) // PADDED
	if err != nil {
		t.Fatalf("extractDataPayload: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("unexpected data payload=%q", string(got))
	}
}
