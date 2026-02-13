package behavior

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestReadTLSHandshakeMessageAcrossMultipleRecords(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	msg := buildServerHelloMessage()
	partA := msg[:12]
	partB := msg[12:]

	go func() {
		_ = writeTLSRecord(right, tlsRecordTypeHandshake, partA)
		_ = writeTLSRecord(right, tlsRecordTypeHandshake, partB)
	}()

	got, err := readTLSHandshakeMessage(left, tlsHandshakeServerHello, 4)
	if err != nil {
		t.Fatalf("readTLSHandshakeMessage: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("message mismatch got=%d want=%d", len(got), len(msg))
	}
}

func TestVerifyServerHello(t *testing.T) {
	conn := &shadowTLSConn{}
	if err := conn.verifyServerHello(buildServerHelloMessage()); err != nil {
		t.Fatalf("verifyServerHello valid: %v", err)
	}
	bad := buildServerHelloMessage()
	bad[0] = 0x03
	if err := conn.verifyServerHello(bad); err == nil {
		t.Fatal("expected verifyServerHello failure for bad handshake type")
	}
}

func TestReadTLSRecordShortRead(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	go func() {
		_ = right.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		right.Write([]byte{0x16, 0x03, 0x03}) // short header
		right.Close()
	}()

	if _, _, _, err := readTLSRecord(left); err == nil {
		t.Fatal("expected short read error")
	}
}

func buildServerHelloMessage() []byte {
	body := make([]byte, 38)
	// legacy_version
	body[0] = 0x03
	body[1] = 0x03
	// random bytes body[2:34] left zero
	// session id len
	body[34] = 0
	// cipher suite
	body[35] = 0x13
	body[36] = 0x01
	// compression method
	body[37] = 0

	msg := make([]byte, 4+len(body))
	msg[0] = tlsHandshakeServerHello
	msg[1] = 0
	msg[2] = 0
	msg[3] = byte(len(body))
	copy(msg[4:], body)
	return msg
}

func writeTLSRecord(conn net.Conn, recordType byte, payload []byte) error {
	record := make([]byte, 5+len(payload))
	record[0] = recordType
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	copy(record[5:], payload)
	_, err := conn.Write(record)
	return err
}

func TestShadowTLSConnConcurrentReadSafety(t *testing.T) {
	// Verify the mutex fix prevents data races in Read
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	conn := &shadowTLSConn{
		Conn:          left,
		handshakeDone: true, // Skip handshake for this test
	}

	// Write TLS ApplicationData records from the other side
	go func() {
		for i := 0; i < 10; i++ {
			payload := []byte("hello-world")
			record := make([]byte, 5+len(payload))
			record[0] = 0x17 // ApplicationData
			record[1] = 0x03
			record[2] = 0x03
			binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
			copy(record[5:], payload)
			right.Write(record)
		}
		right.Close()
	}()

	// Concurrent reads
	done := make(chan struct{})
	for g := 0; g < 3; g++ {
		go func() {
			buf := make([]byte, 64)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					return
				}
			}
		}()
	}

	go func() {
		time.Sleep(500 * time.Millisecond)
		close(done)
	}()
	<-done
}

func TestShadowTLSConnWriteFramesTLSRecords(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	conn := &shadowTLSConn{
		Conn:          left,
		handshakeDone: true,
	}

	payload := []byte("test-data-payload")

	go func() {
		conn.Write(payload)
		left.Close()
	}()

	// Read TLS record from the other end
	header := make([]byte, 5)
	if _, err := right.Read(header); err != nil {
		t.Fatalf("read header: %v", err)
	}

	if header[0] != 0x17 {
		t.Fatalf("expected ApplicationData (0x17), got 0x%02x", header[0])
	}

	recordLen := binary.BigEndian.Uint16(header[3:5])
	if int(recordLen) != len(payload) {
		t.Fatalf("record length %d != payload length %d", recordLen, len(payload))
	}

	data := make([]byte, recordLen)
	if _, err := right.Read(data); err != nil {
		t.Fatalf("read payload: %v", err)
	}

	if !bytes.Equal(data, payload) {
		t.Fatal("payload mismatch")
	}
}
