package tlsutil

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestExtractECHConfigsFromHTTPSAnswerUnknownResource(t *testing.T) {
	targetName := append([]byte{3}, []byte("svc")...)
	targetName = append(targetName, 0x00)
	echValue := []byte{0x01, 0x02, 0x03, 0x04}

	rdata := make([]byte, 0, 2+len(targetName)+4+len(echValue))
	rdata = binary.BigEndian.AppendUint16(rdata, 1) // priority
	rdata = append(rdata, targetName...)
	rdata = binary.BigEndian.AppendUint16(rdata, 5) // ech key
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(echValue)))
	rdata = append(rdata, echValue...)

	out, err := extractECHConfigsFromHTTPSAnswer(&dnsmessage.UnknownResource{Data: rdata})
	if err != nil {
		t.Fatalf("extract ECH from unknown resource: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("len(out)=%d want=1", len(out))
	}
	if !bytes.Equal(out[0], echValue) {
		t.Fatalf("ECH mismatch got=%x want=%x", out[0], echValue)
	}
}

func TestExtractECHConfigsFromHTTPSAnswerHTTPSResource(t *testing.T) {
	echValue := []byte{0xaa, 0xbb, 0xcc}
	out, err := extractECHConfigsFromHTTPSAnswer(&dnsmessage.HTTPSResource{
		SVCBResource: dnsmessage.SVCBResource{
			Priority: 1,
			Target:   dnsmessage.MustNewName("svc.example."),
			Params: []dnsmessage.SVCParam{
				{Key: 1, Value: []byte("alpn")},
				{Key: 5, Value: echValue},
			},
		},
	})
	if err != nil {
		t.Fatalf("extract ECH from HTTPS resource: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("len(out)=%d want=1", len(out))
	}
	if !bytes.Equal(out[0], echValue) {
		t.Fatalf("ECH mismatch got=%x want=%x", out[0], echValue)
	}
}

func TestNormalizeECHConfigListWrapsSingleConfig(t *testing.T) {
	cfg := []byte{0xaa, 0xbb, 0xcc}
	got := NormalizeECHConfigList(cfg)
	if len(got) != 2+2+len(cfg) {
		t.Fatalf("len(got)=%d", len(got))
	}
	listLen := int(binary.BigEndian.Uint16(got[:2]))
	if listLen != len(got)-2 {
		t.Fatalf("invalid list length=%d total=%d", listLen, len(got))
	}
	entryLen := int(binary.BigEndian.Uint16(got[2:4]))
	if entryLen != len(cfg) {
		t.Fatalf("invalid entry length=%d", entryLen)
	}
}
