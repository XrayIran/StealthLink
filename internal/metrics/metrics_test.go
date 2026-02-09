package metrics

import "testing"

func TestTrafficCountersMonotonic(t *testing.T) {
	before := SnapshotData()
	AddTrafficInbound(100)
	AddTrafficOutbound(50)
	IncObfsJunkPackets(2)
	IncObfsSignaturePackets(1)
	after := SnapshotData()

	if after.TrafficBytesInbound < before.TrafficBytesInbound+100 {
		t.Fatalf("inbound counter did not increase as expected")
	}
	if after.TrafficBytesOutbound < before.TrafficBytesOutbound+50 {
		t.Fatalf("outbound counter did not increase as expected")
	}
	if after.ObfsJunkPacketsTotal < before.ObfsJunkPacketsTotal+2 {
		t.Fatalf("obfs junk counter did not increase as expected")
	}
	if after.ObfsSignaturePacketsTotal < before.ObfsSignaturePacketsTotal+1 {
		t.Fatalf("obfs signature counter did not increase as expected")
	}
}
