package bbr

import (
	"testing"
	"time"
)

func TestMeasureNetworkReturnsSaneValues(t *testing.T) {
	tuner := NewTuner(NewManager(&Config{Enabled: true}))

	latency, throughput, loss := tuner.measureNetwork()
	if latency <= 0 {
		t.Fatalf("latency=%v want > 0", latency)
	}
	if throughput < 0 {
		t.Fatalf("throughput=%f want >= 0", throughput)
	}
	if loss < 0 || loss > 1 {
		t.Fatalf("loss=%f want in [0,1]", loss)
	}

	time.Sleep(10 * time.Millisecond)
	latency2, throughput2, loss2 := tuner.measureNetwork()
	if latency2 <= 0 {
		t.Fatalf("second latency=%v want > 0", latency2)
	}
	if throughput2 < 0 {
		t.Fatalf("second throughput=%f want >= 0", throughput2)
	}
	if loss2 < 0 || loss2 > 1 {
		t.Fatalf("second loss=%f want in [0,1]", loss2)
	}
}
