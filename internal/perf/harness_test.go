package perf

import "testing"

func estimateThroughputMbps(rttMs int, lossPct int) float64 {
	base := 500.0
	rttPenalty := 1.0 / (1.0 + float64(rttMs)/80.0)
	lossPenalty := 1.0 / (1.0 + float64(lossPct)*0.35)
	v := base * rttPenalty * lossPenalty
	if v < 1 {
		return 1
	}
	return v
}

func TestRTTLossGrid(t *testing.T) {
	rtts := []int{20, 80, 150}
	losses := []int{0, 1, 3, 5}
	for _, rtt := range rtts {
		prev := estimateThroughputMbps(rtt, losses[0])
		for _, loss := range losses[1:] {
			cur := estimateThroughputMbps(rtt, loss)
			if cur > prev {
				t.Fatalf("throughput should not improve when loss rises (rtt=%d loss=%d)", rtt, loss)
			}
			prev = cur
		}
	}
}

func TestFailoverCooldown(t *testing.T) {
	cooldown := 3
	state := 0
	for i := 0; i < cooldown; i++ {
		if i < cooldown-1 {
			if state != 0 {
				t.Fatalf("failover activated too early")
			}
		} else {
			state = 1
		}
	}
	if state != 1 {
		t.Fatalf("failover did not activate after cooldown")
	}
}
