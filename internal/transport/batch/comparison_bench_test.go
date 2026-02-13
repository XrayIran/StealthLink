//go:build linux
// +build linux

package batch

import (
	"net"
	"testing"
)

func BenchmarkSendBatchComparison(b *testing.B) {
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	defer conn1.Close()

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	defer conn2.Close()

	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	msgs := make([][]byte, 32)
	addrs := make([]*net.UDPAddr, 32)
	for i := range msgs {
		msgs[i] = make([]byte, 1400)
		addrs[i] = actualAddr
	}

	b.Run("BatchEnabled", func(b *testing.B) {
		config := DefaultBatchConfig()
		config.Enabled = true
		config.BatchSize = 32
		mgr := NewBatchIOManager(config)
		b.ResetTimer()
		b.SetBytes(1400 * 32)
		for i := 0; i < b.N; i++ {
			mgr.SendBatchAddr(conn1, msgs, addrs)
		}
	})

	b.Run("BatchDisabled", func(b *testing.B) {
		b.ResetTimer()
		b.SetBytes(1400 * 32)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 32; j++ {
				conn1.WriteToUDP(msgs[j], addrs[j])
			}
		}
	})
}

func BenchmarkRecvBatchComparison(b *testing.B) {
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	defer conn1.Close()

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	defer conn2.Close()

	actualAddr := conn2.LocalAddr().(*net.UDPAddr)
	buffers := make([][]byte, 32)
	for i := range buffers {
		buffers[i] = make([]byte, 1500)
	}

	b.Run("BatchEnabled", func(b *testing.B) {
		config := DefaultBatchConfig()
		config.Enabled = true
		config.BatchSize = 32
		mgr := NewBatchIOManager(config)
		b.ResetTimer()
		b.SetBytes(1400 * 32)
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			for j := 0; j < 32; j++ {
				conn1.WriteToUDP(make([]byte, 1400), actualAddr)
			}
			b.StartTimer()
			mgr.RecvBatch(conn2, buffers)
		}
	})

	b.Run("BatchDisabled", func(b *testing.B) {
		b.ResetTimer()
		b.SetBytes(1400 * 32)
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			for j := 0; j < 32; j++ {
				conn1.WriteToUDP(make([]byte, 1400), actualAddr)
			}
			b.StartTimer()
			for j := 0; j < 32; j++ {
				conn2.ReadFromUDP(buffers[j])
			}
		}
	})
}

func BenchmarkSendBatchComparison_B64(b *testing.B) {
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	defer conn1.Close()

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	defer conn2.Close()

	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	msgs := make([][]byte, 64)
	addrs := make([]*net.UDPAddr, 64)
	for i := range msgs {
		msgs[i] = make([]byte, 1400)
		addrs[i] = actualAddr
	}

	b.Run("BatchEnabled", func(b *testing.B) {
		config := DefaultBatchConfig()
		config.Enabled = true
		config.BatchSize = 64
		mgr := NewBatchIOManager(config)
		b.ResetTimer()
		b.SetBytes(1400 * 64)
		for i := 0; i < b.N; i++ {
			mgr.SendBatchAddr(conn1, msgs, addrs)
		}
	})

	b.Run("BatchDisabled", func(b *testing.B) {
		b.ResetTimer()
		b.SetBytes(1400 * 64)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 64; j++ {
				conn1.WriteToUDP(msgs[j], addrs[j])
			}
		}
	})
}

func BenchmarkRecvBatchComparison_B64(b *testing.B) {
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	defer conn1.Close()

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	defer conn2.Close()

	actualAddr := conn2.LocalAddr().(*net.UDPAddr)
	buffers := make([][]byte, 64)
	for i := range buffers {
		buffers[i] = make([]byte, 1500)
	}

	b.Run("BatchEnabled", func(b *testing.B) {
		config := DefaultBatchConfig()
		config.Enabled = true
		config.BatchSize = 64
		mgr := NewBatchIOManager(config)
		b.ResetTimer()
		b.SetBytes(1400 * 64)
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			for j := 0; j < 64; j++ {
				conn1.WriteToUDP(make([]byte, 1400), actualAddr)
			}
			b.StartTimer()
			mgr.RecvBatch(conn2, buffers)
		}
	})

	b.Run("BatchDisabled", func(b *testing.B) {
		b.ResetTimer()
		b.SetBytes(1400 * 64)
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			for j := 0; j < 64; j++ {
				conn1.WriteToUDP(make([]byte, 1400), actualAddr)
			}
			b.StartTimer()
			for j := 0; j < 64; j++ {
				conn2.ReadFromUDP(buffers[j])
			}
		}
	})
}

func BenchmarkSendBatchComparison_1K(b *testing.B) {
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	defer conn1.Close()

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	defer conn2.Close()

	actualAddr := conn2.LocalAddr().(*net.UDPAddr)

	msgs := make([][]byte, 32)
	addrs := make([]*net.UDPAddr, 32)
	for i := range msgs {
		msgs[i] = make([]byte, 1024)
		addrs[i] = actualAddr
	}

	b.Run("BatchEnabled", func(b *testing.B) {
		config := DefaultBatchConfig()
		config.Enabled = true
		config.BatchSize = 32
		mgr := NewBatchIOManager(config)
		b.ResetTimer()
		b.SetBytes(1024 * 32)
		for i := 0; i < b.N; i++ {
			mgr.SendBatchAddr(conn1, msgs, addrs)
		}
	})

	b.Run("BatchDisabled", func(b *testing.B) {
		b.ResetTimer()
		b.SetBytes(1024 * 32)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 32; j++ {
				conn1.WriteToUDP(msgs[j], addrs[j])
			}
		}
	})
}

func BenchmarkRecvBatchComparison_1K(b *testing.B) {
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	defer conn1.Close()

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	defer conn2.Close()

	actualAddr := conn2.LocalAddr().(*net.UDPAddr)
	buffers := make([][]byte, 32)
	for i := range buffers {
		buffers[i] = make([]byte, 1500)
	}

	b.Run("BatchEnabled", func(b *testing.B) {
		config := DefaultBatchConfig()
		config.Enabled = true
		config.BatchSize = 32
		mgr := NewBatchIOManager(config)
		b.ResetTimer()
		b.SetBytes(1024 * 32)
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			for j := 0; j < 32; j++ {
				conn1.WriteToUDP(make([]byte, 1024), actualAddr)
			}
			b.StartTimer()
			mgr.RecvBatch(conn2, buffers)
		}
	})

	b.Run("BatchDisabled", func(b *testing.B) {
		b.ResetTimer()
		b.SetBytes(1024 * 32)
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			for j := 0; j < 32; j++ {
				conn1.WriteToUDP(make([]byte, 1024), actualAddr)
			}
			b.StartTimer()
			for j := 0; j < 32; j++ {
				conn2.ReadFromUDP(buffers[j])
			}
		}
	})
}
