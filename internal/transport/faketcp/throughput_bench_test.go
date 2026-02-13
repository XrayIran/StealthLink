//go:build linux
// +build linux

package faketcp

import (
	"context"
	"io"
	"stealthlink/internal/transport/batch"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func BenchmarkFakeTCPThroughput_BatchCompare(b *testing.B) {
	runBench := func(b *testing.B, batchEnabled bool) {
		cfg := &Config{
			MTU:        1400,
			WindowSize: 1024 * 1024, // High window for throughput
			RTO:        100 * time.Millisecond,
			Batch: batch.BatchConfig{
				Enabled:   batchEnabled,
				BatchSize: 32,
			},
		}

		smuxCfg := smux.DefaultConfig()
		smuxCfg.MaxReceiveBuffer = 4 * 1024 * 1024
		smuxCfg.MaxStreamBuffer = 1024 * 1024

		ln, err := Listen("127.0.0.1:0", cfg, smuxCfg, "")
		if err != nil {
			b.Fatalf("listen failed: %v", err)
		}
		defer ln.Close()

		go func() {
			for {
				sess, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					for {
						stream, err := sess.AcceptStream()
						if err != nil {
							return
						}
						go func() {
							_, _ = io.Copy(io.Discard, stream)
							_ = stream.Close()
						}()
					}
				}()
			}
		}()

		dialer := NewDialer(cfg, smuxCfg, "")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		sess, err := dialer.Dial(ctx, ln.Addr().String())
		if err != nil {
			b.Fatalf("dial failed: %v", err)
		}
		defer sess.Close()

		data := make([]byte, 64*1024)
		b.ResetTimer()
		b.SetBytes(int64(len(data)))

		b.RunParallel(func(pb *testing.PB) {
			stream, err := sess.OpenStream()
			if err != nil {
				return
			}
			defer stream.Close()

			for pb.Next() {
				_, err := stream.Write(data)
				if err != nil {
					return
				}
			}
		})
	}

	b.Run("BatchON", func(b *testing.B) {
		runBench(b, true)
	})

	b.Run("BatchOFF", func(b *testing.B) {
		runBench(b, false)
	})
}

func BenchmarkFakeTCPThroughput_HighPPS(b *testing.B) {
	runBench := func(b *testing.B, batchEnabled bool) {
		cfg := &Config{
			MTU:        1400,
			WindowSize: 1024 * 1024,
			RTO:        100 * time.Millisecond,
			Batch: batch.BatchConfig{
				Enabled:   batchEnabled,
				BatchSize: 32,
			},
		}

		smuxCfg := smux.DefaultConfig()
		smuxCfg.MaxReceiveBuffer = 4 * 1024 * 1024
		smuxCfg.MaxStreamBuffer = 1024 * 1024

		ln, err := Listen("127.0.0.1:0", cfg, smuxCfg, "")
		if err != nil {
			b.Fatalf("listen failed: %v", err)
		}
		defer ln.Close()

		go func() {
			sess, err := ln.Accept()
			if err != nil {
				return
			}
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			io.Copy(io.Discard, stream)
		}()

		dialer := NewDialer(cfg, smuxCfg, "")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		sess, err := dialer.Dial(ctx, ln.Addr().String())
		if err != nil {
			b.Fatalf("dial failed: %v", err)
		}
		defer sess.Close()

		stream, err := sess.OpenStream()
		if err != nil {
			b.Fatalf("open stream failed: %v", err)
		}
		defer stream.Close()

		// Use small 1KB packets to stress syscall count
		data := make([]byte, 1024)
		b.ResetTimer()
		b.SetBytes(int64(len(data)))

		for i := 0; i < b.N; i++ {
			_, err := stream.Write(data)
			if err != nil {
				return
			}
		}
	}

	b.Run("BatchON", func(b *testing.B) {
		runBench(b, true)
	})

	b.Run("BatchOFF", func(b *testing.B) {
		runBench(b, false)
	})
}
