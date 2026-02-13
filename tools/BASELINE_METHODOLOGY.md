# Baseline Metrics Methodology

**Date**: 2025-02-11  
**Spec**: upstream-integration-completion  
**Phase**: 0.2 - Establish baseline metrics

## Overview

This document describes the methodology for establishing baseline performance metrics for the StealthLink project. These baselines will be used to measure the impact of upstream integration features in subsequent phases.

## Test Environment

### Hardware
- **CPU**: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz (12 cores)
- **Memory**: 31.7 GB
- **NIC**: wlp59s0 (wireless adapter)
- **MTU**: 1500 bytes
- **UDP Buffers**: rmem_max=212992, wmem_max=212992

### Software
- **OS**: Linux 6.17.0-12-generic
- **Architecture**: amd64
- **Go Version**: 1.22+
- **Kernel Features**: sendmmsg (≥3.0), recvmmsg (≥2.6.33) - both available

### Notes
- This is a development laptop environment, not a production VPS
- Wireless NIC may introduce variability in network measurements
- For production benchmarks, use dedicated VPS with 10GbE NIC as specified in requirements

## Test Suite Baseline (Task 0.2a)

### Methodology
```bash
go test ./... -count=1
```

### Results
- **Total Packages**: 89
- **Packages with Tests**: 32
- **Packages without Tests**: 57
- **Failed Packages**: 0
- **Pass Rate**: 100%

### Interpretation
- All existing tests pass successfully
- 57 packages have no tests yet (expected for Phase 0)
- This establishes a clean baseline before implementing new features

## Go Benchmarks (Task 0.2b - Partial)

### Methodology
```bash
go test -bench=. -benchmem -run=^$ ./internal/transport/uqsp/... ./internal/transport/udprelay/...
```

### Results

#### UQSP Package
1. **MorphingOverlayWriteRead**
   - 3,022 ns/op
   - 2,308 B/op
   - 3 allocs/op
   - 365,836 iterations

2. **DatagramFragmentReassemble**
   - 5,010 ns/op
   - 16,496 B/op
   - 17 allocs/op
   - 210,864 iterations

#### UDP Relay Package
1. **PacketEncode**
   - 201.1 ns/op
   - 1,024 B/op
   - 1 allocs/op
   - 5,708,001 iterations

2. **PacketDecode**
   - 56.02 ns/op
   - 72 B/op
   - 2 allocs/op
   - 18,902,954 iterations

3. **ReplayWindow**
   - 29.15 ns/op
   - 0 B/op
   - 0 allocs/op
   - 38,424,328 iterations

### Interpretation
- These benchmarks establish baseline performance for core transport operations
- Low allocation counts indicate efficient memory usage
- High iteration counts demonstrate stable measurements

## Network Performance Benchmarks (Task 0.2b - Not Yet Measured)

### Planned Methodology

#### Throughput (Mbps)
```bash
iperf3 -c <server> -J -t 60 -P 32
```
- 32 parallel streams
- 60-second duration
- JSON output for parsing

#### Packet Per Second (PPS)
```bash
iperf3 -c <server> -u -b 0 -l 1400 -t 60
```
- UDP mode with 1400-byte packets
- Maximum bandwidth
- Count packets/second

#### Latency (P50/P95/P99)
```bash
# Use custom latency measurement tool or netperf
netperf -H <server> -t TCP_RR -l 60 -- -o P50_LATENCY,P95_LATENCY,P99_LATENCY
```

#### CPU Usage
```bash
# During benchmark, measure with:
top -b -n 60 -d 1 | grep stealthlink
# Or use perf:
perf stat -e cycles,instructions,cache-misses ./stealthlink-gateway
```

#### Syscall Count
```bash
strace -c -f ./stealthlink-gateway
# Or use perf:
perf stat -e 'syscalls:*' ./stealthlink-gateway
```

### Current Status
- **Not measured yet** - requires iperf3 server setup
- Placeholder values in baseline_metrics.json:
  - tcp_mbps: 800.0
  - udp_mbps: 600.0
  - latency_p50_ms: 1.0
  - latency_p95_ms: 2.5
  - latency_p99_ms: 5.0

### Next Steps
1. Set up iperf3 server on test VPS
2. Run throughput benchmarks (TCP/UDP)
3. Run latency benchmarks with netperf or custom tool
4. Measure CPU usage during sustained load
5. Count syscalls during benchmark runs
6. Update baseline_metrics.json with real measurements

## Performance Targets (From Requirements)

These targets are from Requirement 13 and will be measured after implementing features:

### Batch I/O (Phase 1)
- **Target**: ≥2× throughput improvement at >10,000 PPS
- **Baseline**: Single-packet I/O
- **Measurement**: iperf3 with 1400-byte packets

### Hardware Entropy (Phase 7)
- **Target**: ≥50% CPU reduction for nonce generation
- **Baseline**: crypto/rand
- **Measurement**: CPU profiling samples in entropy function

### FEC Parity Skip (Phase 8)
- **Target**: ≥10% bandwidth reduction on bursty traffic
- **Baseline**: Always generate parity
- **Measurement**: Bytes transmitted with >500ms gaps

### Adaptive Pool (Phase 12)
- **Target**: ≥20% latency reduction at >80% utilization
- **Baseline**: Static pool size
- **Measurement**: Dial start to first byte sent

### Smux Priority (Phase 9)
- **Target**: ≥30% control frame latency reduction at >100 Mbps
- **Baseline**: FIFO scheduling
- **Measurement**: Frame enqueue to transmission

## Syscall Support Verification

### sendmmsg
- **Available**: Yes (kernel ≥3.0)
- **Current Kernel**: 6.17.0-12-generic ✓

### recvmmsg
- **Available**: Yes (kernel ≥2.6.33)
- **Current Kernel**: 6.17.0-12-generic ✓

## Limitations and Caveats

1. **Development Environment**: Measurements taken on laptop, not production VPS
2. **Wireless NIC**: May introduce variability vs. wired 10GbE
3. **Network Benchmarks**: Not yet measured - require server setup
4. **Single Machine**: Cannot measure end-to-end tunnel performance yet
5. **No Load**: Measurements under idle conditions, not production load

## Recommendations for Production Baseline

For accurate production baselines, use:
- **Hardware**: Intel Xeon E5-2680v4 (2.4GHz), 32GB RAM
- **NIC**: Intel X710 10GbE
- **Kernel**: Linux 5.15+ or 6.x
- **Network**: Dedicated test network with iperf3 server
- **Duration**: 60-second benchmarks for stability
- **Samples**: 10,000+ for latency percentiles

## References

- Requirements Document: Requirement 13 (Performance Targets)
- Design Document: Section on performance measurement
- iperf3 documentation: https://iperf.fr/
- netperf documentation: https://hewlettpackard.github.io/netperf/
- Linux kernel sendmmsg(2): man 2 sendmmsg
- Linux kernel recvmmsg(2): man 2 recvmmsg
