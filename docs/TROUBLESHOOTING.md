# StealthLink Troubleshooting Guide

This guide helps diagnose and resolve common issues with StealthLink.

## Quick Diagnostics

### Check Service Status
```bash
sudo systemctl status stealthlink-gateway  # or stealthlink-agent
```

### View Logs
```bash
sudo journalctl -u stealthlink-gateway -f  # Follow logs
sudo journalctl -u stealthlink-gateway --since "1 hour ago"
```

### Check Metrics
```bash
curl http://localhost:8080/metrics/prom  # Prometheus format
curl http://localhost:8080/metrics       # JSON format
```

## Common Issues

### Issue: Batch I/O Not Working

**Symptoms:**
- Low throughput on UDP-based transports (Mode 4b, 4d)
- `stealthlink_udp_batch_fallback_total` counter increasing

**Diagnosis:**
```bash
# Check kernel version (needs Linux 3.0+ for sendmmsg)
uname -r

# Check metrics for fallback reason
curl -s http://localhost:8080/metrics/prom | grep batch_fallback
```

**Resolution:**
- Ensure Linux kernel >= 3.0
- Check for ENOSYS/EINVAL errors in logs
- Verify `udp_batch_enabled: true` in config
- If running in a container, ensure syscalls are not blocked

### Issue: AEAD Authentication Failures

**Symptoms:**
- `stealthlink_faketcp_aead_auth_failures_total` increasing
- Connection drops or data corruption in Mode 4b

**Diagnosis:**
```bash
# Check for auth failures
curl -s http://localhost:8080/metrics/prom | grep aead_auth_failures

# Verify crypto keys match on both sides
grep crypto_key /etc/stealthlink/config.yaml
```

**Resolution:**
- Ensure `crypto_key` matches on gateway and agent
- Verify `aead_mode` is the same on both sides
- Check for packet corruption in network path

### Issue: Connection Pool Not Scaling

**Symptoms:**
- High connection latency under load
- `stealthlink_pool_utilization` consistently > 80%

**Diagnosis:**
```bash
# Check current pool size and utilization
curl -s http://localhost:8080/metrics/prom | grep -E "pool_size|pool_utilization"

# Check for adjustments
curl -s http://localhost:8080/metrics/prom | grep pool_adjustments
```

**Resolution:**
- Increase `max_size` in pool configuration
- Check if `cooldown_secs` is preventing adjustments
- Verify `mode: aggressive` for faster scaling

### Issue: Xmux Rotation Not Occurring

**Symptoms:**
- Long-lived connections never rotate
- `stealthlink_xmux_connection_rotations_total` not increasing

**Diagnosis:**
```bash
# Check Xmux configuration
grep -A 10 xmux /etc/stealthlink/config.yaml

# Check rotation metrics
curl -s http://localhost:8080/metrics/prom | grep xmux
```

**Resolution:**
- Verify `xmux.enabled: true`
- Check that limits (`reuse_limit`, `request_limit`, `max_reusable_secs`) are configured
- Ensure `drain_timeout` is not zero

### Issue: REALITY Spider Timeout

**Symptoms:**
- Mode 4c connections timing out during establishment
- Long connection times (>10 seconds)

**Diagnosis:**
```bash
# Check spider duration histogram
curl -s http://localhost:8080/metrics/prom | grep spider_duration

# Check if spider fetches are occurring
curl -s http://localhost:8080/metrics/prom | grep spider_fetches
```

**Resolution:**
- Increase `spider_timeout` (default: 10s)
- Reduce `spider_concurrency` if hitting rate limits
- Verify `spider_x` URL is accessible
- Check if target domain blocks crawlers

### Issue: KCP FEC Not Adapting

**Symptoms:**
- High bandwidth usage on bursty traffic
- `stealthlink_kcp_fec_auto_tune_adjustments_total` not increasing

**Diagnosis:**
```bash
# Check FEC metrics
curl -s http://localhost:8080/metrics/prom | grep kcp_fec

# Check current shard configuration
curl -s http://localhost:8080/metrics/prom | grep -E "fec_data_shards|fec_parity_shards"
```

**Resolution:**
- Enable `fec.auto_tune: true`
- Verify `fec.parity_skip: true` for bursty traffic
- Check that loss rate is within detectable range (>1%)

### Issue: Smux Priority Shaper Starvation

**Symptoms:**
- Control frames (SYN/FIN) delayed during heavy transfers
- `stealthlink_smux_shaper_starvation_preventions_total` increasing rapidly

**Diagnosis:**
```bash
# Check shaper metrics
curl -s http://localhost:8080/metrics/prom | grep smux_shaper

# Check queue size
curl -s http://localhost:8080/metrics/prom | grep shaper_queue_size
```

**Resolution:**
- Increase `max_control_burst` to allow more control frames
- Check if `queue_size` is too small
- Verify shaper is enabled: `priority_shaper: true`

### Issue: Hardware Entropy Not Used

**Symptoms:**
- High CPU usage during crypto operations
- `stealthlink_entropy_method` shows `crypto-rand` instead of `aes-ni` or `chacha8`

**Diagnosis:**
```bash
# Check entropy method
curl -s http://localhost:8080/metrics/prom | grep entropy_method

# Check CPU features
cat /proc/cpuinfo | grep -E "flags|aes"
```

**Resolution:**
- Verify CPU supports AES-NI (`flags` contains `aes`)
- Ensure Go version >= 1.22 for ChaCha8Rand fallback
- Check `entropy.accelerated: true` in config

### Issue: WARP Underlay Not Working

**Symptoms:**
- Traffic not routing through Cloudflare WARP
- Egress IP not showing as Cloudflare IP

**Diagnosis:**
```bash
# Check WARP status
curl -s http://localhost:8080/metrics/prom | grep warp_health

# Verify WARP is configured
grep -A 10 warp /etc/stealthlink/config.yaml
```

**Resolution:**
- Ensure WARP daemon is installed and running
- Verify `warp.enabled: true`
- Check `endpoint` is reachable
- Try `mode: wgquick` if `builtin` fails

## Debug Mode

Enable debug logging for detailed diagnostics:

```yaml
# In config.yaml
logging:
  level: debug
  output: /var/log/stealthlink/debug.log
```

### Packet Capture

For Mode 4b (FakeTCP) issues:
```bash
sudo tcpdump -i eth0 -w /tmp/stealthlink.pcap 'tcp port 443'
# Analyze with Wireshark
```

### CPU Profiling

```bash
# Enable pprof
curl http://localhost:8080/debug/pprof/profile > /tmp/cpu.prof
go tool pprof /tmp/cpu.prof
```

### Memory Profiling

```bash
curl http://localhost:8080/debug/pprof/heap > /tmp/heap.prof
go tool pprof /tmp/heap.prof
```

## Performance Tuning

### Throughput Optimization

1. **Enable Batch I/O** (Mode 4b, 4d):
   ```yaml
   transport:
     udp_batch_enabled: true
     udp_batch_size: 32
   ```

2. **Tune KCP Parameters** (Mode 4d):
   ```yaml
   transport:
     uqsp:
       carrier:
         kcp:
           fec:
             auto_tune: true
             parity_skip: true
   ```

3. **Optimize Connection Pool** (All modes):
   ```yaml
   transport:
     connection_pool:
       mode: aggressive
       min_size: 4
       max_size: 64
   ```

### Latency Optimization

1. **Enable Smux Priority Shaper**:
   ```yaml
   transport:
     smux:
       priority_shaper: true
       max_control_burst: 16
   ```

2. **Tune Xmux for faster rotation**:
   ```yaml
   transport:
     xmux:
       enabled: true
       drain_timeout: 5s
   ```

## Getting Help

If issues persist:

1. Collect diagnostics:
   ```bash
   stealthlink-ctl diagnose > /tmp/stealthlink-diagnostic.log
   ```

2. Include in bug reports:
   - Config file (redact sensitive data)
   - Log excerpts
   - Metrics output
   - System info: `uname -a`, `go version`

3. Check known issues:
   - GitHub Issues: https://github.com/your-org/stealthlink/issues
   - Documentation: https://docs.stealthlink.io
