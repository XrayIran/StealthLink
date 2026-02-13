package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/netutil"
	"stealthlink/internal/tproxy"
)

// Set via -ldflags at build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "secret":
		cmdSecret(args)
	case "ping":
		cmdPing(args)
	case "iface":
		cmdIface(args)
	case "dump":
		cmdDump(args)
	case "version":
		cmdVersion()
	case "bench":
		cmdBench(args)
	case "autotune":
		cmdAutotune(args)
	case "host-optimize":
		cmdHostOptimize(args)
	case "proxy-matrix":
		cmdProxyMatrix(args)
	case "tproxy":
		cmdTProxy(args)
	case "status":
		cmdStatus(args)
	case "live-stress":
		cmdLiveStress(args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Stealthlink Diagnostic Tools

Usage: stealthlink-tools <command> [options]

Commands:
  secret [length]     Generate a cryptographically secure random key
                      Default length: 32 bytes (base64 encoded)
  ping <address>      Test connectivity to a gateway/agent
  iface               List available network interfaces
  dump <interface>    Capture and dump packets on interface
  bench <address>     Run latency/jitter benchmark against endpoint
  autotune <address>  Recommend transport/KCP tuning from benchmark
  host-optimize       Print/apply host TCP optimization profile
  proxy-matrix        Plan/apply transparent proxy mode/backend policy
  tproxy <op> ...     Setup/Cleanup transparent proxy firewall rules
  status [addr]       Query runtime status from metrics endpoint
  live-stress ...     Run deterministic stress harness (echo server/client)
  version             Show version information

Examples:
  stealthlink-tools secret
  stealthlink-tools secret 64
  stealthlink-tools ping localhost:8080
  stealthlink-tools iface
  stealthlink-tools dump eth0
  stealthlink-tools bench 1.2.3.4:8443
  stealthlink-tools autotune 1.2.3.4:8443
  stealthlink-tools host-optimize throughput
  stealthlink-tools host-optimize balanced --apply
  stealthlink-tools proxy-matrix tproxy nftables 15001 1 --apply 10.0.0.0/8 192.168.0.0/16
  stealthlink-tools host-optimize --rollback=hostopt-1700000000
  stealthlink-tools tproxy setup 15001 1 auto`)
}

func cmdLiveStress(args []string) {
	// Usage:
	//   stealthlink-tools live-stress server --tcp <ip:port> --udp <ip:port>
	//   stealthlink-tools live-stress client --tcp-target <ip:port> --udp-target <ip:port> --tcp-conns 1000 --duration 60s --payload-bytes 1024 --udp-packets 5000
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: stealthlink-tools live-stress <server|client> ...\n")
		os.Exit(1)
	}
	switch args[0] {
	case "server":
		liveStressServer(args[1:])
	case "client":
		liveStressClient(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Usage: stealthlink-tools live-stress <server|client> ...\n")
		os.Exit(1)
	}
}

func liveStressServer(args []string) {
	var tcpAddr, udpAddr string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--tcp":
			if i+1 < len(args) {
				i++
				tcpAddr = args[i]
			}
		case "--udp":
			if i+1 < len(args) {
				i++
				udpAddr = args[i]
			}
		default:
		}
	}
	if tcpAddr == "" && udpAddr == "" {
		fmt.Fprintf(os.Stderr, "Usage: stealthlink-tools live-stress server --tcp <ip:port> --udp <ip:port>\n")
		os.Exit(1)
	}

	errCh := make(chan error, 2)
	if tcpAddr != "" {
		go func() { errCh <- runStressTCPServer(tcpAddr) }()
	}
	if udpAddr != "" {
		go func() { errCh <- runStressUDPServer(udpAddr) }()
	}

	// Run until first fatal error (or until process is killed by orchestrator).
	err := <-errCh
	if err != nil {
		fmt.Fprintf(os.Stderr, "live-stress server failed: %v\n", err)
		os.Exit(2)
	}
}

func runStressTCPServer(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 64*1024)
			n, rerr := conn.Read(buf)
			if rerr != nil || n <= 0 {
				return
			}
			_, _ = conn.Write(buf[:n])
		}(c)
	}
}

func runStressUDPServer(addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	defer c.Close()
	buf := make([]byte, 64*1024)
	for {
		n, raddr, err := c.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		_, _ = c.WriteToUDP(buf[:n], raddr)
	}
}

type liveStressResult struct {
	Mode         string  `json:"mode"`
	TCPAttempted int64   `json:"tcp_attempted"`
	TCPSucceeded int64   `json:"tcp_succeeded"`
	TCPFailed    int64   `json:"tcp_failed"`
	UDPAttempted int64   `json:"udp_attempted"`
	UDPEchoed    int64   `json:"udp_echoed"`
	UDPLost      int64   `json:"udp_lost"`
	DurationSec  float64 `json:"duration_seconds"`
}

func liveStressClient(args []string) {
	var tcpTarget, udpTarget string
	tcpConns := 1000
	payloadBytes := 1024
	udpPackets := 5000
	duration := 60 * time.Second
	timeout := 10 * time.Second

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--tcp-target":
			if i+1 < len(args) {
				i++
				tcpTarget = args[i]
			}
		case "--udp-target":
			if i+1 < len(args) {
				i++
				udpTarget = args[i]
			}
		case "--tcp-conns":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil && v > 0 {
					tcpConns = v
				}
			}
		case "--payload-bytes":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil && v > 0 && v <= 64*1024 {
					payloadBytes = v
				}
			}
		case "--udp-packets":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil && v >= 0 {
					udpPackets = v
				}
			}
		case "--duration":
			if i+1 < len(args) {
				i++
				if d, err := time.ParseDuration(args[i]); err == nil && d > 0 {
					duration = d
				}
			}
		case "--timeout":
			if i+1 < len(args) {
				i++
				if d, err := time.ParseDuration(args[i]); err == nil && d > 0 {
					timeout = d
				}
			}
		default:
		}
	}

	if tcpTarget == "" && udpTarget == "" {
		fmt.Fprintf(os.Stderr, "Usage: stealthlink-tools live-stress client --tcp-target <ip:port> --udp-target <ip:port> [--tcp-conns N] [--duration 60s] [--payload-bytes 1024] [--udp-packets 5000]\n")
		os.Exit(1)
	}

	start := time.Now()
	deadline := start.Add(duration)

	res := liveStressResult{Mode: "client"}

	// TCP: dial N connections and keep them open until deadline (send 1 echo).
	if tcpTarget != "" {
		payload := make([]byte, payloadBytes)
		if _, err := rand.Read(payload); err != nil {
			// Best-effort; payload content doesn't matter.
		}
		type connOutcome struct{ ok bool }
		outcomes := make(chan connOutcome, tcpConns)
		for i := 0; i < tcpConns; i++ {
			go func() {
				res.TCPAttempted++
				d := net.Dialer{Timeout: timeout}
				c, err := d.Dial("tcp", tcpTarget)
				if err != nil {
					outcomes <- connOutcome{ok: false}
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(timeout))
				if _, err := c.Write(payload); err != nil {
					outcomes <- connOutcome{ok: false}
					return
				}
				buf := make([]byte, len(payload))
				if _, err := io.ReadFull(c, buf); err != nil {
					outcomes <- connOutcome{ok: false}
					return
				}
				outcomes <- connOutcome{ok: true}
				// Hold connection open until deadline.
				_ = c.SetDeadline(time.Time{})
				for time.Now().Before(deadline) {
					time.Sleep(250 * time.Millisecond)
				}
			}()
		}
		for i := 0; i < tcpConns; i++ {
			o := <-outcomes
			if o.ok {
				res.TCPSucceeded++
			} else {
				res.TCPFailed++
			}
		}
	}

	// UDP: send packets and count echoes.
	if udpTarget != "" && udpPackets > 0 {
		raddr, err := net.ResolveUDPAddr("udp", udpTarget)
		if err != nil {
			fmt.Fprintf(os.Stderr, "udp target invalid: %v\n", err)
			os.Exit(2)
		}
		c, err := net.ListenUDP("udp", nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "udp listen failed: %v\n", err)
			os.Exit(2)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(duration + timeout))

		payload := make([]byte, payloadBytes)
		if len(payload) < 8 {
			payload = make([]byte, 8)
		}
		for i := 0; i < udpPackets; i++ {
			// First 8 bytes: seq
			seq := uint64(i)
			payload[0] = byte(seq >> 56)
			payload[1] = byte(seq >> 48)
			payload[2] = byte(seq >> 40)
			payload[3] = byte(seq >> 32)
			payload[4] = byte(seq >> 24)
			payload[5] = byte(seq >> 16)
			payload[6] = byte(seq >> 8)
			payload[7] = byte(seq)
			res.UDPAttempted++
			_, _ = c.WriteToUDP(payload, raddr)
		}

		seen := make(map[uint64]struct{}, udpPackets)
		buf := make([]byte, 64*1024)
		for int64(len(seen)) < res.UDPAttempted {
			n, _, err := c.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if n < 8 {
				continue
			}
			seq := (uint64(buf[0]) << 56) | (uint64(buf[1]) << 48) | (uint64(buf[2]) << 40) | (uint64(buf[3]) << 32) |
				(uint64(buf[4]) << 24) | (uint64(buf[5]) << 16) | (uint64(buf[6]) << 8) | uint64(buf[7])
			seen[seq] = struct{}{}
			res.UDPEchoed = int64(len(seen))
		}
		res.UDPLost = res.UDPAttempted - res.UDPEchoed
	}

	res.DurationSec = time.Since(start).Seconds()
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
}

// cmdSecret generates a cryptographically secure random key
func cmdSecret(args []string) {
	length := 32
	if len(args) > 0 {
		if _, err := fmt.Sscanf(args[0], "%d", &length); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid length: %s\n", args[0])
			os.Exit(1)
		}
	}

	if length < 1 || length > 1024 {
		fmt.Fprintf(os.Stderr, "Length must be between 1 and 1024\n")
		os.Exit(1)
	}

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate random bytes: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Base64: %s\n", base64.StdEncoding.EncodeToString(buf))
	fmt.Printf("Hex:    %s\n", hex.EncodeToString(buf))
}

// cmdPing tests connectivity to a gateway/agent
func cmdPing(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: stealthlink-tools ping <address>\n")
		os.Exit(1)
	}

	address := args[0]
	if !strings.Contains(address, ":") {
		address = address + ":8080"
	}

	fmt.Printf("Pinging %s...\n", address)

	// Try TCP connection
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		fmt.Printf("TCP connection failed: %v\n", err)
	} else {
		elapsed := time.Since(start)
		fmt.Printf("TCP connection successful (latency: %v)\n", elapsed)
		conn.Close()
	}

	// Try UDP connection (just check if port is reachable)
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		fmt.Printf("Failed to resolve UDP address: %v\n", err)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Printf("UDP connection failed: %v\n", err)
		return
	}
	defer udpConn.Close()

	// Send a test packet
	testData := []byte("STEALTHLINK_PING")
	start = time.Now()
	_, err = udpConn.Write(testData)
	if err != nil {
		fmt.Printf("UDP write failed: %v\n", err)
		return
	}

	// Set read timeout
	udpConn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Try to read response
	buf := make([]byte, 1024)
	n, err := udpConn.Read(buf)
	elapsed := time.Since(start)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Printf("UDP: No response received (packet sent successfully, timeout after 3s)\n")
		} else {
			fmt.Printf("UDP read error: %v\n", err)
		}
	} else {
		fmt.Printf("UDP response received (latency: %v, %d bytes)\n", elapsed, n)
	}
}

// cmdIface lists available network interfaces
func cmdIface(args []string) {
	fmt.Printf("Network Interfaces (%s/%s):\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println(strings.Repeat("-", 60))

	// Get all interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list interfaces: %v\n", err)
		os.Exit(1)
	}

	for _, iface := range ifaces {
		// Get flags string
		flags := []string{}
		if iface.Flags&net.FlagUp != 0 {
			flags = append(flags, "UP")
		}
		if iface.Flags&net.FlagBroadcast != 0 {
			flags = append(flags, "BROADCAST")
		}
		if iface.Flags&net.FlagLoopback != 0 {
			flags = append(flags, "LOOPBACK")
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			flags = append(flags, "P2P")
		}
		if iface.Flags&net.FlagMulticast != 0 {
			flags = append(flags, "MULTICAST")
		}

		fmt.Printf("\nName:  %s\n", iface.Name)
		fmt.Printf("Index: %d\n", iface.Index)
		fmt.Printf("MTU:   %d\n", iface.MTU)
		fmt.Printf("Flags: %s\n", strings.Join(flags, ", "))
		fmt.Printf("MAC:   %s\n", iface.HardwareAddr)

		// Get addresses
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Printf("Addrs: (error: %v)\n", err)
			continue
		}

		if len(addrs) > 0 {
			fmt.Println("Addrs:")
			for _, addr := range addrs {
				fmt.Printf("       %s\n", addr.String())
			}
		}
	}

	// Also list pcap devices if available
	fmt.Println()
	fmt.Println("PCAP Devices:")
	fmt.Println(strings.Repeat("-", 60))
	printPCAPDevices()
}

// cmdDump captures and dumps packets on an interface
func cmdDump(args []string) {
	if err := runPCAPDump(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// cmdVersion shows version information
func cmdVersion() {
	fmt.Printf("stealthlink-tools %s (commit=%s built=%s)\n", version, commit, buildTime)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("CPUs:       %d\n", runtime.NumCPU())
}

func cmdBench(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: stealthlink-tools bench <address> [count]\n")
		os.Exit(1)
	}
	addr := args[0]
	count := 20
	if len(args) > 1 {
		if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
			count = n
		}
	}
	rtts := make([]time.Duration, 0, count)
	var fails int
	for i := 0; i < count; i++ {
		start := time.Now()
		c, err := net.DialTimeout("tcp", addr, 4*time.Second)
		if err != nil {
			fails++
			time.Sleep(100 * time.Millisecond)
			continue
		}
		_ = c.Close()
		rtts = append(rtts, time.Since(start))
		time.Sleep(100 * time.Millisecond)
	}
	if len(rtts) == 0 {
		fmt.Printf("bench failed: no successful probes (%d failures)\n", fails)
		return
	}
	min, max, avg, jitter := summarizeRTT(rtts)
	fmt.Printf("samples=%d failures=%d\n", len(rtts), fails)
	fmt.Printf("min=%v avg=%v max=%v jitter=%v\n", min, avg, max, jitter)
}

func cmdAutotune(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: stealthlink-tools autotune <address> [count]\n")
		os.Exit(1)
	}
	addr := args[0]
	count := 20
	if len(args) > 1 {
		if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
			count = n
		}
	}
	rtts := make([]time.Duration, 0, count)
	var fails int
	for i := 0; i < count; i++ {
		start := time.Now()
		c, err := net.DialTimeout("tcp", addr, 4*time.Second)
		if err != nil {
			fails++
			continue
		}
		_ = c.Close()
		rtts = append(rtts, time.Since(start))
		time.Sleep(80 * time.Millisecond)
	}
	if len(rtts) == 0 {
		fmt.Printf("autotune failed: no successful probes (%d failures)\n", fails)
		return
	}
	_, _, avg, jitter := summarizeRTT(rtts)
	fmt.Printf("# Recommended config snippet\n")
	fmt.Printf("transport:\n")
	fmt.Printf("  type: \"auto\"\n")
	fmt.Printf("  auto:\n")
	fmt.Printf("    candidates: [\"wss\", \"h2\", \"xhttp\", \"quic\", \"shadowtls\", \"reality\", \"dtls\", \"kcp\", \"rawtcp\", \"masque\"]\n")
	fmt.Printf("    probe_timeout: \"%ds\"\n", maxInt(2, int((avg+jitter)/(time.Second))+1))
	fmt.Printf("  kcp:\n")
	fmt.Printf("    mode: \"%s\"\n", recommendKCPMode(avg, jitter))
	fmt.Printf("    autotune: true\n")
	fmt.Printf("    packet_guard: true\n")
	fmt.Printf("  dtls:\n")
	fmt.Printf("    mtu: %d\n", recommendMTU(avg, jitter))
	fmt.Printf("    retransmit: %t\n", avg > 80*time.Millisecond)
	fmt.Printf("# benchmark failures=%d avg=%v jitter=%v\n", fails, avg, jitter)
}

func cmdHostOptimize(args []string) {
	profile := "balanced"
	apply := false
	rollbackToken := ""
	forceSnapshot := false
	for _, arg := range args {
		switch {
		case arg == "--apply":
			apply = true
		case arg == "--snapshot":
			forceSnapshot = true
		case strings.HasPrefix(arg, "--rollback="):
			rollbackToken = strings.TrimPrefix(arg, "--rollback=")
		case strings.HasPrefix(arg, "--profile="):
			profile = strings.TrimPrefix(arg, "--profile=")
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintf(os.Stderr, "unknown flag: %s\n", arg)
			os.Exit(1)
		default:
			profile = arg
		}
	}
	if rollbackToken != "" {
		if err := netutil.RestoreSystemTCPSnapshot(rollbackToken); err != nil {
			fmt.Fprintf(os.Stderr, "rollback failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("host optimization rollback applied from token=%s\n", rollbackToken)
		return
	}

	cfg, note, err := optimizationProfile(profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("# Host optimization profile: %s\n", profile)
	fmt.Printf("# %s\n", note)
	fmt.Printf("transport:\n")
	fmt.Printf("  tcp:\n")
	fmt.Printf("    enabled: true\n")
	fmt.Printf("    congestion_algorithm: %q\n", cfg.CongestionAlgorithm)
	fmt.Printf("    read_buffer_size: %d\n", cfg.ReadBufferSize)
	fmt.Printf("    write_buffer_size: %d\n", cfg.WriteBufferSize)
	fmt.Printf("    no_delay: %t\n", cfg.NoDelay)
	fmt.Printf("    quick_ack: %t\n", cfg.QuickAck)
	fmt.Printf("    keep_alive: %t\n", cfg.KeepAlive)
	fmt.Printf("    keep_alive_idle: %d\n", cfg.KeepAliveIdle)
	fmt.Printf("    keep_alive_interval: %d\n", cfg.KeepAliveInterval)
	fmt.Printf("    fast_open: %t\n", cfg.FastOpen)

	if algos, err := netutil.GetAvailableCongestionAlgorithms(); err == nil && len(algos) > 0 {
		fmt.Printf("# host available congestion algorithms: %s\n", strings.Join(algos, ","))
	}

	if !apply {
		if forceSnapshot {
			token, err := netutil.SnapshotSystemTCP()
			if err != nil {
				fmt.Fprintf(os.Stderr, "snapshot failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("# rollback_token: %s\n", token)
		}
		fmt.Printf("# dry-run only; pass --apply to apply system-wide sysctl changes (root required)\n")
		return
	}
	token, err := netutil.SnapshotSystemTCP()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pre-apply snapshot failed: %v\n", err)
		os.Exit(1)
	}
	if err := netutil.ApplySystemWideTCP(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to apply host optimization: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("host optimization applied (rollback_token=%s)\n", token)
}

func optimizationProfile(profile string) (config.TCPOptimizationConfig, string, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "balanced", "":
		return config.TCPOptimizationConfig{
			Enabled:             true,
			CongestionAlgorithm: "bbr",
			ReadBufferSize:      2 * 1024 * 1024,
			WriteBufferSize:     2 * 1024 * 1024,
			NoDelay:             true,
			QuickAck:            true,
			KeepAlive:           true,
			KeepAliveIdle:       20,
			KeepAliveInterval:   10,
			FastOpen:            true,
		}, "Balanced throughput and latency for mixed traffic.", nil
	case "throughput":
		return config.TCPOptimizationConfig{
			Enabled:             true,
			CongestionAlgorithm: "bbr",
			ReadBufferSize:      8 * 1024 * 1024,
			WriteBufferSize:     8 * 1024 * 1024,
			NoDelay:             false,
			QuickAck:            false,
			KeepAlive:           true,
			KeepAliveIdle:       30,
			KeepAliveInterval:   15,
			FastOpen:            true,
		}, "Optimized for sustained bulk throughput.", nil
	case "low-latency", "latency":
		return config.TCPOptimizationConfig{
			Enabled:             true,
			CongestionAlgorithm: "bbr",
			ReadBufferSize:      512 * 1024,
			WriteBufferSize:     512 * 1024,
			NoDelay:             true,
			QuickAck:            true,
			KeepAlive:           true,
			KeepAliveIdle:       10,
			KeepAliveInterval:   5,
			FastOpen:            true,
		}, "Optimized for low-latency interactive traffic.", nil
	default:
		return config.TCPOptimizationConfig{}, "", fmt.Errorf("unknown profile %q (supported: balanced, throughput, low-latency)", profile)
	}
}

func cmdTProxy(args []string) {
	if len(args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: stealthlink-tools tproxy <setup|cleanup> <listen_port> <mark> [auto|iptables|nft]\n")
		os.Exit(1)
	}
	op := args[0]
	port, err := strconv.Atoi(args[1])
	if err != nil || port <= 0 || port > 65535 {
		fmt.Fprintf(os.Stderr, "invalid listen_port: %s\n", args[1])
		os.Exit(1)
	}
	mark, err := strconv.Atoi(args[2])
	if err != nil || mark <= 0 {
		fmt.Fprintf(os.Stderr, "invalid mark: %s\n", args[2])
		os.Exit(1)
	}
	backendMode := "auto"
	if len(args) >= 4 {
		backendMode = strings.ToLower(strings.TrimSpace(args[3]))
	}
	useNFT := false
	switch backendMode {
	case "auto", "":
		useNFT = tproxy.IsNFTablesAvailable()
		if useNFT {
			backendMode = "nft"
		} else {
			backendMode = "iptables"
		}
	case "nft", "nftables":
		useNFT = true
		backendMode = "nft"
	case "iptables":
		useNFT = false
	default:
		fmt.Fprintf(os.Stderr, "invalid backend %q (expected: auto, iptables, nft)\n", backendMode)
		os.Exit(1)
	}
	backend := tproxy.NewBackend(useNFT, mark)
	switch op {
	case "setup":
		if err := backend.Setup(port); err != nil {
			fmt.Fprintf(os.Stderr, "tproxy setup failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("tproxy rules installed: port=%d mark=%d backend=%s\n", port, mark, backendMode)
	case "cleanup":
		if err := backend.Cleanup(port); err != nil {
			fmt.Fprintf(os.Stderr, "tproxy cleanup failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("tproxy rules removed: port=%d mark=%d backend=%s\n", port, mark, backendMode)
	default:
		fmt.Fprintf(os.Stderr, "unknown tproxy op: %s\n", op)
		os.Exit(1)
	}
}

func cmdProxyMatrix(args []string) {
	if len(args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: stealthlink-tools proxy-matrix <mode> <backend> <listen_port> <mark> [--apply] [whitelist_cidr...]\n")
		os.Exit(1)
	}
	mode := strings.ToLower(strings.TrimSpace(args[0]))
	backend := strings.ToLower(strings.TrimSpace(args[1]))
	port, err := strconv.Atoi(args[2])
	if err != nil || port <= 0 || port > 65535 {
		fmt.Fprintf(os.Stderr, "invalid listen_port: %s\n", args[2])
		os.Exit(1)
	}
	mark, err := strconv.Atoi(args[3])
	if err != nil || mark <= 0 {
		fmt.Fprintf(os.Stderr, "invalid mark: %s\n", args[3])
		os.Exit(1)
	}
	apply := false
	var whitelists []string
	for _, arg := range args[4:] {
		if arg == "--apply" {
			apply = true
			continue
		}
		whitelists = append(whitelists, arg)
	}
	switch mode {
	case "redirect", "tproxy", "tun_system", "tun_gvisor":
	default:
		fmt.Fprintf(os.Stderr, "invalid mode %q (expected redirect|tproxy|tun_system|tun_gvisor)\n", mode)
		os.Exit(1)
	}
	switch backend {
	case "auto", "iptables", "nft", "nftables":
	default:
		fmt.Fprintf(os.Stderr, "invalid backend %q (expected auto|iptables|nftables)\n", backend)
		os.Exit(1)
	}
	if backend == "nft" {
		backend = "nftables"
	}

	fmt.Printf("mode=%s backend=%s listen_port=%d mark=%d\n", mode, backend, port, mark)
	if len(whitelists) > 0 {
		fmt.Printf("whitelist=%s\n", strings.Join(whitelists, ","))
	}
	if !apply {
		fmt.Println("dry-run matrix; pass --apply to install rules")
		return
	}
	// redirect/tun modes currently share firewall programming with tproxy backend handler.
	useNFT := backend == "nftables" || (backend == "auto" && tproxy.IsNFTablesAvailable())
	b := tproxy.NewBackend(useNFT, mark)
	if err := b.Setup(port); err != nil {
		fmt.Fprintf(os.Stderr, "proxy-matrix apply failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("proxy-matrix applied with backend=%s\n", map[bool]string{true: "nftables", false: "iptables"}[useNFT])
}

func summarizeRTT(samples []time.Duration) (min, max, avg, jitter time.Duration) {
	min = samples[0]
	max = samples[0]
	var sum time.Duration
	for _, s := range samples {
		sum += s
		if s < min {
			min = s
		}
		if s > max {
			max = s
		}
	}
	avg = sum / time.Duration(len(samples))
	var dev time.Duration
	for _, s := range samples {
		if s > avg {
			dev += s - avg
		} else {
			dev += avg - s
		}
	}
	jitter = dev / time.Duration(len(samples))
	return
}

func recommendKCPMode(avg, jitter time.Duration) string {
	switch {
	case avg > 150*time.Millisecond || jitter > 40*time.Millisecond:
		return "fast3"
	case avg > 60*time.Millisecond || jitter > 20*time.Millisecond:
		return "fast2"
	default:
		return "fast"
	}
}

func recommendMTU(avg, jitter time.Duration) int {
	if avg > 120*time.Millisecond || jitter > 30*time.Millisecond {
		return 1250
	}
	return 1350
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func cmdStatus(args []string) {
	addr := "127.0.0.1:9090"
	useJSON := false
	timeout := 2 * time.Second

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			useJSON = true
		case "--timeout":
			if i+1 < len(args) {
				i++
				d, err := time.ParseDuration(args[i])
				if err != nil {
					fmt.Fprintf(os.Stderr, "invalid timeout: %v\n", err)
					os.Exit(1)
				}
				timeout = d
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				addr = args[i]
			}
		}
	}

	client := &http.Client{Timeout: timeout}

	if useJSON {
		resp, err := client.Get("http://" + addr + "/api/v1/status")
		if err != nil {
			fmt.Fprintf(os.Stderr, "status request failed: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		// Pretty-print JSON
		var out json.RawMessage
		if json.Unmarshal(body, &out) == nil {
			pretty, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(pretty))
		} else {
			fmt.Println(string(body))
		}
		return
	}

	// Text status
	resp, err := client.Get("http://" + addr + "/debug/status/text")
	if err != nil {
		fmt.Fprintf(os.Stderr, "status request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Print(string(body))
}
