#!/usr/bin/env python3
"""SSH-based live validation orchestrator for StealthLink Phase 11 gates.

This tool provisions (via stealthlink-ctl install --bundle) a gateway + agent,
generates configs per mode (4a..4e) and WARP setting (off/on), runs:
- health checks and metrics assertions (underlay_selected / warp_health),
- iperf3 TCP+UDP benchmarks through the TUN interface,
- reconnect measurement,
- pprof collection from metrics listener,
- deterministic stress via stealthlink-tools live-stress.

Artifacts are written under dist/live-validation/<timestamp>/.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import pathlib
import random
import shlex
import signal
import subprocess
import sys
import time
from typing import Any

from sshutil import SSHConfig, run_ssh, scp_to, start_ssh_forward


ROOT = pathlib.Path(__file__).resolve().parents[1]


def ts() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def die(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def rand_b64(nbytes: int) -> str:
    raw = os.urandom(nbytes)
    return base64.b64encode(raw).decode("ascii")


def parse_json(stdout: str) -> dict[str, Any]:
    try:
        obj = json.loads(stdout)
    except json.JSONDecodeError:
        return {}
    return obj if isinstance(obj, dict) else {}


def ensure_rc(ok: bool, context: str, stdout: str = "", stderr: str = "") -> None:
    if ok:
        return
    msg = f"{context} failed"
    if stderr.strip():
        msg += f": {stderr.strip()}"
    if stdout.strip():
        msg += f"\nstdout:\n{stdout.strip()}"
    die(msg)


def remote_preflight(cfg: SSHConfig, host: str) -> None:
    r = run_ssh(cfg, host, "command -v systemctl >/dev/null && command -v curl >/dev/null && command -v ip >/dev/null")
    ensure_rc(r.returncode == 0, f"{host}: missing required commands (systemctl/curl/ip)", r.stdout, r.stderr)

    r = run_ssh(cfg, host, "command -v iperf3 >/dev/null")
    ensure_rc(r.returncode == 0, f"{host}: iperf3 not installed (required)", r.stdout, r.stderr)


def detect_uplink(cfg: SSHConfig, host: str) -> dict[str, str]:
    r = run_ssh(cfg, host, "ip route get 1.1.1.1")
    ensure_rc(r.returncode == 0, f"{host}: ip route get failed", r.stdout, r.stderr)
    line = r.stdout.strip().splitlines()[0] if r.stdout.strip().splitlines() else ""
    # Typical: "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 0"
    parts = line.split()
    out: dict[str, str] = {}
    for i, p in enumerate(parts):
        if p == "dev" and i + 1 < len(parts):
            out["dev"] = parts[i + 1]
        if p == "src" and i + 1 < len(parts):
            out["src"] = parts[i + 1]
        if p == "via" and i + 1 < len(parts):
            out["via"] = parts[i + 1]
    if not out.get("dev") or not out.get("src") or not out.get("via"):
        die(f"{host}: unable to parse uplink from: {line}")

    # Ensure neighbor table has gateway MAC.
    run_ssh(cfg, host, f"ping -c 1 -W 1 {shlex.quote(out['via'])} >/dev/null 2>&1 || true")
    r = run_ssh(cfg, host, f"ip neigh show {shlex.quote(out['via'])} dev {shlex.quote(out['dev'])} | head -n 1")
    ensure_rc(r.returncode == 0, f"{host}: ip neigh failed", r.stdout, r.stderr)
    neigh = r.stdout.strip()
    mac = ""
    for i, p in enumerate(neigh.split()):
        if p == "lladdr" and i + 1 < len(neigh.split()):
            mac = neigh.split()[i + 1]
            break
    if not mac:
        die(f"{host}: unable to detect router MAC from: {neigh}")
    out["router_mac"] = mac
    return out


def build_gateway_config(
    mode: str,
    gateway_port: int,
    shared_key: str,
    gw_tun_ip_cidr: str,
    agent_tun_ip: str,
    warp: str,
    warp_engine: str,
    rawtcp: dict[str, str],
) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "role": "gateway",
        "variant": mode,
        "gateway": {"listen": f"0.0.0.0:{gateway_port}"},
        "agent": {"id": "", "gateway_addr": "", "reconnect_backoff": "3s"},
        "transport": {
            "type": "uqsp",
            "dialer": "direct" if warp == "off" else "warp",
            "warp_dialer": {
                "engine": warp_engine,
                "required": (warp != "off"),
                "mode": "consumer",
                "device_id": "",
            },
            "uqsp": {
                "carrier": {"type": ""},  # variant preset fills
            },
        },
        "security": {"shared_key": shared_key},
        "metrics": {"listen": "127.0.0.1:9091", "pprof": True},
        "services": [
            {
                "name": "vpnlink",
                "protocol": "tun",
                "tun": {"name": "sl0", "mode": "tun", "mtu": 1400},
            }
        ],
        "vpn": {
            "enabled": True,
            "mode": "tun",
            "name": "sl0",
            "interface_ip": gw_tun_ip_cidr,
            "peer_ip": agent_tun_ip,
            "mtu": 1400,
            "routes": [],
            "dns": [],
        },
        "warp": {
            "enabled": (warp != "off"),
            "required": (warp != "off"),
            "mode": "builtin" if warp_engine == "builtin" else "wgquick",
            "endpoint": "engage.cloudflareclient.com:2408",
            "routing_mode": "vpn_only",
            "vpn_subnet": "10.8.0.0/24",
            "keepalive": "25s",
        },
    }

    if mode == "4b":
        cfg["transport"]["uqsp"]["carrier"] = {
            "type": "rawtcp",
            "rawtcp": {
                "raw": {
                    "interface": rawtcp["dev"],
                    "ipv4": {"addr": f"{rawtcp['src']}:{gateway_port}", "router_mac": rawtcp["router_mac"]},
                    "pcap": {"sockbuf": 8388608},
                    "tcp": {"local_flag": ["PA", "SA", "FA"], "remote_flag": ["PA", "SA", "FA"], "randomize": True, "cycle_mode": "random"},
                    "fingerprint_profile": "chrome_win10",
                    "bpf_profile": "stealth",
                },
                "kcp": {"block": "aes", "packet_guard": True, "packet_guard_magic": "PQT1", "packet_guard_window": 30, "packet_guard_skew": 1},
            },
        }

    if mode == "4c":
        # Exercise AnyTLS carrier path for TLS-lookalike mode.
        password = rand_b64(24)
        cfg["transport"]["uqsp"]["carrier"] = {
            "type": "anytls",
            "anytls": {
                # Used by the dialer; listener uses gateway.listen instead.
                "server": f"127.0.0.1:{gateway_port}",
                "password": password,
                "padding_scheme": "random",
                "padding_min": 100,
                "padding_max": 900,
                "idle_session_timeout": 300,
                "tls_insecure_skip_verify": True,
                "tls_server_name": "localhost",
            },
        }
        # Also populate behavior password mapping for compatibility.
        cfg["transport"]["uqsp"].setdefault("behaviors", {})
        cfg["transport"]["uqsp"]["behaviors"]["anytls"] = {"enabled": True, "password": password, "padding_min": 100, "padding_max": 900}

    return cfg


def build_agent_config(
    mode: str,
    gateway_host: str,
    gateway_port: int,
    shared_key: str,
    agent_tun_ip_cidr: str,
    gw_tun_ip: str,
    warp: str,
    warp_engine: str,
    rawtcp: dict[str, str],
) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "role": "agent",
        "variant": mode,
        "agent": {"id": f"agent-{mode}-{random.randint(1000,9999)}", "gateway_addr": f"{gateway_host}:{gateway_port}", "reconnect_backoff": "3s"},
        "gateway": {"listen": ""},
        "transport": {
            "type": "uqsp",
            "dialer": "direct" if warp == "off" else "warp",
            "warp_dialer": {
                "engine": warp_engine,
                "required": (warp != "off"),
                "mode": "consumer",
                "device_id": "",
            },
            "uqsp": {
                "carrier": {"type": ""},  # variant preset fills
            },
        },
        "security": {"shared_key": shared_key},
        "metrics": {"listen": "127.0.0.1:9092", "pprof": True},
        "services": [
            {
                "name": "vpnlink",
                "protocol": "tun",
                "tun": {"name": "sl0", "mode": "tun", "mtu": 1400},
            }
        ],
        "vpn": {
            "enabled": True,
            "mode": "tun",
            "name": "sl0",
            "interface_ip": agent_tun_ip_cidr,
            "peer_ip": gw_tun_ip,
            "mtu": 1400,
            "routes": [],
            "dns": [],
        },
        "warp": {
            "enabled": (warp != "off"),
            "required": (warp != "off"),
            "mode": "builtin" if warp_engine == "builtin" else "wgquick",
            "endpoint": "engage.cloudflareclient.com:2408",
            "routing_mode": "vpn_only",
            "vpn_subnet": "10.8.0.0/24",
            "keepalive": "25s",
        },
    }

    if mode == "4b":
        cfg["transport"]["uqsp"]["carrier"] = {
            "type": "rawtcp",
            "rawtcp": {
                "raw": {
                    "interface": rawtcp["dev"],
                    "ipv4": {"addr": f"{rawtcp['src']}:0", "router_mac": rawtcp["router_mac"]},
                    "pcap": {"sockbuf": 4194304},
                    "tcp": {"local_flag": ["PA", "SA", "FA"], "remote_flag": ["PA", "SA", "FA"], "randomize": True, "cycle_mode": "random"},
                    "fingerprint_profile": "chrome_win10",
                    "bpf_profile": "stealth",
                },
                "kcp": {"block": "aes", "packet_guard": True, "packet_guard_magic": "PQT1", "packet_guard_window": 30, "packet_guard_skew": 1},
            },
        }

    if mode == "4c":
        # Must match gateway password; will be injected by orchestrator when building both configs.
        pass

    return cfg


def write_local(path: pathlib.Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def fetch_metrics_json(local_port: int, timeout_sec: int = 2) -> dict[str, Any]:
    import urllib.request

    url = f"http://127.0.0.1:{local_port}/metrics"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return parse_json(raw)


def collect_pprof(local_port: int, out_dir: pathlib.Path, prefix: str, cpu_seconds: int = 60) -> dict[str, Any]:
    import urllib.request

    out_dir.mkdir(parents=True, exist_ok=True)
    cpu_path = out_dir / f"{prefix}-cpu.pb.gz"
    heap_path = out_dir / f"{prefix}-heap.pb.gz"

    cpu_url = f"http://127.0.0.1:{local_port}/debug/pprof/profile?seconds={cpu_seconds}"
    heap_url = f"http://127.0.0.1:{local_port}/debug/pprof/heap"
    for url, path in [(cpu_url, cpu_path), (heap_url, heap_path)]:
        with urllib.request.urlopen(url, timeout=cpu_seconds + 10) as resp:
            path.write_bytes(resp.read())
    return {
        "cpu": str(cpu_path),
        "heap": str(heap_path),
        "cpu_nonempty": cpu_path.stat().st_size > 0,
        "heap_nonempty": heap_path.stat().st_size > 0,
    }


def run() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway-host", required=True)
    ap.add_argument("--agent-host", required=True)
    ap.add_argument("--ssh-user", default="root")
    ap.add_argument("--ssh-key", default="")
    ap.add_argument("--gateway-port", type=int, default=8443)
    ap.add_argument("--modes", default="4a,4b,4c,4d,4e")
    ap.add_argument("--warp", choices=["both", "off", "builtin", "wgquick"], default="both")
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--tun-subnet", default="10.77.0.0/30")
    ap.add_argument("--gw-tun-ip", default="10.77.0.1/30")
    ap.add_argument("--agent-tun-ip", default="10.77.0.2/30")
    ap.add_argument("--metrics-forward", action="store_true", default=True)
    ap.add_argument("--iperf-seconds", type=int, default=60)
    ap.add_argument("--iperf-parallel", type=int, default=32)
    ap.add_argument("--udp-len", type=int, default=1400)
    ap.add_argument("--output-dir", default="")
    ap.add_argument("--capture-baseline", action="store_true", help="Write per-mode/warp baselines into tools/baseline_metrics.json (local repo).")
    ap.add_argument("--soak", action="store_true", help="Run a long soak loop after validate-live (default off).")
    ap.add_argument("--soak-duration-seconds", type=int, default=24 * 60 * 60)
    ap.add_argument("--soak-interval-seconds", type=int, default=300)
    ap.add_argument("--soak-mode", default="4d")
    ap.add_argument("--soak-warp", choices=["off", "on"], default="off")
    ap.add_argument("--soak-engine", choices=["builtin", "wgquick"], default="builtin")
    args = ap.parse_args()

    out_dir = pathlib.Path(args.output_dir) if args.output_dir else (ROOT / "dist" / "live-validation" / dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
    out_dir.mkdir(parents=True, exist_ok=True)

    ssh_cfg = SSHConfig(user=args.ssh_user, key=args.ssh_key)

    # Preflight
    remote_preflight(ssh_cfg, args.gateway_host)
    remote_preflight(ssh_cfg, args.agent_host)

    bundle = pathlib.Path(args.bundle)
    if not bundle.exists():
        die(f"bundle not found: {bundle}")

    # Upload bundle
    ensure_rc(scp_to(ssh_cfg, args.gateway_host, str(bundle), "/tmp/stealthlink.zip").returncode == 0, "scp bundle to gateway")
    ensure_rc(scp_to(ssh_cfg, args.agent_host, str(bundle), "/tmp/stealthlink.zip").returncode == 0, "scp bundle to agent")

    # Install offline
    r = run_ssh(ssh_cfg, args.gateway_host, "stealthlink-ctl install --bundle=/tmp/stealthlink.zip --role=gateway --offline")
    ensure_rc(r.returncode == 0, "install gateway", r.stdout, r.stderr)
    r = run_ssh(ssh_cfg, args.agent_host, "stealthlink-ctl install --bundle=/tmp/stealthlink.zip --role=agent --offline")
    ensure_rc(r.returncode == 0, "install agent", r.stdout, r.stderr)

    # Detect rawtcp uplink (only required for 4b, but cheap and reused)
    gw_uplink = detect_uplink(ssh_cfg, args.gateway_host)
    ag_uplink = detect_uplink(ssh_cfg, args.agent_host)

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    warp_runs: list[tuple[str, str]] = []
    if args.warp == "both":
        warp_runs = [("off", "builtin"), ("on", "builtin")]
    elif args.warp == "off":
        warp_runs = [("off", "builtin")]
    elif args.warp == "builtin":
        warp_runs = [("on", "builtin")]
    elif args.warp == "wgquick":
        warp_runs = [("on", "wgquick")]

    report: dict[str, Any] = {
        "generated_at": ts(),
        "gateway_host": args.gateway_host,
        "agent_host": args.agent_host,
        "gateway_port": args.gateway_port,
        "runs": [],
        "pass": True,
    }

    # Setup signal handling to clean up forwarding processes.
    forwards: list[subprocess.Popen[str]] = []

    def cleanup(*_a: Any) -> None:
        for p in forwards:
            try:
                p.terminate()
            except Exception:
                pass
        for p in forwards:
            try:
                p.wait(timeout=3)
            except Exception:
                pass

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    baselines: dict[str, Any] = {}

    for mode in modes:
        for warp_state, engine in warp_runs:
            run_obj: dict[str, Any] = {"mode": mode, "warp": warp_state, "engine": engine, "pass": False}

            shared_key = rand_b64(48)
            gw_cfg = build_gateway_config(
                mode=mode,
                gateway_port=args.gateway_port,
                shared_key=shared_key,
                gw_tun_ip_cidr=args.gw_tun_ip,
                agent_tun_ip=args.agent_tun_ip.split("/")[0],
                warp=warp_state,
                warp_engine=engine,
                rawtcp=gw_uplink,
            )
            ag_cfg = build_agent_config(
                mode=mode,
                gateway_host=args.gateway_host,
                gateway_port=args.gateway_port,
                shared_key=shared_key,
                agent_tun_ip_cidr=args.agent_tun_ip,
                gw_tun_ip=args.gw_tun_ip.split("/")[0],
                warp=warp_state,
                warp_engine=engine,
                rawtcp=ag_uplink,
            )

            # Sync AnyTLS password for 4c carrier if used.
            if mode == "4c":
                anytls = gw_cfg["transport"]["uqsp"]["carrier"]["anytls"]
                ag_carrier = {"type": "anytls", "anytls": dict(anytls)}
                # The agent must dial the real gateway host:port.
                ag_carrier["anytls"]["server"] = f"{args.gateway_host}:{args.gateway_port}"
                ag_carrier["anytls"]["tls_server_name"] = args.gateway_host
                ag_cfg["transport"]["uqsp"]["carrier"] = ag_carrier
                ag_cfg["transport"]["uqsp"].setdefault("behaviors", {})
                ag_cfg["transport"]["uqsp"]["behaviors"]["anytls"] = dict(gw_cfg["transport"]["uqsp"]["behaviors"]["anytls"])

            local_cfg_dir = out_dir / "configs" / f"{mode}-{warp_state}-{engine}"
            gw_local = local_cfg_dir / "gateway.yaml"
            ag_local = local_cfg_dir / "agent.yaml"
            write_local(gw_local, gw_cfg)
            write_local(ag_local, ag_cfg)

            # Upload configs
            ensure_rc(scp_to(ssh_cfg, args.gateway_host, str(gw_local), "/etc/stealthlink/gateway.yaml").returncode == 0, "upload gateway.yaml")
            ensure_rc(scp_to(ssh_cfg, args.agent_host, str(ag_local), "/etc/stealthlink/agent.yaml").returncode == 0, "upload agent.yaml")

            # Restart services
            r = run_ssh(ssh_cfg, args.gateway_host, "systemctl restart stealthlink-gateway")
            ensure_rc(r.returncode == 0, "restart gateway", r.stdout, r.stderr)
            r = run_ssh(ssh_cfg, args.agent_host, "systemctl restart stealthlink-agent")
            ensure_rc(r.returncode == 0, "restart agent", r.stdout, r.stderr)

            # Forward metrics ports
            # (Gateway 9091 -> local 19091, Agent 9092 -> local 19092)
            for p in forwards:
                try:
                    p.terminate()
                except Exception:
                    pass
            forwards.clear()
            p_gw = start_ssh_forward(ssh_cfg, args.gateway_host, 19091, "127.0.0.1", 9091)
            p_ag = start_ssh_forward(ssh_cfg, args.agent_host, 19092, "127.0.0.1", 9092)
            forwards.extend([p_gw, p_ag])
            time.sleep(1.0)

            # Health check: ping over tunnel from gateway.
            r = run_ssh(ssh_cfg, args.gateway_host, f"ping -c 3 -W 2 {shlex.quote(args.agent_tun_ip.split('/')[0])} >/dev/null 2>&1")
            ensure_rc(r.returncode == 0, "tun ping (gateway->agent)")

            # Metrics assertions
            gw_metrics = fetch_metrics_json(19091)
            run_obj["gateway_metrics"] = {
                "underlay_selected": gw_metrics.get("underlay_selected"),
                "warp_health": gw_metrics.get("warp_health"),
            }
            if warp_state == "off":
                ensure_rc(gw_metrics.get("underlay_selected") in (None, "", "direct"), "underlay_selected expected direct")
            else:
                ensure_rc(gw_metrics.get("underlay_selected") == "warp", "underlay_selected expected warp")
                ensure_rc(gw_metrics.get("warp_health") == "up", "warp_health expected up")

            # Start iperf3 server on agent bound to TUN IP.
            agent_tun_ip = args.agent_tun_ip.split("/")[0]
            r = run_ssh(ssh_cfg, args.agent_host, f"nohup iperf3 -s -B {shlex.quote(agent_tun_ip)} -p 5201 > /tmp/iperf3.log 2>&1 & echo $!")
            ensure_rc(r.returncode == 0, "start iperf3 server", r.stdout, r.stderr)
            iperf_pid = r.stdout.strip().splitlines()[-1].strip()
            run_obj["iperf3_server_pid"] = iperf_pid
            time.sleep(1.0)

            # Run benchmark runner on gateway against agent TUN IP (through tunnel).
            cmd = (
                "python3 /etc/stealthlink/tools/benchmark_runner.py "
                + shlex.quote(agent_tun_ip)
                + f" --seconds {args.iperf_seconds} --baseline /etc/stealthlink/tools/baseline_metrics.json"
                + f" --mode-profile {mode} --warp {'on' if warp_state != 'off' else 'off'}"
            )
            r = run_ssh(ssh_cfg, args.gateway_host, cmd, timeout_sec=max(30, args.iperf_seconds + 30))
            run_obj["benchmark_runner"] = {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr, "cmd": cmd}
            parsed = parse_json(r.stdout)
            run_obj["benchmark_parsed"] = parsed
            ensure_rc(r.returncode == 0, "benchmark_runner", r.stdout, r.stderr)

            metrics = parsed.get("metrics", {})
            if isinstance(metrics, dict):
                baselines.setdefault(mode, {})
                baselines[mode][("on" if warp_state != "off" else "off")] = {
                    "tcp_mbps": metrics.get("tcp_mbps"),
                    "udp_mbps": metrics.get("udp_mbps"),
                    "latency_ms": metrics.get("latency_ms"),
                    "reconnect_seconds": metrics.get("reconnect_seconds"),
                }

            # Stop iperf3 server best-effort.
            run_ssh(ssh_cfg, args.agent_host, f"kill {shlex.quote(iperf_pid)} >/dev/null 2>&1 || true")

            # Reconnect probe: restart agent and time until ping works again.
            t0 = time.monotonic()
            run_ssh(ssh_cfg, args.agent_host, "systemctl restart stealthlink-agent")
            ok = False
            while time.monotonic() - t0 < 30:
                r = run_ssh(ssh_cfg, args.gateway_host, f"ping -c 1 -W 1 {shlex.quote(agent_tun_ip)} >/dev/null 2>&1")
                if r.returncode == 0:
                    ok = True
                    break
                time.sleep(1.0)
            reconnect_seconds = time.monotonic() - t0
            run_obj["reconnect_seconds_observed"] = reconnect_seconds
            ensure_rc(ok, "reconnect probe (ping after agent restart)")

            # Collect pprof from gateway metrics port forward.
            pprof_dir = out_dir / "pprof" / f"{mode}-{warp_state}-{engine}"
            pprof = collect_pprof(19091, pprof_dir, "gateway", cpu_seconds=60)
            run_obj["pprof"] = pprof
            ensure_rc(pprof["cpu_nonempty"] and pprof["heap_nonempty"], "pprof collection")

            # Stress: start echo server on agent (tun), run client on gateway.
            stress_port = 18080
            # Start server (kill old first).
            run_ssh(ssh_cfg, args.agent_host, "pkill -f \"stealthlink-tools live-stress server\" >/dev/null 2>&1 || true")
            r = run_ssh(
                ssh_cfg,
                args.agent_host,
                f"nohup stealthlink-tools live-stress server --tcp {shlex.quote(agent_tun_ip)}:{stress_port} --udp {shlex.quote(agent_tun_ip)}:{stress_port} > /tmp/live-stress-server.log 2>&1 & echo $!",
            )
            ensure_rc(r.returncode == 0, "start live-stress server", r.stdout, r.stderr)
            stress_pid = r.stdout.strip().splitlines()[-1].strip()
            time.sleep(1.0)
            r = run_ssh(
                ssh_cfg,
                args.gateway_host,
                f"stealthlink-tools live-stress client --tcp-target {shlex.quote(agent_tun_ip)}:{stress_port} --udp-target {shlex.quote(agent_tun_ip)}:{stress_port} --tcp-conns 1000 --duration 60s --payload-bytes 1024 --udp-packets 5000",
                timeout_sec=120,
            )
            run_obj["stress_client"] = {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
            ensure_rc(r.returncode == 0, "run live-stress client", r.stdout, r.stderr)
            stress_parsed = parse_json(r.stdout)
            run_obj["stress_parsed"] = stress_parsed
            # Apply pass/fail criteria.
            tcp_attempted = int(stress_parsed.get("tcp_attempted") or 0)
            tcp_succeeded = int(stress_parsed.get("tcp_succeeded") or 0)
            udp_attempted = int(stress_parsed.get("udp_attempted") or 0)
            udp_echoed = int(stress_parsed.get("udp_echoed") or 0)
            tcp_ok = (tcp_attempted == 0) or (tcp_succeeded / max(1, tcp_attempted) >= 0.995)
            udp_ok = (udp_attempted == 0) or ((udp_attempted - udp_echoed) / max(1, udp_attempted) <= 0.01)
            run_obj["stress_pass"] = bool(tcp_ok and udp_ok)
            ensure_rc(tcp_ok and udp_ok, "stress criteria")
            run_ssh(ssh_cfg, args.agent_host, f"kill {shlex.quote(stress_pid)} >/dev/null 2>&1 || true")

            run_obj["pass"] = True
            report["runs"].append(run_obj)

    # Write reports
    validate_path = out_dir / "validate-live.json"
    validate_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    # Secondary Phase 11 artifact names expected by docs/runbook.
    stress_summary = {
        "generated_at": ts(),
        "runs": [
            {"mode": r.get("mode"), "warp": r.get("warp"), "engine": r.get("engine"), "pass": r.get("stress_pass"), "result": r.get("stress_parsed")}
            for r in report["runs"]
        ],
        "pass": all(bool(r.get("stress_pass")) for r in report["runs"]),
    }
    (out_dir / "stress-live.json").write_text(json.dumps(stress_summary, indent=2) + "\n", encoding="utf-8")

    profile_summary = {
        "generated_at": ts(),
        "runs": [
            {"mode": r.get("mode"), "warp": r.get("warp"), "engine": r.get("engine"), "pass": bool(r.get("pprof", {}).get("cpu_nonempty")) and bool(r.get("pprof", {}).get("heap_nonempty")), "pprof": r.get("pprof")}
            for r in report["runs"]
        ],
        "pass": all((bool(r.get("pprof", {}).get("cpu_nonempty")) and bool(r.get("pprof", {}).get("heap_nonempty"))) for r in report["runs"]),
    }
    (out_dir / "profile-live.json").write_text(json.dumps(profile_summary, indent=2) + "\n", encoding="utf-8")

    if args.soak:
        # Re-apply chosen soak mode config, then probe periodically.
        soak_mode = args.soak_mode
        soak_warp_state = args.soak_warp
        soak_engine = args.soak_engine
        # Sanity: if user requests wgquick soak, preflight for wg-quick.
        if soak_warp_state == "on" and soak_engine == "wgquick":
            for host in (args.gateway_host, args.agent_host):
                r = run_ssh(ssh_cfg, host, "command -v wg-quick >/dev/null")
                ensure_rc(r.returncode == 0, f"{host}: wg-quick missing (required for --soak-engine=wgquick)", r.stdout, r.stderr)

        shared_key = rand_b64(48)
        gw_cfg = build_gateway_config(
            mode=soak_mode,
            gateway_port=args.gateway_port,
            shared_key=shared_key,
            gw_tun_ip_cidr=args.gw_tun_ip,
            agent_tun_ip=args.agent_tun_ip.split("/")[0],
            warp=("off" if soak_warp_state == "off" else "on"),
            warp_engine=soak_engine,
            rawtcp=gw_uplink,
        )
        ag_cfg = build_agent_config(
            mode=soak_mode,
            gateway_host=args.gateway_host,
            gateway_port=args.gateway_port,
            shared_key=shared_key,
            agent_tun_ip_cidr=args.agent_tun_ip,
            gw_tun_ip=args.gw_tun_ip.split("/")[0],
            warp=("off" if soak_warp_state == "off" else "on"),
            warp_engine=soak_engine,
            rawtcp=ag_uplink,
        )
        if soak_mode == "4c":
            anytls = gw_cfg["transport"]["uqsp"]["carrier"]["anytls"]
            ag_carrier = {"type": "anytls", "anytls": dict(anytls)}
            ag_carrier["anytls"]["server"] = f"{args.gateway_host}:{args.gateway_port}"
            ag_carrier["anytls"]["tls_server_name"] = args.gateway_host
            ag_cfg["transport"]["uqsp"]["carrier"] = ag_carrier
            ag_cfg["transport"]["uqsp"].setdefault("behaviors", {})
            ag_cfg["transport"]["uqsp"]["behaviors"]["anytls"] = dict(gw_cfg["transport"]["uqsp"]["behaviors"]["anytls"])

        local_cfg_dir = out_dir / "configs" / f"soak-{soak_mode}-{soak_warp_state}-{soak_engine}"
        gw_local = local_cfg_dir / "gateway.yaml"
        ag_local = local_cfg_dir / "agent.yaml"
        write_local(gw_local, gw_cfg)
        write_local(ag_local, ag_cfg)
        ensure_rc(scp_to(ssh_cfg, args.gateway_host, str(gw_local), "/etc/stealthlink/gateway.yaml").returncode == 0, "upload soak gateway.yaml")
        ensure_rc(scp_to(ssh_cfg, args.agent_host, str(ag_local), "/etc/stealthlink/agent.yaml").returncode == 0, "upload soak agent.yaml")
        ensure_rc(run_ssh(ssh_cfg, args.gateway_host, "systemctl restart stealthlink-gateway").returncode == 0, "restart gateway (soak)")
        ensure_rc(run_ssh(ssh_cfg, args.agent_host, "systemctl restart stealthlink-agent").returncode == 0, "restart agent (soak)")

        # Ensure forwards are up (reuse ports).
        for p in forwards:
            try:
                p.terminate()
            except Exception:
                pass
        forwards.clear()
        p_gw = start_ssh_forward(ssh_cfg, args.gateway_host, 19091, "127.0.0.1", 9091)
        p_ag = start_ssh_forward(ssh_cfg, args.agent_host, 19092, "127.0.0.1", 9092)
        forwards.extend([p_gw, p_ag])
        time.sleep(1.0)

        agent_tun_ip = args.agent_tun_ip.split("/")[0]
        started = time.monotonic()
        checks: list[dict[str, Any]] = []
        consecutive_fail = 0
        baseline_mem: int | None = None
        max_mem: int | None = None
        pass_all = True
        while time.monotonic() - started < args.soak_duration_seconds:
            at = ts()
            ping_rc = run_ssh(ssh_cfg, args.gateway_host, f"ping -c 1 -W 2 {shlex.quote(agent_tun_ip)} >/dev/null 2>&1").returncode
            ok_ping = (ping_rc == 0)
            if ok_ping:
                consecutive_fail = 0
            else:
                consecutive_fail += 1
                if consecutive_fail >= 2:
                    pass_all = False

            # systemd MemoryCurrent best-effort (0 if unsupported).
            gw_mem = run_ssh(ssh_cfg, args.gateway_host, "systemctl show -p MemoryCurrent --value stealthlink-gateway || true").stdout.strip()
            try:
                gw_mem_i = int(gw_mem) if gw_mem else 0
            except ValueError:
                gw_mem_i = 0
            if baseline_mem is None and gw_mem_i > 0:
                baseline_mem = gw_mem_i
            if gw_mem_i > 0:
                max_mem = gw_mem_i if max_mem is None else max(max_mem, gw_mem_i)

            m = {}
            try:
                m = fetch_metrics_json(19091)
            except Exception:
                pass_all = False

            checks.append(
                {
                    "at": at,
                    "ping_ok": ok_ping,
                    "gateway_memory_current": gw_mem_i,
                    "metrics_underlay_selected": m.get("underlay_selected"),
                    "metrics_warp_health": m.get("warp_health"),
                }
            )
            time.sleep(max(1, args.soak_interval_seconds))

        mem_ok = True
        if baseline_mem and max_mem:
            mem_ok = max_mem <= int(baseline_mem * 1.25)
        soak_payload = {
            "generated_at": ts(),
            "mode": soak_mode,
            "warp": soak_warp_state,
            "engine": soak_engine,
            "duration_seconds": args.soak_duration_seconds,
            "interval_seconds": args.soak_interval_seconds,
            "checks": checks,
            "baseline_memory_current": baseline_mem,
            "max_memory_current": max_mem,
            "memory_ok": mem_ok,
            "pass": bool(pass_all and mem_ok),
        }
        (out_dir / "soak-24h.json").write_text(json.dumps(soak_payload, indent=2) + "\n", encoding="utf-8")
        if not soak_payload["pass"]:
            report["pass"] = False

    # Optional baseline capture into repo baseline file.
    if args.capture_baseline:
        baseline_path = ROOT / "tools" / "baseline_metrics.json"
        existing = json.loads(baseline_path.read_text(encoding="utf-8"))
        existing.setdefault("profiles", {})
        for mode, bywarp in baselines.items():
            existing["profiles"].setdefault(mode, {})
            for w, vals in bywarp.items():
                # Only write numeric values.
                payload = {}
                for k in ("tcp_mbps", "udp_mbps", "latency_ms", "reconnect_seconds"):
                    v = vals.get(k)
                    if isinstance(v, (int, float)):
                        payload[k] = float(v)
                existing["profiles"][mode][w] = payload
        # Mark as measured.
        if isinstance(existing.get("network_performance"), dict):
            existing["network_performance"]["measurement_status"] = "measured"
            existing["network_performance"]["notes"] = "Measured via tools/live_validation_ssh.py"
        baseline_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")

    # Global pass status
    report["pass"] = all(r.get("pass") for r in report["runs"])
    (out_dir / "release-readiness.json").write_text(json.dumps({"generated_at": ts(), "pass": report["pass"]}, indent=2) + "\n", encoding="utf-8")
    return 0 if report["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(run())
