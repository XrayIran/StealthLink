#!/usr/bin/env python3
"""Minimal ssh/scp wrappers (no third-party deps)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence


@dataclass
class SSHConfig:
    user: str = "root"
    key: str = ""
    connect_timeout_sec: int = 10


def _base_ssh_args(cfg: SSHConfig) -> list[str]:
    args = [
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={cfg.connect_timeout_sec}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=3",
    ]
    if cfg.key:
        args += ["-i", cfg.key]
    return args


def run_ssh(cfg: SSHConfig, host: str, remote_cmd: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess[str]:
    cmd = ["ssh", *_base_ssh_args(cfg), f"{cfg.user}@{host}", remote_cmd]
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout_sec)


def start_ssh_forward(
    cfg: SSHConfig,
    host: str,
    local_port: int,
    remote_host: str,
    remote_port: int,
) -> subprocess.Popen[str]:
    cmd = [
        "ssh",
        *_base_ssh_args(cfg),
        "-N",
        "-o", "ExitOnForwardFailure=yes",
        "-L", f"127.0.0.1:{local_port}:{remote_host}:{remote_port}",
        f"{cfg.user}@{host}",
    ]
    return subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def scp_to(cfg: SSHConfig, host: str, local_path: str, remote_path: str) -> subprocess.CompletedProcess[str]:
    cmd = ["scp", *_base_ssh_args(cfg), local_path, f"{cfg.user}@{host}:{remote_path}"]
    return subprocess.run(cmd, text=True, capture_output=True)


def scp_from(cfg: SSHConfig, host: str, remote_path: str, local_path: str) -> subprocess.CompletedProcess[str]:
    cmd = ["scp", *_base_ssh_args(cfg), f"{cfg.user}@{host}:{remote_path}", local_path]
    return subprocess.run(cmd, text=True, capture_output=True)

