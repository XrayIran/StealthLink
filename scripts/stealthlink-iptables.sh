#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  stealthlink-iptables.sh apply <port>
  stealthlink-iptables.sh remove <port>
  stealthlink-iptables.sh persist
  stealthlink-iptables.sh status <port>

Adds/removes iptables/ip6tables/firewalld rules to suppress TCP RSTs for
rawtcp (pcap) transport. Supports IPv4 + IPv6 and firewalld detection.
EOF
}

action="${1:-}"
port="${2:-}"

if [[ -z "${action}" ]]; then
  usage
  exit 1
fi

if [[ "${action}" != "persist" && "${action}" != "status" && -z "${port}" ]]; then
  usage
  exit 1
fi

if [[ -n "${port}" ]] && ! [[ "${port}" =~ ^[0-9]+$ ]]; then
  echo "error: port must be a number" >&2
  exit 1
fi

# Detect firewall backend
is_firewalld_active() {
  command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null
}

has_iptables() {
  command -v iptables &>/dev/null
}

has_ip6tables() {
  command -v ip6tables &>/dev/null
}

# iptables helpers (idempotent)
ipt_add() {
  local table="$1"; shift
  if ! iptables -t "${table}" -C "$@" 2>/dev/null; then
    iptables -t "${table}" -A "$@"
  fi
}

ipt_del() {
  local table="$1"; shift
  if iptables -t "${table}" -C "$@" 2>/dev/null; then
    iptables -t "${table}" -D "$@"
  fi
}

# ip6tables helpers
ip6t_add() {
  local table="$1"; shift
  if has_ip6tables; then
    if ! ip6tables -t "${table}" -C "$@" 2>/dev/null; then
      ip6tables -t "${table}" -A "$@"
    fi
  fi
}

ip6t_del() {
  local table="$1"; shift
  if has_ip6tables; then
    if ip6tables -t "${table}" -C "$@" 2>/dev/null; then
      ip6tables -t "${table}" -D "$@"
    fi
  fi
}

# firewalld helpers
fwd_apply() {
  local port="$1"
  firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p tcp --dport "${port}" -j NOTRACK 2>/dev/null || true
  firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p tcp --sport "${port}" -j NOTRACK 2>/dev/null || true
  firewall-cmd --direct --add-rule ipv4 mangle OUTPUT 0 -p tcp --sport "${port}" --tcp-flags RST RST -j DROP 2>/dev/null || true
  # IPv6
  firewall-cmd --direct --add-rule ipv6 raw PREROUTING 0 -p tcp --dport "${port}" -j NOTRACK 2>/dev/null || true
  firewall-cmd --direct --add-rule ipv6 raw OUTPUT 0 -p tcp --sport "${port}" -j NOTRACK 2>/dev/null || true
  firewall-cmd --direct --add-rule ipv6 mangle OUTPUT 0 -p tcp --sport "${port}" --tcp-flags RST RST -j DROP 2>/dev/null || true
}

fwd_remove() {
  local port="$1"
  firewall-cmd --direct --remove-rule ipv4 mangle OUTPUT 0 -p tcp --sport "${port}" --tcp-flags RST RST -j DROP 2>/dev/null || true
  firewall-cmd --direct --remove-rule ipv4 raw OUTPUT 0 -p tcp --sport "${port}" -j NOTRACK 2>/dev/null || true
  firewall-cmd --direct --remove-rule ipv4 raw PREROUTING 0 -p tcp --dport "${port}" -j NOTRACK 2>/dev/null || true
  firewall-cmd --direct --remove-rule ipv6 mangle OUTPUT 0 -p tcp --sport "${port}" --tcp-flags RST RST -j DROP 2>/dev/null || true
  firewall-cmd --direct --remove-rule ipv6 raw OUTPUT 0 -p tcp --sport "${port}" -j NOTRACK 2>/dev/null || true
  firewall-cmd --direct --remove-rule ipv6 raw PREROUTING 0 -p tcp --dport "${port}" -j NOTRACK 2>/dev/null || true
}

persist_rules() {
  if is_firewalld_active; then
    firewall-cmd --runtime-to-permanent 2>/dev/null && echo "firewalld rules persisted" && return
  fi

  # Debian/Ubuntu
  if [[ -d /etc/iptables ]]; then
    iptables-save > /etc/iptables/rules.v4
    has_ip6tables && ip6tables-save > /etc/iptables/rules.v6
    echo "iptables rules saved to /etc/iptables/rules.v{4,6}"
    return
  fi

  # RHEL/CentOS
  if command -v service &>/dev/null && [[ -f /etc/sysconfig/iptables ]]; then
    service iptables save 2>/dev/null || iptables-save > /etc/sysconfig/iptables
    has_ip6tables && (service ip6tables save 2>/dev/null || ip6tables-save > /etc/sysconfig/ip6tables)
    echo "iptables rules saved"
    return
  fi

  # Fallback
  if command -v iptables-save &>/dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    has_ip6tables && ip6tables-save > /etc/iptables/rules.v6
    echo "iptables rules saved to /etc/iptables/rules.v{4,6}"
    return
  fi

  echo "warning: could not persist rules, no persistence mechanism found" >&2
}

show_status() {
  local port="$1"
  echo "=== StealthLink Firewall Rules (port ${port}) ==="
  echo

  if is_firewalld_active; then
    echo "Backend: firewalld"
    echo
    echo "Direct rules:"
    firewall-cmd --direct --get-all-rules 2>/dev/null | grep -E "${port}" || echo "  (none matching)"
  elif has_iptables; then
    echo "Backend: iptables"
    echo
    echo "IPv4 raw table:"
    iptables -t raw -L -n 2>/dev/null | grep -E "${port}" || echo "  (none matching)"
    echo
    echo "IPv4 mangle table:"
    iptables -t mangle -L -n 2>/dev/null | grep -E "${port}" || echo "  (none matching)"
    if has_ip6tables; then
      echo
      echo "IPv6 raw table:"
      ip6tables -t raw -L -n 2>/dev/null | grep -E "${port}" || echo "  (none matching)"
      echo
      echo "IPv6 mangle table:"
      ip6tables -t mangle -L -n 2>/dev/null | grep -E "${port}" || echo "  (none matching)"
    fi
  else
    echo "No firewall backend found"
  fi
}

case "${action}" in
  apply)
    if is_firewalld_active; then
      echo "Using firewalld backend"
      fwd_apply "${port}"
    elif has_iptables; then
      echo "Using iptables backend"
      # IPv4
      ipt_add raw PREROUTING -p tcp --dport "${port}" -j NOTRACK
      ipt_add raw OUTPUT -p tcp --sport "${port}" -j NOTRACK
      ipt_add mangle OUTPUT -p tcp --sport "${port}" --tcp-flags RST RST -j DROP
      # IPv6
      ip6t_add raw PREROUTING -p tcp --dport "${port}" -j NOTRACK
      ip6t_add raw OUTPUT -p tcp --sport "${port}" -j NOTRACK
      ip6t_add mangle OUTPUT -p tcp --sport "${port}" --tcp-flags RST RST -j DROP
    else
      echo "error: no firewall backend (iptables or firewalld) found" >&2
      exit 1
    fi
    echo "Rules applied for port ${port}"
    ;;
  remove)
    if is_firewalld_active; then
      fwd_remove "${port}"
    elif has_iptables; then
      ipt_del mangle OUTPUT -p tcp --sport "${port}" --tcp-flags RST RST -j DROP
      ipt_del raw OUTPUT -p tcp --sport "${port}" -j NOTRACK
      ipt_del raw PREROUTING -p tcp --dport "${port}" -j NOTRACK
      ip6t_del mangle OUTPUT -p tcp --sport "${port}" --tcp-flags RST RST -j DROP
      ip6t_del raw OUTPUT -p tcp --sport "${port}" -j NOTRACK
      ip6t_del raw PREROUTING -p tcp --dport "${port}" -j NOTRACK
    fi
    echo "Rules removed for port ${port}"
    ;;
  persist)
    persist_rules
    ;;
  status)
    show_status "${port}"
    ;;
  *)
    usage
    exit 1
    ;;
esac
