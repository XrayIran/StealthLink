#!/usr/bin/env bash
# Stealthlink Systemd iptables Helper
# Reads configuration and applies/removes iptables rules for rawtcp transport
# Intended for use as ExecStartPre/ExecStopPost in systemd service

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
CONFIG_FILE=""
ACTION=""

usage() {
  cat <<'EOF'
Usage: stealthlink-systemd-iptables.sh [options] <action>

Options:
  -c, --config <path>   Path to stealthlink config file (required)
  -h, --help            Show this help message

Actions:
  apply                 Apply iptables rules for rawtcp transport
  remove                Remove iptables rules for rawtcp transport

Environment Variables:
  STEALTHLINK_CONFIG    Default config file path if -c not specified

Examples:
  stealthlink-systemd-iptables.sh -c /etc/stealthlink/gateway.yaml apply
  stealthlink-systemd-iptables.sh -c /etc/stealthlink/gateway.yaml remove

Systemd Integration:
  ExecStartPre=-/usr/local/bin/stealthlink-systemd-iptables.sh -c /etc/stealthlink/gateway.yaml apply
  ExecStopPost=-/usr/local/bin/stealthlink-systemd-iptables.sh -c /etc/stealthlink/gateway.yaml remove
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--config)
      CONFIG_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    apply|remove)
      ACTION="$1"
      shift
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

# Use environment variable as fallback
if [[ -z "$CONFIG_FILE" && -n "${STEALTHLINK_CONFIG:-}" ]]; then
  CONFIG_FILE="$STEALTHLINK_CONFIG"
fi

# Validate arguments
if [[ -z "$CONFIG_FILE" ]]; then
  echo "error: config file required (use -c or STEALTHLINK_CONFIG)" >&2
  usage
  exit 1
fi

if [[ -z "$ACTION" ]]; then
  echo "error: action required (apply or remove)" >&2
  usage
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "error: config file not found: $CONFIG_FILE" >&2
  exit 1
fi

# Extract transport type and rawtcp port from config
# This uses simple grep/sed parsing - assumes YAML format
transport_type=""
rawtcp_port=""

# Try to extract transport type
transport_type=$(grep -E '^\s*type:\s*' "$CONFIG_FILE" | head -1 | sed 's/.*:\s*//;s/["'\'' ]//g')

# If transport type is rawtcp, extract the port
if [[ "$transport_type" == "rawtcp" ]]; then
  # Try to get port from gateway.listen
  listen_addr=$(grep -E '^\s*listen:\s*' "$CONFIG_FILE" | head -1 | sed 's/.*:\s*//;s/["'\'' ]//g')
  if [[ -n "$listen_addr" ]]; then
    # Extract port from address (handle "host:port" or ":port" formats)
    if [[ "$listen_addr" =~ :([0-9]+)$ ]]; then
      rawtcp_port="${BASH_REMATCH[1]}"
    fi
  fi

  # Fallback: try to get port from rawtcp.ipv4.addr
  if [[ -z "$rawtcp_port" ]]; then
    rawtcp_addr=$(grep -A5 'rawtcp:' "$CONFIG_FILE" | grep -E 'addr:' | head -1 | sed 's/.*:\s*//;s/["'\'' ]//g')
    if [[ "$rawtcp_addr" =~ :([0-9]+)$ ]]; then
      rawtcp_port="${BASH_REMATCH[1]}"
    fi
  fi
fi

# If not rawtcp transport, nothing to do
if [[ "$transport_type" != "rawtcp" ]]; then
  echo "Transport type is '$transport_type', not rawtcp - no iptables rules needed"
  exit 0
fi

if [[ -z "$rawtcp_port" ]]; then
  echo "error: could not determine rawtcp port from config" >&2
  exit 1
fi

echo "RawTCP transport detected on port $rawtcp_port"

# iptables helper functions
rule_exists() {
  local table="$1"
  shift
  iptables -t "$table" -C "$@" 2>/dev/null
}

rule_add() {
  local table="$1"
  shift
  if ! rule_exists "$table" "$@"; then
    echo "Adding iptables rule: -t $table $*"
    iptables -t "$table" -A "$@"
  else
    echo "Rule already exists: -t $table $*"
  fi
}

rule_del() {
  local table="$1"
  shift
  if rule_exists "$table" "$@"; then
    echo "Removing iptables rule: -t $table $*"
    iptables -t "$table" -D "$@"
  else
    echo "Rule does not exist: -t $table $*"
  fi
}

# Apply or remove rules
case "$ACTION" in
  apply)
    echo "Applying iptables rules for rawtcp port $rawtcp_port..."

    # Bypass conntrack for the rawtcp port
    rule_add raw PREROUTING -p tcp --dport "$rawtcp_port" -j NOTRACK
    rule_add raw OUTPUT -p tcp --sport "$rawtcp_port" -j NOTRACK

    # Drop kernel-generated RSTs from the rawtcp port
    rule_add mangle OUTPUT -p tcp --sport "$rawtcp_port" --tcp-flags RST RST -j DROP

    # Also handle IPv6 if ip6tables is available
    if command -v ip6tables >/dev/null 2>&1; then
      echo "Applying IPv6 rules..."
      if ! ip6tables -t raw -C PREROUTING -p tcp --dport "$rawtcp_port" -j NOTRACK 2>/dev/null; then
        ip6tables -t raw -A PREROUTING -p tcp --dport "$rawtcp_port" -j NOTRACK 2>/dev/null || true
      fi
      if ! ip6tables -t raw -C OUTPUT -p tcp --sport "$rawtcp_port" -j NOTRACK 2>/dev/null; then
        ip6tables -t raw -A OUTPUT -p tcp --sport "$rawtcp_port" -j NOTRACK 2>/dev/null || true
      fi
      if ! ip6tables -t mangle -C OUTPUT -p tcp --sport "$rawtcp_port" --tcp-flags RST RST -j DROP 2>/dev/null; then
        ip6tables -t mangle -A OUTPUT -p tcp --sport "$rawtcp_port" --tcp-flags RST RST -j DROP 2>/dev/null || true
      fi
    fi

    echo "Rules applied successfully"
    ;;

  remove)
    echo "Removing iptables rules for rawtcp port $rawtcp_port..."

    # Remove in reverse order
    rule_del mangle OUTPUT -p tcp --sport "$rawtcp_port" --tcp-flags RST RST -j DROP
    rule_del raw OUTPUT -p tcp --sport "$rawtcp_port" -j NOTRACK
    rule_del raw PREROUTING -p tcp --dport "$rawtcp_port" -j NOTRACK

    # Also handle IPv6 if ip6tables is available
    if command -v ip6tables >/dev/null 2>&1; then
      echo "Removing IPv6 rules..."
      ip6tables -t mangle -D OUTPUT -p tcp --sport "$rawtcp_port" --tcp-flags RST RST -j DROP 2>/dev/null || true
      ip6tables -t raw -D OUTPUT -p tcp --sport "$rawtcp_port" -j NOTRACK 2>/dev/null || true
      ip6tables -t raw -D PREROUTING -p tcp --dport "$rawtcp_port" -j NOTRACK 2>/dev/null || true
    fi

    echo "Rules removed successfully"
    ;;

  *)
    echo "error: unknown action: $ACTION" >&2
    exit 1
    ;;
esac
