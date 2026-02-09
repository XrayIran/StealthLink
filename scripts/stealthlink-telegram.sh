#!/usr/bin/env bash
set -euo pipefail

# StealthLink Telegram Monitoring Bot
# Monitors StealthLink service and sends alerts/reports via Telegram

CONFIG="/opt/stealthlink/telegram.conf"
POLL_INTERVAL=30
REPORT_INTERVAL=21600  # 6 hours
LAST_REPORT_FILE="/var/tmp/stealthlink-telegram-last-report"
LAST_STATE_FILE="/var/tmp/stealthlink-telegram-last-state"
ALERT_COOLDOWN=300  # 5 minutes cooldown for CPU alerts
LAST_CPU_ALERT_FILE="/var/tmp/stealthlink-telegram-last-cpu-alert"

# Color codes for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

# Load configuration
load_config() {
    if [[ ! -f "$CONFIG" ]]; then
        log_error "Configuration file not found: $CONFIG"
        return 1
    fi

    # shellcheck disable=SC1090
    source "$CONFIG"

    if [[ -z "${BOT_TOKEN:-}" ]] || [[ -z "${CHAT_ID:-}" ]]; then
        log_error "BOT_TOKEN and CHAT_ID must be set in $CONFIG"
        return 1
    fi

    # Set defaults
    SERVER_LABEL="${SERVER_LABEL:-StealthLink}"
    CHECK_INTERVAL="${CHECK_INTERVAL:-$REPORT_INTERVAL}"
    ALERTS_ENABLED="${ALERTS_ENABLED:-true}"

    log_info "Configuration loaded: SERVER_LABEL=$SERVER_LABEL"
}

# Secure token storage - write to temp file for curl
get_token_file() {
    local token_file
    token_file=$(mktemp)
    chmod 600 "$token_file"
    echo "$BOT_TOKEN" > "$token_file"
    echo "$token_file"
}

# Send Telegram message
send_message() {
    local text="$1"
    local token_file
    token_file=$(get_token_file)

    local response
    response=$(curl -s -X POST \
        "https://api.telegram.org/bot$(cat "$token_file")/sendMessage" \
        -d "chat_id=$CHAT_ID" \
        -d "parse_mode=HTML" \
        -d "text=$text" \
        2>&1) || {
        log_error "Failed to send message: $response"
        rm -f "$token_file"
        return 1
    }

    rm -f "$token_file"

    if echo "$response" | grep -q '"ok":false'; then
        log_error "Telegram API error: $response"
        return 1
    fi

    log_info "Message sent successfully"
    return 0
}

# Get Telegram updates
get_updates() {
    local offset="${1:-0}"
    local token_file
    token_file=$(get_token_file)

    local response
    response=$(curl -s -X GET \
        "https://api.telegram.org/bot$(cat "$token_file")/getUpdates?offset=$offset&timeout=5" \
        2>&1) || {
        log_warn "Failed to get updates: $response"
        rm -f "$token_file"
        echo "{}"
        return 1
    }

    rm -f "$token_file"
    echo "$response"
}

# Get service status
get_service_status() {
    if systemctl is-active --quiet stealthlink; then
        echo "running"
    else
        echo "stopped"
    fi
}

# Get service uptime
get_service_uptime() {
    if systemctl is-active --quiet stealthlink; then
        systemctl show stealthlink --property=ActiveEnterTimestamp | cut -d= -f2 | xargs -I{} date -d "{}" +%s || echo "0"
    else
        echo "0"
    fi
}

# Get CPU usage
get_cpu_usage() {
    top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1
}

# Get memory usage
get_memory_usage() {
    free | grep Mem | awk '{printf "%.1f", ($3/$2) * 100.0}'
}

# Get active sessions (if metrics endpoint available)
get_active_sessions() {
    local metrics
    metrics=$(curl -s http://localhost:9090/metrics 2>/dev/null || echo "")

    if [[ -n "$metrics" ]]; then
        echo "$metrics" | grep -oP 'stealthlink_active_sessions \K[0-9]+' || echo "N/A"
    else
        echo "N/A"
    fi
}

# Get StealthLink version
get_version() {
    if command -v stealthlink &>/dev/null; then
        stealthlink version 2>/dev/null | head -n1 || echo "unknown"
    else
        echo "not installed"
    fi
}

# Generate status report
generate_status_report() {
    local status
    status=$(get_service_status)

    local uptime_seconds
    local uptime_text
    if [[ "$status" == "running" ]]; then
        uptime_seconds=$(get_service_uptime)
        local current_time
        current_time=$(date +%s)
        local uptime_duration=$((current_time - uptime_seconds))

        local days=$((uptime_duration / 86400))
        local hours=$(( (uptime_duration % 86400) / 3600 ))
        local minutes=$(( (uptime_duration % 3600) / 60 ))

        if [[ $days -gt 0 ]]; then
            uptime_text="${days}d ${hours}h ${minutes}m"
        elif [[ $hours -gt 0 ]]; then
            uptime_text="${hours}h ${minutes}m"
        else
            uptime_text="${minutes}m"
        fi
    else
        uptime_text="N/A"
    fi

    local cpu_usage
    cpu_usage=$(get_cpu_usage)

    local mem_usage
    mem_usage=$(get_memory_usage)

    local sessions
    sessions=$(get_active_sessions)

    local version
    version=$(get_version)

    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    local status_icon
    if [[ "$status" == "running" ]]; then
        status_icon="✅"
    else
        status_icon="🔴"
    fi

    cat <<EOF
<b>$SERVER_LABEL Status Report</b>
<i>$timestamp</i>

<b>Service:</b> $status_icon $status
<b>Version:</b> $version
<b>Uptime:</b> $uptime_text

<b>System Resources:</b>
CPU: ${cpu_usage}%
Memory: ${mem_usage}%

<b>Connections:</b>
Active Sessions: $sessions
EOF
}

# Handle bot commands
handle_command() {
    local command="$1"
    local response=""

    log_info "Processing command: $command"

    case "$command" in
        /status)
            response=$(generate_status_report)
            ;;
        /health)
            local health_status
            if systemctl is-active --quiet stealthlink; then
                health_status="✅ Service is running"
            else
                health_status="🔴 Service is not running"
            fi

            local cpu
            cpu=$(get_cpu_usage)
            local mem
            mem=$(get_memory_usage)

            response="<b>Health Check - $SERVER_LABEL</b>\n\n$health_status\nCPU: ${cpu}%\nMemory: ${mem}%"
            ;;
        /restart)
            log_info "Restarting stealthlink service..."
            if sudo systemctl restart stealthlink; then
                response="✅ StealthLink service restarted successfully"
            else
                response="🔴 Failed to restart StealthLink service"
            fi
            ;;
        /stop)
            log_info "Stopping stealthlink service..."
            if sudo systemctl stop stealthlink; then
                response="⏹️ StealthLink service stopped"
            else
                response="🔴 Failed to stop StealthLink service"
            fi
            ;;
        /start)
            log_info "Starting stealthlink service..."
            if sudo systemctl start stealthlink; then
                response="▶️ StealthLink service started"
            else
                response="🔴 Failed to start StealthLink service"
            fi
            ;;
        /version)
            local version
            version=$(get_version)
            response="<b>$SERVER_LABEL Version</b>\n\n$version"
            ;;
        *)
            response="Unknown command. Available commands:\n/status /health /restart /stop /start /version"
            ;;
    esac

    send_message "$response"
}

# Process Telegram updates
process_updates() {
    local updates
    updates=$(get_updates "$UPDATE_OFFSET")

    # Extract update_id and commands
    local update_ids
    update_ids=$(echo "$updates" | grep -oP '"update_id":\K[0-9]+' || echo "")

    if [[ -z "$update_ids" ]]; then
        return 0
    fi

    # Process each update
    while IFS= read -r update_id; do
        if [[ -n "$update_id" ]] && [[ "$update_id" -gt "$UPDATE_OFFSET" ]]; then
            UPDATE_OFFSET=$((update_id + 1))

            # Extract command text
            local command
            command=$(echo "$updates" | grep -oP '"text":"(/[^"]+)"' | head -n1 | cut -d'"' -f4 || echo "")

            if [[ -n "$command" ]]; then
                handle_command "$command"
            fi
        fi
    done <<< "$update_ids"
}

# Monitor service state changes
monitor_service() {
    local current_state
    current_state=$(get_service_status)

    local last_state
    if [[ -f "$LAST_STATE_FILE" ]]; then
        last_state=$(cat "$LAST_STATE_FILE")
    else
        last_state=""
    fi

    # State change detection
    if [[ -n "$last_state" ]] && [[ "$current_state" != "$last_state" ]]; then
        if [[ "$ALERTS_ENABLED" == "true" ]]; then
            if [[ "$current_state" == "running" ]]; then
                send_message "✅ <b>$SERVER_LABEL</b> - Service is UP\n\n$(date '+%Y-%m-%d %H:%M:%S')"
            else
                send_message "🔴 <b>$SERVER_LABEL</b> - Service is DOWN\n\n$(date '+%Y-%m-%d %H:%M:%S')"
            fi
        fi
    fi

    echo "$current_state" > "$LAST_STATE_FILE"

    # CPU alert
    local cpu_usage
    cpu_usage=$(get_cpu_usage)
    local cpu_threshold=80

    if (( $(echo "$cpu_usage > $cpu_threshold" | bc -l 2>/dev/null || echo 0) )); then
        local current_time
        current_time=$(date +%s)
        local last_cpu_alert=0

        if [[ -f "$LAST_CPU_ALERT_FILE" ]]; then
            last_cpu_alert=$(cat "$LAST_CPU_ALERT_FILE")
        fi

        if [[ $((current_time - last_cpu_alert)) -gt $ALERT_COOLDOWN ]]; then
            if [[ "$ALERTS_ENABLED" == "true" ]]; then
                send_message "⚠️ <b>$SERVER_LABEL</b> - High CPU Usage\n\nCPU: ${cpu_usage}% (threshold: ${cpu_threshold}%)\n$(date '+%Y-%m-%d %H:%M:%S')"
            fi
            echo "$current_time" > "$LAST_CPU_ALERT_FILE"
        fi
    fi
}

# Send periodic status report
check_periodic_report() {
    local current_time
    current_time=$(date +%s)

    local last_report=0
    if [[ -f "$LAST_REPORT_FILE" ]]; then
        last_report=$(cat "$LAST_REPORT_FILE")
    fi

    if [[ $((current_time - last_report)) -gt $CHECK_INTERVAL ]]; then
        log_info "Sending periodic status report"
        local report
        report=$(generate_status_report)
        send_message "$report"
        echo "$current_time" > "$LAST_REPORT_FILE"
    fi
}

# Main daemon loop
daemon_loop() {
    log_info "Starting StealthLink Telegram monitoring daemon"
    log_info "Poll interval: ${POLL_INTERVAL}s, Report interval: ${CHECK_INTERVAL}s"

    # Initialize update offset
    UPDATE_OFFSET=0

    # Get initial offset to skip old messages
    local initial_updates
    initial_updates=$(get_updates 0)
    local last_update_id
    last_update_id=$(echo "$initial_updates" | grep -oP '"update_id":\K[0-9]+' | tail -n1 || echo "0")
    UPDATE_OFFSET=$((last_update_id + 1))

    log_info "Initialized with update offset: $UPDATE_OFFSET"

    while true; do
        monitor_service
        check_periodic_report
        process_updates
        sleep "$POLL_INTERVAL"
    done
}

# Setup wizard
setup_wizard() {
    echo "StealthLink Telegram Bot Setup"
    echo "==============================="
    echo ""

    read -r -p "Enter Telegram Bot Token: " bot_token
    read -r -p "Enter Telegram Chat ID: " chat_id
    read -r -p "Enter Server Label (default: StealthLink): " server_label
    server_label="${server_label:-StealthLink}"

    read -r -p "Report Interval in seconds (default: 21600 = 6h): " check_interval
    check_interval="${check_interval:-21600}"

    read -r -p "Enable alerts? (true/false, default: true): " alerts_enabled
    alerts_enabled="${alerts_enabled:-true}"

    echo ""
    echo "Creating configuration at $CONFIG..."

    sudo mkdir -p "$(dirname "$CONFIG")"
    sudo tee "$CONFIG" > /dev/null <<EOF
# StealthLink Telegram Bot Configuration
BOT_TOKEN="$bot_token"
CHAT_ID="$chat_id"
SERVER_LABEL="$server_label"
CHECK_INTERVAL=$check_interval
ALERTS_ENABLED=$alerts_enabled
EOF

    sudo chmod 600 "$CONFIG"

    echo ""
    echo "Configuration saved. Testing notification..."

    if load_config; then
        if send_message "✅ <b>$SERVER_LABEL</b> - Telegram bot configured successfully!"; then
            echo ""
            log_info "Setup complete! Test notification sent."
            echo ""
            echo "Next steps:"
            echo "  1. Run: sudo $0 install-service"
            echo "  2. Run: sudo systemctl start stealthlink-telegram"
            echo "  3. Run: sudo systemctl enable stealthlink-telegram"
        else
            log_error "Failed to send test notification. Please check your bot token and chat ID."
            exit 1
        fi
    fi
}

# Install systemd service
install_service() {
    local service_file="/etc/systemd/system/stealthlink-telegram.service"
    local script_path
    script_path=$(realpath "$0")

    log_info "Installing systemd service to $service_file"

    sudo tee "$service_file" > /dev/null <<EOF
[Unit]
Description=StealthLink Telegram Monitoring Bot
After=network.target stealthlink.service
Wants=stealthlink.service

[Service]
Type=simple
ExecStart=$script_path daemon
Restart=always
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload

    log_info "Service installed successfully"
    echo ""
    echo "To start the service:"
    echo "  sudo systemctl start stealthlink-telegram"
    echo "  sudo systemctl enable stealthlink-telegram"
    echo ""
    echo "To view logs:"
    echo "  sudo journalctl -u stealthlink-telegram -f"
}

# Test configuration
test_config() {
    log_info "Testing configuration..."

    if ! load_config; then
        exit 1
    fi

    log_info "Sending test message..."
    if send_message "🧪 <b>Test Message</b>\n\nStealthLink Telegram bot is working!\n\n$(generate_status_report)"; then
        log_info "Test successful!"
    else
        log_error "Test failed!"
        exit 1
    fi
}

# Main
main() {
    local command="${1:-daemon}"

    case "$command" in
        setup)
            setup_wizard
            ;;
        install-service)
            install_service
            ;;
        test)
            test_config
            ;;
        daemon|start)
            if ! load_config; then
                log_error "Failed to load configuration. Run: $0 setup"
                exit 1
            fi
            daemon_loop
            ;;
        *)
            echo "Usage: $0 {setup|install-service|test|daemon}"
            echo ""
            echo "Commands:"
            echo "  setup           - Interactive setup wizard"
            echo "  install-service - Install systemd service"
            echo "  test            - Test configuration and send test message"
            echo "  daemon          - Run monitoring daemon (default)"
            exit 1
            ;;
    esac
}

main "$@"
