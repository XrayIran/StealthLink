#!/usr/bin/env bash
set -euo pipefail

# ╔═══════════════════════════════════════════════════════════════════════╗
# ║                   StealthLink Installer v1.0.0                        ║
# ║                                                                       ║
# ║  Production-quality installer for StealthLink unified proxy suite    ║
# ║  * Auto-detects OS, architecture, network config                     ║
# ║  * Installs binaries: gateway, agent, tools                          ║
# ║  * Configures systemd/OpenRC/SysVinit services                       ║
# ║  * Sets up iptables, logrotate, capabilities                         ║
# ║  * Provides uninstall mode                                           ║
# ║                                                                       ║
# ║  Usage:                                                              ║
# ║    curl -fsSL <URL>/stealthlink-install.sh | sudo bash               ║
# ║    sudo bash stealthlink-install.sh                                  ║
# ║    sudo bash stealthlink-install.sh --uninstall                      ║
# ║    sudo bash stealthlink-install.sh --role=gateway --version=1.2.3   ║
# ╚═══════════════════════════════════════════════════════════════════════╝

#═══════════════════════════════════════════════════════════════════════════
# Configuration
#═══════════════════════════════════════════════════════════════════════════

STEALTHLINK_VERSION="${STEALTHLINK_VERSION:-1.0.0}"
INSTALL_DIR="${INSTALL_DIR:-/opt/stealthlink}"
GITHUB_REPO="${GITHUB_REPO:-stealthlink/stealthlink}"
CONFIG_DIR="${CONFIG_DIR:-${INSTALL_DIR}}"
LOG_DIR="/var/log/stealthlink"
SERVICE_NAME="stealthlink"
ROLE="gateway"  # gateway|agent - can be overridden via --role=

# Download settings
DOWNLOAD_RETRIES=3
DOWNLOAD_TIMEOUT=300

#═══════════════════════════════════════════════════════════════════════════
# Colors for output
#═══════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

#═══════════════════════════════════════════════════════════════════════════
# Logging Functions
#═══════════════════════════════════════════════════════════════════════════

print_header() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║           StealthLink Installer v${STEALTHLINK_VERSION}                     ║"
    echo "║    Unified QUIC Superset Protocol - Bypass Everything         ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "${MAGENTA}[===>]${NC} ${BOLD}$1${NC}"
}

#═══════════════════════════════════════════════════════════════════════════
# Utility Functions
#═══════════════════════════════════════════════════════════════════════════

check_root() {
    if [ "${EUID}" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
    log_success "Root privileges confirmed"
}

detect_os() {
    log_step "Detecting operating system"

    OS="unknown"
    OS_VERSION="unknown"
    OS_FAMILY="unknown"
    HAS_SYSTEMD=false
    PKG_MANAGER="unknown"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS="${ID}"
        OS_VERSION="${VERSION_ID:-unknown}"
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
    elif [ -f /etc/alpine-release ]; then
        OS="alpine"
    elif [ -f /etc/arch-release ]; then
        OS="arch"
    elif [ -f /etc/SuSE-release ] || [ -f /etc/SUSE-brand ]; then
        OS="opensuse"
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi

    case "${OS}" in
        ubuntu|debian|linuxmint|pop|elementary|zorin|kali|raspbian)
            OS_FAMILY="debian"
            PKG_MANAGER="apt"
            ;;
        rhel|centos|fedora|rocky|almalinux|oracle|amazon|amzn)
            OS_FAMILY="rhel"
            if command -v dnf &>/dev/null; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi
            ;;
        arch|manjaro|endeavouros|garuda)
            OS_FAMILY="arch"
            PKG_MANAGER="pacman"
            ;;
        opensuse|opensuse-leap|opensuse-tumbleweed|sles)
            OS_FAMILY="suse"
            PKG_MANAGER="zypper"
            ;;
        alpine)
            OS_FAMILY="alpine"
            PKG_MANAGER="apk"
            ;;
        *)
            log_error "Unsupported OS: ${OS}"
            exit 1
            ;;
    esac

    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        HAS_SYSTEMD=true
    fi

    log_success "Detected: ${OS} ${OS_VERSION} (${OS_FAMILY} family)"
    log_info "Package manager: ${PKG_MANAGER}"
    log_info "Systemd available: ${HAS_SYSTEMD}"
}

detect_arch() {
    log_step "Detecting system architecture"

    local machine_arch
    machine_arch=$(uname -m)

    case "${machine_arch}" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armv7)
            ARCH="arm32"
            ;;
        *)
            log_error "Unsupported architecture: ${machine_arch}"
            log_error "Supported: x86_64, aarch64, armv7l"
            exit 1
            ;;
    esac

    log_success "Architecture: ${machine_arch} -> ${ARCH}"
}

install_package() {
    local package="$1"
    local package_alt="${2:-}"

    log_info "Installing ${package}..."

    case "${PKG_MANAGER}" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq 2>/dev/null || log_warn "apt-get update failed, continuing..."
            if apt-get install -y -qq "${package}" 2>/dev/null; then
                log_success "${package} installed"
                return 0
            elif [ -n "${package_alt}" ] && apt-get install -y -qq "${package_alt}" 2>/dev/null; then
                log_success "${package_alt} installed (alternative)"
                return 0
            else
                return 1
            fi
            ;;
        dnf)
            if dnf install -y -q "${package}" 2>/dev/null; then
                log_success "${package} installed"
                return 0
            elif [ -n "${package_alt}" ] && dnf install -y -q "${package_alt}" 2>/dev/null; then
                log_success "${package_alt} installed (alternative)"
                return 0
            else
                return 1
            fi
            ;;
        yum)
            if yum install -y -q "${package}" 2>/dev/null; then
                log_success "${package} installed"
                return 0
            elif [ -n "${package_alt}" ] && yum install -y -q "${package_alt}" 2>/dev/null; then
                log_success "${package_alt} installed (alternative)"
                return 0
            else
                return 1
            fi
            ;;
        pacman)
            if pacman -Sy --noconfirm --needed "${package}" 2>/dev/null; then
                log_success "${package} installed"
                return 0
            elif [ -n "${package_alt}" ] && pacman -Sy --noconfirm --needed "${package_alt}" 2>/dev/null; then
                log_success "${package_alt} installed (alternative)"
                return 0
            else
                return 1
            fi
            ;;
        zypper)
            if zypper install -y -n "${package}" 2>/dev/null; then
                log_success "${package} installed"
                return 0
            elif [ -n "${package_alt}" ] && zypper install -y -n "${package_alt}" 2>/dev/null; then
                log_success "${package_alt} installed (alternative)"
                return 0
            else
                return 1
            fi
            ;;
        apk)
            if apk add --no-cache "${package}" 2>/dev/null; then
                log_success "${package} installed"
                return 0
            elif [ -n "${package_alt}" ] && apk add --no-cache "${package_alt}" 2>/dev/null; then
                log_success "${package_alt} installed (alternative)"
                return 0
            else
                return 1
            fi
            ;;
        *)
            log_error "Unknown package manager: ${PKG_MANAGER}"
            return 1
            ;;
    esac
}

install_deps() {
    log_step "Installing dependencies"

    local base_packages=()
    local libpcap_package=""

    case "${OS_FAMILY}" in
        debian)
            base_packages=(bash curl tar ca-certificates iproute2 iptables)
            libpcap_package="libpcap-dev"
            ;;
        rhel)
            base_packages=(bash curl tar ca-certificates iproute iptables)
            libpcap_package="libpcap-devel"
            ;;
        arch)
            base_packages=(bash curl tar ca-certificates iproute2 iptables)
            libpcap_package="libpcap"
            ;;
        suse)
            base_packages=(bash curl tar ca-certificates iproute2 iptables)
            libpcap_package="libpcap-devel"
            ;;
        alpine)
            base_packages=(bash curl tar ca-certificates iproute2 iptables)
            libpcap_package="libpcap"
            ;;
    esac

    for pkg in "${base_packages[@]}"; do
        if ! command -v "${pkg}" &>/dev/null; then
            install_package "${pkg}" || log_warn "Failed to install ${pkg}, continuing..."
        else
            log_info "${pkg} already installed"
        fi
    done

    # Install libpcap (critical for raw socket operations)
    if ! install_package "${libpcap_package}"; then
        log_warn "Failed to install ${libpcap_package} - raw socket carriers may not work"
    fi

    # Optional multi-language toolchain for Phase 5.
    install_package python3 || true
    install_package python3-pip pip || true
    install_package cargo rust || true
    install_package npm nodejs || true

    log_success "Dependencies installed"
}

install_phase5_tooling() {
    log_step "Installing Phase 5 tooling dependencies"

    # Python tools
    if command -v python3 >/dev/null 2>&1 && [ -f "${INSTALL_DIR}/tools/requirements.txt" ]; then
        if command -v pip3 >/dev/null 2>&1; then
            pip3 install -r "${INSTALL_DIR}/tools/requirements.txt" >/dev/null 2>&1 || log_warn "Python dependencies install failed"
        fi
    fi

    # Rust crypto build
    if command -v cargo >/dev/null 2>&1 && [ -d "${INSTALL_DIR}/rust/stealthlink-crypto" ]; then
        (cd "${INSTALL_DIR}/rust/stealthlink-crypto" && cargo build --release) || log_warn "Rust crypto build failed"
    else
        log_warn "cargo not found; skipping Rust crypto build"
    fi

    # Dashboard build
    if command -v npm >/dev/null 2>&1 && [ -f "${INSTALL_DIR}/dashboard/package.json" ]; then
        (cd "${INSTALL_DIR}/dashboard" && npm install && npm run build) || log_warn "Dashboard build failed"
    else
        log_warn "npm not found; skipping dashboard build"
    fi
}

detect_network() {
    log_step "Detecting network configuration"

    DEFAULT_INTERFACE=""
    DEFAULT_IP=""
    DEFAULT_GATEWAY=""
    DEFAULT_ROUTER_MAC=""

    # Get default interface
    if command -v ip &>/dev/null; then
        DEFAULT_INTERFACE=$(ip route show default | awk '/default/ {print $5; exit}')

        if [ -n "${DEFAULT_INTERFACE}" ]; then
            # Get local IP
            DEFAULT_IP=$(ip -4 addr show "${DEFAULT_INTERFACE}" | awk '/inet / {print $2; exit}' | cut -d/ -f1)

            # Get default gateway
            DEFAULT_GATEWAY=$(ip route show default | awk '/default/ {print $3; exit}')

            # Try to get router MAC from ARP table
            if [ -n "${DEFAULT_GATEWAY}" ]; then
                DEFAULT_ROUTER_MAC=$(ip neigh show "${DEFAULT_GATEWAY}" | awk '{print $5; exit}')

                # If not in ARP, try to ping and check again
                if [ -z "${DEFAULT_ROUTER_MAC}" ] || [ "${DEFAULT_ROUTER_MAC}" == "FAILED" ]; then
                    ping -c 1 -W 1 "${DEFAULT_GATEWAY}" &>/dev/null || true
                    sleep 1
                    DEFAULT_ROUTER_MAC=$(ip neigh show "${DEFAULT_GATEWAY}" | awk '{print $5; exit}')
                fi
            fi
        fi
    fi

    log_info "Default interface: ${DEFAULT_INTERFACE:-not detected}"
    log_info "Local IP: ${DEFAULT_IP:-not detected}"
    log_info "Gateway: ${DEFAULT_GATEWAY:-not detected}"
    log_info "Router MAC: ${DEFAULT_ROUTER_MAC:-not detected}"
}

download_binary() {
    log_step "Downloading StealthLink v${STEALTHLINK_VERSION}"

    local download_url="https://github.com/${GITHUB_REPO}/releases/download/v${STEALTHLINK_VERSION}/stealthlink-linux-${ARCH}-v${STEALTHLINK_VERSION}.tar.gz"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    cleanup_download() {
        rm -rf "${tmp_dir}"
    }
    trap cleanup_download EXIT

    log_info "Download URL: ${download_url}"

    local attempt=1
    while [ ${attempt} -le ${DOWNLOAD_RETRIES} ]; do
        log_info "Download attempt ${attempt}/${DOWNLOAD_RETRIES}..."

        if curl -fsSL --max-time "${DOWNLOAD_TIMEOUT}" --retry 2 --retry-delay 5 \
            -o "${tmp_dir}/stealthlink.tar.gz" "${download_url}"; then
            log_success "Download completed"
            break
        else
            if [ ${attempt} -eq ${DOWNLOAD_RETRIES} ]; then
                log_error "Failed to download after ${DOWNLOAD_RETRIES} attempts"
                log_error "URL: ${download_url}"
                exit 1
            fi
            log_warn "Download failed, retrying..."
            attempt=$((attempt + 1))
            sleep 3
        fi
    done

    log_info "Extracting archive..."
    tar -xzf "${tmp_dir}/stealthlink.tar.gz" -C "${tmp_dir}" || {
        log_error "Failed to extract archive"
        exit 1
    }

    log_info "Installing binaries to ${INSTALL_DIR}..."
    mkdir -p "${INSTALL_DIR}"

    # Install binaries
    if [ -f "${tmp_dir}/stealthlink-gateway" ]; then
        install -m 0755 "${tmp_dir}/stealthlink-gateway" "${INSTALL_DIR}/stealthlink-gateway"
        log_success "Installed: stealthlink-gateway"
    fi

    if [ -f "${tmp_dir}/stealthlink-agent" ]; then
        install -m 0755 "${tmp_dir}/stealthlink-agent" "${INSTALL_DIR}/stealthlink-agent"
        log_success "Installed: stealthlink-agent"
    fi

    if [ -f "${tmp_dir}/stealthlink-tools" ]; then
        install -m 0755 "${tmp_dir}/stealthlink-tools" "${INSTALL_DIR}/stealthlink-tools"
        log_success "Installed: stealthlink-tools"
    fi

    # Create symlinks
    log_info "Creating symlinks in /usr/local/bin..."
    ln -sf "${INSTALL_DIR}/stealthlink-gateway" /usr/local/bin/stealthlink-gateway
    ln -sf "${INSTALL_DIR}/stealthlink-agent" /usr/local/bin/stealthlink-agent
    ln -sf "${INSTALL_DIR}/stealthlink-tools" /usr/local/bin/stealthlink-tools

    log_success "Binaries installed and symlinked"
}

sync_local_phase5_assets() {
    log_step "Syncing local Phase 5 assets"
    local script_root
    script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    if [ -d "${script_root}/dashboard" ]; then
        rm -rf "${INSTALL_DIR}/dashboard"
        cp -r "${script_root}/dashboard" "${INSTALL_DIR}/dashboard"
        log_success "Copied dashboard sources"
    fi

    if [ -d "${script_root}/rust/stealthlink-crypto" ]; then
        mkdir -p "${INSTALL_DIR}/rust"
        rm -rf "${INSTALL_DIR}/rust/stealthlink-crypto"
        cp -r "${script_root}/rust/stealthlink-crypto" "${INSTALL_DIR}/rust/stealthlink-crypto"
        log_success "Copied Rust crypto sources"
    fi

    if [ -d "${script_root}/tools" ]; then
        rm -rf "${INSTALL_DIR}/tools"
        cp -r "${script_root}/tools" "${INSTALL_DIR}/tools"
        log_success "Copied Python tools"
    fi
}

setup_config() {
    log_step "Setting up configuration"

    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${LOG_DIR}"

    local config_file="${CONFIG_DIR}/config.yaml"

    if [ -f "${config_file}" ]; then
        log_warn "Configuration already exists at ${config_file}"
        log_info "Backing up to ${config_file}.bak"
        cp "${config_file}" "${config_file}.bak"
    fi

    # Create minimal config based on role
    if [ "${ROLE}" == "gateway" ]; then
        cat > "${config_file}" <<EOF
role: gateway

gateway:
  listen: ":8443"

transport:
  type: rawtcp
  rawtcp:
    interface: "${DEFAULT_INTERFACE:-eth0}"
    ipv4:
      addr: "${DEFAULT_IP:-10.0.0.10}:8443"
      router_mac: "${DEFAULT_ROUTER_MAC:-aa:bb:cc:dd:ee:ff}"
    pcap:
      sockbuf: 8388608
    tcp:
      local_flag: ["PA"]
      remote_flag: ["PA"]

mux:
  max_streams_per_session: 2048
  header_timeout: "10s"

security:
  shared_key: "CHANGE_ME_$(openssl rand -hex 16 2>/dev/null || echo 'random-key-here')"

auth:
  strict: true
  providers:
    - name: "static-main"
      type: "static"
      enabled: true
      static:
        agent_tokens:
          agent-1: "CHANGE_ME_$(openssl rand -hex 16 2>/dev/null || echo 'random-token-here')"

transparent_proxy:
  mode: "off"
  backend: "auto"

metrics:
  listen: "127.0.0.1:9091"

services:
  - name: "ssh"
    protocol: "tcp"
    listen: ":2222"
    max_streams: 256
    allow_cidrs:
      - "0.0.0.0/0"
EOF
    else  # agent
        cat > "${config_file}" <<EOF
role: agent

agent:
  id: "agent-1"
  gateway_addr: "CHANGE_ME_GATEWAY_IP:8443"
  reconnect_backoff: "3s"

transport:
  type: rawtcp
  rawtcp:
    interface: "${DEFAULT_INTERFACE:-eth0}"
    ipv4:
      addr: "${DEFAULT_IP:-192.168.1.100}:0"
      router_mac: "${DEFAULT_ROUTER_MAC:-aa:bb:cc:dd:ee:ff}"
    pcap:
      sockbuf: 4194304
    tcp:
      local_flag: ["PA"]
      remote_flag: ["PA"]

mux:
  max_streams_per_session: 2048
  header_timeout: "10s"

security:
  shared_key: "CHANGE_ME_SAME_AS_GATEWAY"

auth:
  strict: true
  providers:
    - name: "static-main"
      type: "static"
      enabled: true
      static:
        agent_tokens:
          agent-1: "CHANGE_ME_SAME_AS_GATEWAY"

transparent_proxy:
  mode: "off"
  backend: "auto"

metrics:
  listen: "127.0.0.1:9092"

services:
  - name: "ssh"
    protocol: "tcp"
    target: "127.0.0.1:22"
EOF
    fi

    log_success "Configuration created at ${config_file}"
    log_warn "IMPORTANT: Edit ${config_file} and replace CHANGE_ME placeholders!"
}

setup_service() {
    log_step "Setting up service"

    local binary_name="stealthlink-${ROLE}"
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"

    if [ "${HAS_SYSTEMD}" = true ]; then
        log_info "Creating systemd service..."

        cat > "${service_file}" <<EOF
[Unit]
Description=StealthLink ${ROLE}
Documentation=https://github.com/${GITHUB_REPO}
After=network-online.target
Wants=network-online.target
ConditionPathExists=${CONFIG_DIR}/config.yaml

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/${binary_name} --config ${CONFIG_DIR}/config.yaml
Restart=on-failure
RestartSec=10
LimitNOFILE=1048576

# Capabilities for raw sockets and network administration
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${LOG_DIR}
ReadOnlyPaths=${CONFIG_DIR}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=stealthlink

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        log_success "Systemd service created at ${service_file}"
        log_info "Enable with: systemctl enable ${SERVICE_NAME}"
        log_info "Start with: systemctl start ${SERVICE_NAME}"

    elif [ -d /etc/init.d ]; then
        log_info "Creating OpenRC/SysVinit service..."

        cat > "/etc/init.d/${SERVICE_NAME}" <<'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          stealthlink
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: StealthLink proxy
### END INIT INFO

EOF
        cat >> "/etc/init.d/${SERVICE_NAME}" <<EOF
NAME="${SERVICE_NAME}"
DAEMON="${INSTALL_DIR}/${binary_name}"
DAEMON_ARGS="--config ${CONFIG_DIR}/config.yaml"
PIDFILE="/var/run/\${NAME}.pid"

case "\$1" in
    start)
        echo "Starting \${NAME}..."
        start-stop-daemon --start --quiet --pidfile "\${PIDFILE}" --exec "\${DAEMON}" -- \${DAEMON_ARGS} &
        echo \$! > "\${PIDFILE}"
        ;;
    stop)
        echo "Stopping \${NAME}..."
        start-stop-daemon --stop --quiet --pidfile "\${PIDFILE}"
        rm -f "\${PIDFILE}"
        ;;
    restart)
        \$0 stop
        sleep 2
        \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac
exit 0
EOF

        chmod +x "/etc/init.d/${SERVICE_NAME}"

        # Try to enable with update-rc.d or chkconfig
        if command -v update-rc.d &>/dev/null; then
            update-rc.d "${SERVICE_NAME}" defaults 2>/dev/null || true
        elif command -v chkconfig &>/dev/null; then
            chkconfig --add "${SERVICE_NAME}" 2>/dev/null || true
        fi

        log_success "Init script created at /etc/init.d/${SERVICE_NAME}"
        log_info "Start with: service ${SERVICE_NAME} start"
    else
        log_warn "No supported init system found"
        log_info "You'll need to start ${binary_name} manually"
    fi
}

setup_capabilities() {
    log_step "Applying binary capabilities"
    if command -v setcap >/dev/null 2>&1; then
        for bin in "${INSTALL_DIR}/stealthlink-gateway" "${INSTALL_DIR}/stealthlink-agent"; do
            if [ -x "$bin" ]; then
                setcap cap_net_raw,cap_net_admin+ep "$bin" || log_warn "Failed setcap on $bin"
            fi
        done
    else
        log_warn "setcap not found; CAP_NET_RAW/CAP_NET_ADMIN not applied"
    fi
}

deploy_dashboard_assets() {
    log_step "Deploying dashboard assets"
    local dist_dir="${INSTALL_DIR}/dashboard/dist"
    if [ ! -d "$dist_dir" ]; then
        log_warn "Dashboard dist not found; run npm build in ${INSTALL_DIR}/dashboard"
        return
    fi

    mkdir -p /var/www/stealthlink-dashboard
    cp -r "${dist_dir}/." /var/www/stealthlink-dashboard/

    if command -v caddy >/dev/null 2>&1; then
        cat > /etc/caddy/Caddyfile-stealthlink-dashboard <<EOF
:8088 {
    root * /var/www/stealthlink-dashboard
    file_server
}
EOF
        log_success "Dashboard prepared for Caddy on :8088"
    elif command -v nginx >/dev/null 2>&1; then
        cat > /etc/nginx/conf.d/stealthlink-dashboard.conf <<EOF
server {
    listen 8088;
    server_name _;
    root /var/www/stealthlink-dashboard;
    index index.html;
    location / {
        try_files \$uri /index.html;
    }
}
EOF
        log_success "Dashboard prepared for nginx on :8088"
    else
        log_warn "Neither caddy nor nginx found; dashboard files copied only"
    fi
}

setup_logrotate() {
    log_step "Setting up log rotation"

    if [ ! -d /etc/logrotate.d ]; then
        log_warn "logrotate not available, skipping"
        return
    fi

    cat > /etc/logrotate.d/stealthlink <<EOF
${LOG_DIR}/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    missingok
    copytruncate
    maxsize 50M
    create 0640 root root
}
EOF

    log_success "Logrotate configured at /etc/logrotate.d/stealthlink"
}

print_success_info() {
    echo ""
    echo -e "${GREEN}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║          StealthLink Installation Complete!                   ║${NC}"
    echo -e "${GREEN}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Installed Version:${NC} ${STEALTHLINK_VERSION}"
    echo -e "${CYAN}Role:${NC} ${ROLE}"
    echo -e "${CYAN}Install Directory:${NC} ${INSTALL_DIR}"
    echo -e "${CYAN}Config File:${NC} ${CONFIG_DIR}/config.yaml"
    echo -e "${CYAN}Log Directory:${NC} ${LOG_DIR}"
    echo ""
    echo -e "${YELLOW}${BOLD}Next Steps:${NC}"
    echo -e "  ${BOLD}1.${NC} Edit configuration: ${CYAN}nano ${CONFIG_DIR}/config.yaml${NC}"
    echo -e "     ${DIM}Replace all CHANGE_ME placeholders with actual values${NC}"
    echo ""
    if [ "${HAS_SYSTEMD}" = true ]; then
        echo -e "  ${BOLD}2.${NC} Enable service: ${CYAN}systemctl enable ${SERVICE_NAME}${NC}"
        echo -e "  ${BOLD}3.${NC} Start service: ${CYAN}systemctl start ${SERVICE_NAME}${NC}"
        echo -e "  ${BOLD}4.${NC} Check status: ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
        echo -e "  ${BOLD}5.${NC} View logs: ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
    else
        echo -e "  ${BOLD}2.${NC} Start service: ${CYAN}service ${SERVICE_NAME} start${NC}"
        echo -e "  ${BOLD}3.${NC} Check logs: ${CYAN}tail -f ${LOG_DIR}/stealthlink.log${NC}"
    fi
    echo ""
    echo -e "${YELLOW}${BOLD}Available Commands:${NC}"
    echo -e "  ${CYAN}stealthlink-gateway${NC} - Start gateway mode"
    echo -e "  ${CYAN}stealthlink-agent${NC}   - Start agent mode"
    echo -e "  ${CYAN}stealthlink-tools${NC}   - Utility tools"
    echo ""
    echo -e "${DIM}Documentation: https://github.com/${GITHUB_REPO}${NC}"
    echo ""
}

uninstall() {
    log_step "Uninstalling StealthLink"

    echo ""
    echo -e "${YELLOW}${BOLD}WARNING:${NC} This will remove:"
    echo "  - Binaries from ${INSTALL_DIR}"
    echo "  - Configuration from ${CONFIG_DIR}"
    echo "  - Logs from ${LOG_DIR}"
    echo "  - Service files"
    echo "  - Symlinks from /usr/local/bin"
    echo ""
    read -p "Are you sure? (yes/no): " -r
    echo

    if [[ ! "${REPLY}" =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Uninstall cancelled"
        exit 0
    fi

    # Stop and disable service
    if [ "${HAS_SYSTEMD}" = true ]; then
        if systemctl is-active --quiet "${SERVICE_NAME}"; then
            log_info "Stopping service..."
            systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
        fi
        if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
            log_info "Disabling service..."
            systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
        fi
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload 2>/dev/null || true
    else
        if [ -f "/etc/init.d/${SERVICE_NAME}" ]; then
            service "${SERVICE_NAME}" stop 2>/dev/null || true
            if command -v update-rc.d &>/dev/null; then
                update-rc.d -f "${SERVICE_NAME}" remove 2>/dev/null || true
            elif command -v chkconfig &>/dev/null; then
                chkconfig --del "${SERVICE_NAME}" 2>/dev/null || true
            fi
            rm -f "/etc/init.d/${SERVICE_NAME}"
        fi
    fi

    # Remove files
    log_info "Removing binaries..."
    rm -rf "${INSTALL_DIR}"

    log_info "Removing symlinks..."
    rm -f /usr/local/bin/stealthlink-gateway
    rm -f /usr/local/bin/stealthlink-agent
    rm -f /usr/local/bin/stealthlink-tools

    log_info "Removing configuration..."
    rm -rf "${CONFIG_DIR}"

    log_info "Removing logs..."
    rm -rf "${LOG_DIR}"

    log_info "Removing logrotate config..."
    rm -f /etc/logrotate.d/stealthlink

    log_success "StealthLink uninstalled successfully"
    echo ""
}

#═══════════════════════════════════════════════════════════════════════════
# Main
#═══════════════════════════════════════════════════════════════════════════

main() {
    # Parse arguments
    UNINSTALL_MODE=false

    for arg in "$@"; do
        case "${arg}" in
            --uninstall|uninstall|--remove|remove|--purge|purge)
                UNINSTALL_MODE=true
                ;;
            --version=*)
                STEALTHLINK_VERSION="${arg#*=}"
                ;;
            --role=*)
                ROLE="${arg#*=}"
                if [[ ! "${ROLE}" =~ ^(gateway|agent)$ ]]; then
                    log_error "Invalid role: ${ROLE}. Must be 'gateway' or 'agent'"
                    exit 1
                fi
                ;;
            --help|-h)
                print_header
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --role=ROLE         Set role: gateway or agent (default: gateway)"
                echo "  --version=VERSION   Set version to install (default: ${STEALTHLINK_VERSION})"
                echo "  --uninstall         Uninstall StealthLink"
                echo "  --help              Show this help message"
                echo ""
                exit 0
                ;;
            *)
                log_warn "Unknown argument: ${arg}"
                ;;
        esac
    done

    print_header

    check_root
    detect_os
    detect_arch

    if [ "${UNINSTALL_MODE}" = true ]; then
        uninstall
        exit 0
    fi

    detect_network
    install_deps
    download_binary
    sync_local_phase5_assets
    setup_config
    install_phase5_tooling
    setup_service
    setup_capabilities
    deploy_dashboard_assets
    setup_logrotate

    print_success_info
}

# Run main
main "$@"
