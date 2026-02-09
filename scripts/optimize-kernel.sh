#!/bin/bash
#
# StealthLink Kernel Optimization Script
# Based on VPS-Optimizer techniques for high-performance tunneling
#
# This script optimizes kernel parameters for:
# - BBR/BBRv3 congestion control
# - Buffer size tuning
# - TCP Fast Open
# - ECN enablement
# - Queueing algorithms (FQ-CoDel/CAKE)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    log_info "Detected OS: $OS $VER"
}

# Backup current sysctl config
backup_sysctl() {
    local backup_file="/etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S)"
    if [[ -f /etc/sysctl.conf ]]; then
        cp /etc/sysctl.conf "$backup_file"
        log_success "Backup created: $backup_file"
    fi
}

# Enable BBR congestion control
enable_bbr() {
    log_info "Configuring BBR congestion control..."

    # Check if BBR is available
    if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "bbr"; then
        log_warn "BBR not available in kernel. Loading tcp_bbr module..."
        modprobe tcp_bbr 2>/dev/null || true
    fi

    # Apply BBR settings
    cat >> /etc/sysctl.conf << 'EOF'

# BBR Congestion Control
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc=fq
EOF

    # Apply immediately
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null || log_warn "Failed to set BBR (may require newer kernel)"
    sysctl -w net.core.default_qdisc=fq 2>/dev/null || true

    log_success "BBR configuration applied"
}

# Enable BBRv3 (requires XanMod kernel)
enable_bbr3() {
    log_info "Checking for BBRv3 support..."

    # Check if running XanMod kernel
    if uname -r | grep -qi "xanmod"; then
        log_info "XanMod kernel detected, BBRv3 available"

        cat >> /etc/sysctl.conf << 'EOF'

# BBRv3 Congestion Control (XanMod)
net.ipv4.tcp_congestion_control=bbr3
net.core.default_qdisc=fq
EOF
        sysctl -w net.ipv4.tcp_congestion_control=bbr3 2>/dev/null || log_warn "BBRv3 not available, falling back to BBR"
        log_success "BBRv3 configuration applied"
    else
        log_warn "BBRv3 requires XanMod kernel. Using standard BBR."
        enable_bbr
    fi
}

# Optimize buffer sizes
optimize_buffers() {
    log_info "Optimizing buffer sizes..."

    cat >> /etc/sysctl.conf << 'EOF'

# Buffer Size Optimization
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.core.rmem_default=262144
net.core.wmem_default=262144
net.core.netdev_max_backlog=65536
net.ipv4.tcp_rmem=4096 262144 33554432
net.ipv4.tcp_wmem=4096 262144 33554432
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
EOF

    # Apply immediately
    sysctl -w net.core.rmem_max=33554432
    sysctl -w net.core.wmem_max=33554432
    sysctl -w net.core.netdev_max_backlog=65536
    sysctl -w net.ipv4.tcp_rmem="4096 262144 33554432"
    sysctl -w net.ipv4.tcp_wmem="4096 262144 33554432"

    log_success "Buffer sizes optimized"
}

# Enable TCP Fast Open
enable_fastopen() {
    log_info "Enabling TCP Fast Open..."

    cat >> /etc/sysctl.conf << 'EOF'

# TCP Fast Open
net.ipv4.tcp_fastopen=3
EOF

    sysctl -w net.ipv4.tcp_fastopen=3 2>/dev/null || log_warn "TCP Fast Open not supported"
    log_success "TCP Fast Open enabled"
}

# Enable ECN
enable_ecn() {
    log_info "Configuring ECN (Explicit Congestion Notification)..."

    cat >> /etc/sysctl.conf << 'EOF'

# ECN Configuration
net.ipv4.tcp_ecn=1
EOF

    sysctl -w net.ipv4.tcp_ecn=1 2>/dev/null || log_warn "ECN configuration failed"
    log_success "ECN enabled"
}

# Configure queueing algorithm
configure_qdisc() {
    local qdisc=${1:-fq}
    log_info "Configuring queueing algorithm: $qdisc"

    case $qdisc in
        fq)
            cat >> /etc/sysctl.conf << 'EOF'

# Queueing Algorithm - FQ (Fair Queue)
net.core.default_qdisc=fq
EOF
            ;;
        fq_codel)
            cat >> /etc/sysctl.conf << 'EOF'

# Queueing Algorithm - FQ-CoDel
net.core.default_qdisc=fq_codel
EOF
            ;;
        cake)
            cat >> /etc/sysctl.conf << 'EOF'

# Queueing Algorithm - CAKE
net.core.default_qdisc=cake
EOF
            log_warn "CAKE requires kernel support. Install linux-modules-extra if needed."
            ;;
        *)
            log_warn "Unknown queueing algorithm: $qdisc. Using fq."
            cat >> /etc/sysctl.conf << 'EOF'

# Queueing Algorithm - FQ
net.core.default_qdisc=fq
EOF
            ;;
    esac

    sysctl -w net.core.default_qdisc=$qdisc 2>/dev/null || log_warn "Failed to set queueing algorithm"
    log_success "Queueing algorithm configured"
}

# Additional TCP optimizations
optimize_tcp() {
    log_info "Applying additional TCP optimizations..."

    cat >> /etc/sysctl.conf << 'EOF'

# TCP Optimizations
net.ipv4.tcp_notsent_lowat=16384
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets=5000
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_moderate_rcvbuf=1
net.ipv4.tcp_slow_start_after_idle=0
EOF

    # Apply immediately
    sysctl -w net.ipv4.tcp_notsent_lowat=16384
    sysctl -w net.ipv4.tcp_tw_reuse=1
    sysctl -w net.ipv4.tcp_max_syn_backlog=8192
    sysctl -w net.ipv4.tcp_mtu_probing=1
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0

    log_success "TCP optimizations applied"
}

# Optimize for high connection counts
optimize_connections() {
    log_info "Optimizing for high connection counts..."

    cat >> /etc/sysctl.conf << 'EOF'

# Connection Limits
net.core.somaxconn=65535
net.core.netdev_max_backlog=65536
net.ipv4.tcp_max_syn_backlog=65536
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=15
fs.file-max=2097152
fs.nr_open=2097152
EOF

    # Increase system limits
    cat >> /etc/security/limits.conf << 'EOF'

# StealthLink Limits
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
EOF

    # Apply immediately
    sysctl -w net.core.somaxconn=65535
    sysctl -w fs.file-max=2097152

    log_success "Connection optimizations applied"
}

# Memory optimizations
optimize_memory() {
    log_info "Applying memory optimizations..."

    cat >> /etc/sysctl.conf << 'EOF'

# Memory Optimizations
vm.swappiness=10
vm.dirty_ratio=40
vm.dirty_background_ratio=10
vm.vfs_cache_pressure=50
EOF

    sysctl -w vm.swappiness=10 2>/dev/null || true
    log_success "Memory optimizations applied"
}

# Install XanMod kernel (optional)
install_xanmod() {
    log_info "XanMod kernel installation..."
    log_warn "This will install a new kernel. Reboot required after installation."

    read -p "Install XanMod kernel? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Skipping XanMod installation"
        return
    fi

    if [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y wget gnupg
        wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
        echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' > /etc/apt/sources.list.d/xanmod-release.list
        apt-get update
        apt-get install -y linux-xanmod-x64v3
    elif [[ -f /etc/redhat-release ]]; then
        # RHEL/CentOS/Fedora
        log_warn "XanMod installation for RHEL-based systems requires manual steps"
        log_info "Visit: https://xanmod.org/#install_via_akmods"
    else
        log_warn "Unsupported distribution for XanMod installation"
    fi
}

# Create systemd service optimization
create_service_optimizations() {
    log_info "Creating service optimizations..."

    mkdir -p /etc/systemd/system/stealthlink.service.d/

    cat > /etc/systemd/system/stealthlink.service.d/limits.conf << 'EOF'
[Service]
LimitNOFILE=1048576
LimitNPROC=1048576
LimitMEMLOCK=infinity
EOF

    systemctl daemon-reload 2>/dev/null || true
    log_success "Service optimizations created"
}

# Display current settings
show_current() {
    log_info "Current TCP congestion control:"
    sysctl net.ipv4.tcp_congestion_control 2>/dev/null || true

    log_info "Current queueing algorithm:"
    sysctl net.core.default_qdisc 2>/dev/null || true

    log_info "Current buffer sizes:"
    sysctl net.core.rmem_max 2>/dev/null || true
    sysctl net.core.wmem_max 2>/dev/null || true
}

# Verify optimizations
verify() {
    log_info "Verifying optimizations..."

    local errors=0

    # Check BBR
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        log_success "BBR is active"
    else
        log_warn "BBR is not active"
        errors=$((errors + 1))
    fi

    # Check buffer sizes
    local rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "0")
    if [[ "$rmem_max" -ge 33554432 ]]; then
        log_success "Buffer sizes optimized"
    else
        log_warn "Buffer sizes may not be optimal: rmem_max=$rmem_max"
        errors=$((errors + 1))
    fi

    if [[ $errors -eq 0 ]]; then
        log_success "All optimizations verified successfully"
    else
        log_warn "Some optimizations could not be verified. A reboot may be required."
    fi
}

# Main function
main() {
    local mode=${1:-standard}
    local qdisc=${2:-fq}

    echo "========================================"
    echo "  StealthLink Kernel Optimization"
    echo "========================================"
    echo

    check_root
    detect_os
    backup_sysctl

    case $mode in
        standard)
            log_info "Running standard optimizations..."
            enable_bbr
            optimize_buffers
            enable_fastopen
            enable_ecn
            configure_qdisc "$qdisc"
            optimize_tcp
            optimize_connections
            optimize_memory
            create_service_optimizations
            ;;
        xanmod)
            log_info "Running XanMod optimizations..."
            install_xanmod
            enable_bbr3
            optimize_buffers
            enable_fastopen
            enable_ecn
            configure_qdisc "$qdisc"
            optimize_tcp
            optimize_connections
            optimize_memory
            create_service_optimizations
            ;;
        minimal)
            log_info "Running minimal optimizations..."
            enable_bbr
            optimize_buffers
            enable_fastopen
            ;;
        verify)
            show_current
            verify
            exit 0
            ;;
        *)
            echo "Usage: $0 [standard|xanmod|minimal|verify] [fq|fq_codel|cake]"
            echo
            echo "Modes:"
            echo "  standard  - Full optimization with BBR (default)"
            echo "  xanmod    - Install XanMod kernel with BBRv3"
            echo "  minimal   - Basic optimizations only"
            echo "  verify    - Check current settings"
            echo
            echo "Queueing algorithms:"
            echo "  fq        - Fair Queue (default, recommended with BBR)"
            echo "  fq_codel  - Fair Queue CoDel"
            echo "  cake      - Common Applications Kept Enhanced"
            exit 1
            ;;
    esac

    # Apply all sysctl changes
    log_info "Applying sysctl changes..."
    sysctl -p 2>/dev/null || log_warn "Some sysctl values could not be applied immediately"

    echo
    echo "========================================"
    log_success "Optimization complete!"
    echo "========================================"
    echo
    show_current
    echo
    log_info "Some changes may require a reboot to take full effect."
    log_info "Run '$0 verify' after reboot to confirm settings."
}

main "$@"
