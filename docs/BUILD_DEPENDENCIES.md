# Build Dependencies

This document specifies the build dependencies for StealthLink.

## Go Version

**Required**: Go 1.25.7 or later

The project uses Go 1.25.7 as specified in `go.mod`. While Go 1.22+ is the minimum for certain features (ChaCha8Rand entropy), Go 1.25.7 is required for full compatibility.

**Verification**:
```bash
go version
# Expected: go version go1.25.7 or later
```

## System Libraries

### Linux

**Required packages**:
- `libpcap-dev` - Required for raw socket operations (rawtcp, faketcp carriers)
- `build-essential` - Standard build tools (gcc, make, etc.)

**Installation** (Debian/Ubuntu):
```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev build-essential
```

**Installation** (RHEL/CentOS/Fedora):
```bash
sudo yum install -y libpcap-devel gcc make
```

### macOS

**Required**:
- Xcode Command Line Tools
- libpcap (included with macOS)

**Installation**:
```bash
xcode-select --install
```

## Kernel Version

**Minimum**: Linux kernel 3.0+
**Recommended**: Linux kernel 5.15+ or 6.x

### Kernel Feature Requirements

| Feature | Minimum Kernel | Notes |
|---------|----------------|-------|
| `sendmmsg` syscall | 3.0 | Batch UDP send operations |
| `recvmmsg` syscall | 2.6.33 | Batch UDP receive operations |
| TUN/TAP devices | 2.4+ | Virtual network interfaces |
| eBPF (optional) | 4.1+ | Advanced packet filtering |
| io_uring (future) | 5.1+ | High-performance async I/O |

**Verification**:
```bash
uname -r
# Expected: 5.15.0 or later for optimal performance
```

### Kernel Configuration

For full functionality, ensure these kernel options are enabled:

```
CONFIG_TUN=y                    # TUN/TAP support
CONFIG_NET_SCH_FQ=y            # Fair Queue packet scheduler
CONFIG_TCP_CONG_BBR=y          # BBR congestion control
CONFIG_NETFILTER=y             # Netfilter support
CONFIG_NETFILTER_XT_TARGET_TPROXY=y  # TPROXY support
```

**Check current kernel config**:
```bash
grep -E "CONFIG_(TUN|NET_SCH_FQ|TCP_CONG_BBR|NETFILTER)" /boot/config-$(uname -r)
```

## Hardware Requirements

### CPU Features (Optional but Recommended)

| Feature | Benefit | Detection |
|---------|---------|-----------|
| AES-NI | Hardware-accelerated encryption | `grep -o aes /proc/cpuinfo` |
| AVX/AVX2 | SIMD acceleration | `grep -o avx /proc/cpuinfo` |
| RDRAND | Hardware RNG | `grep -o rdrand /proc/cpuinfo` |

**Verification**:
```bash
# Check for AES-NI support
lscpu | grep -i aes

# Check all CPU flags
cat /proc/cpuinfo | grep flags | head -1
```

## Build System

**Make**: GNU Make 3.81 or later

**Verification**:
```bash
make --version
```

## Optional Dependencies

### Rust (for rust-crypto module)

**Version**: Rust 1.70+

**Installation**:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Build**:
```bash
make rust-crypto
```

### Node.js (for dashboard)

**Version**: Node.js 18+ and npm 9+

**Installation**:
```bash
# Using nvm (recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 18
nvm use 18
```

**Build**:
```bash
make dashboard-build
```

### Python (for tools)

**Version**: Python 3.8+

**Required packages**:
- Standard library only (no external dependencies for basic tools)

**Verification**:
```bash
python3 --version
make pytools-check
```

## Build Verification

### Quick Build Test

```bash
# Build all Go packages
make build

# Build binaries
make build-binaries

# Run tests
make test

# Run all checks
make check
```

### Full Build Test

```bash
# Build everything including optional components
make rust-crypto
make dashboard-build
make build-binaries
make test
```

## CI/CD Matrix

The project is tested on the following configurations:

| OS | Architecture | Go Version | Kernel |
|----|--------------|------------|--------|
| Ubuntu 22.04 | amd64 | 1.25+ | 5.15+ |
| Ubuntu 22.04 | arm64 | 1.25+ | 5.15+ |
| Ubuntu 24.04 | amd64 | 1.25+ | 6.x |
| Ubuntu 24.04 | arm64 | 1.25+ | 6.x |

### Hardware Feature Matrix

Tests are run with and without:
- AES-NI instructions
- AVX/AVX2 support

## Troubleshooting

### Build Fails with "undefined: syscall.SYS_SENDMMSG"

**Cause**: Kernel too old (< 3.0)

**Solution**: Upgrade kernel or build will automatically fall back to single-packet I/O

### Build Fails with "libpcap not found"

**Cause**: Missing libpcap development headers

**Solution**:
```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# RHEL/CentOS
sudo yum install libpcap-devel
```

### TUN Device Creation Fails

**Cause**: Missing TUN kernel module

**Solution**:
```bash
# Load TUN module
sudo modprobe tun

# Verify
lsmod | grep tun

# Make persistent
echo "tun" | sudo tee -a /etc/modules
```

## References

- [Go Installation Guide](https://go.dev/doc/install)
- [Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/)
- [sendmmsg(2) man page](https://man7.org/linux/man-pages/man2/sendmmsg.2.html)
- [recvmmsg(2) man page](https://man7.org/linux/man-pages/man2/recvmmsg.2.html)
- [TUN/TAP Documentation](https://www.kernel.org/doc/Documentation/networking/tuntap.txt)
