# StealthLink Systemd Unit Hardening

## Overview

This document describes the security hardening applied to StealthLink systemd service units following Red Hat best practices and systemd security guidelines.

## Implemented Security Features

### 1. Privilege Restrictions

**NoNewPrivileges=true**
- Prevents the service and its children from gaining new privileges
- Blocks privilege escalation via setuid binaries or file capabilities
- Essential defense-in-depth measure

**User=root**
- Required for TUN/TAP interface creation and raw socket operations
- Capabilities are used to limit what root can do (see Capabilities section)

### 2. File System Isolation

**ProtectSystem=strict**
- Makes /usr, /boot, /efi read-only
- Prevents modification of system binaries and libraries
- Most restrictive protection level

**ProtectHome=true**
- Makes /home, /root, /run/user inaccessible
- Prevents access to user data
- Service has no legitimate need for home directories

**PrivateTmp=true**
- Provides private /tmp and /var/tmp
- Prevents temp file attacks and information leakage
- Isolates temporary files from other services

**ReadWritePaths=/var/log/stealthlink /var/lib/stealthlink /etc/stealthlink**
- Explicitly grants write access only to required directories
- Logs: /var/log/stealthlink
- State: /var/lib/stealthlink
- Config: /etc/stealthlink (for dynamic updates)

**ReadOnlyPaths=/proc/sys/net**
- Allows reading network tunables
- Prevents modification of kernel network parameters
- Required for network stack introspection

### 3. Kernel Protection

**ProtectKernelTunables=true**
- Makes /proc/sys, /sys read-only
- Prevents modification of kernel parameters
- Blocks kernel tuning attacks

**ProtectKernelModules=true**
- Prevents loading/unloading kernel modules
- Blocks kernel module injection attacks
- Service has no legitimate need for module management

**ProtectControlGroups=true**
- Makes cgroup filesystem read-only
- Prevents cgroup manipulation
- Blocks resource limit bypass attempts

### 4. System Call Restrictions

**RestrictRealtime=true**
- Prevents realtime scheduling
- Blocks realtime priority escalation
- Service doesn't require realtime scheduling

**RestrictNamespaces=false**
- Allows namespace creation
- **Required** for TUN/TAP interface creation
- TUN/TAP requires network namespace operations

**RestrictSUIDSGID=true**
- Prevents creation of SUID/SGID files
- Blocks privilege escalation via file permissions
- Service has no legitimate need to create privileged files

**LockPersonality=true**
- Prevents personality changes
- Blocks execution domain switching
- Prevents compatibility mode exploits

**SystemCallArchitectures=native**
- Restricts to native architecture syscalls
- Prevents cross-architecture syscall exploits
- Blocks 32-bit syscalls on 64-bit systems

### 5. Memory Protection

**MemoryDenyWriteExecute=false**
- Allows W^X (write XOR execute) violations
- **Required** for some cryptographic operations
- JIT compilation and dynamic code generation need this
- Note: Set to false because crypto libraries may need it

### 6. Capabilities

StealthLink requires specific Linux capabilities for network operations:

**CAP_NET_ADMIN**
- Create and configure TUN/TAP interfaces
- Modify routing tables
- Configure network interfaces
- Required for all StealthLink modes

**CAP_NET_RAW**
- Create raw sockets
- Send/receive raw packets
- Required for FakeTCP mode (Mode 4b)
- Required for ICMP operations

**CAP_NET_BIND_SERVICE**
- Bind to privileged ports (<1024)
- Required for standard service ports (443, 80, etc.)
- Optional but commonly needed

**Implementation:**
```
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
```

- `AmbientCapabilities`: Inherited by child processes
- `CapabilityBoundingSet`: Maximum capabilities the service can acquire

### 7. Configuration Validation

**ExecStartPre=/usr/local/bin/stealthlink-gateway -config /etc/stealthlink/gateway.yaml -validate**

Pre-start validation ensures:
- Configuration file exists and is readable
- YAML syntax is correct
- Required fields are present
- Values are valid for their types
- Mode-specific configuration is valid
- Network configuration is sane

If validation fails:
- Service will not start
- Error is logged to systemd journal
- Administrator can fix config before retry

### 8. Network Dependencies

**After=network-online.target**
- Service starts after network is fully configured
- Ensures network interfaces are available

**Wants=network-online.target**
- Declares dependency on network availability
- systemd will try to bring up network first
- Service can bind to network addresses immediately

### 9. Restart Policy

**Restart=on-failure**
- Automatically restart on abnormal exit
- Does not restart on clean shutdown
- Prevents restart loops on configuration errors

**RestartSec=5s**
- Wait 5 seconds before restart
- Prevents rapid restart loops
- Allows time for transient issues to resolve

### 10. Resource Limits

**LimitNOFILE=65536**
- Maximum open file descriptors
- Required for high connection counts
- Supports thousands of concurrent connections

## Security Analysis

Run systemd security analysis:

```bash
sudo systemd-analyze security stealthlink-gateway
```

Expected results:
- Overall exposure level: Medium (due to root user and capabilities)
- Most security features enabled
- Remaining risks are necessary for functionality

Check for specific issues:

```bash
sudo systemd-analyze security stealthlink-gateway | grep -E "UNSAFE|MEDIUM"
```

## Trade-offs

### Why root user?

StealthLink requires root for:
1. TUN/TAP interface creation (CAP_NET_ADMIN)
2. Raw socket operations (CAP_NET_RAW)
3. Privileged port binding (CAP_NET_BIND_SERVICE)

While capabilities could theoretically allow non-root operation, TUN/TAP creation is deeply integrated with root privileges in the Linux kernel.

### Why MemoryDenyWriteExecute=false?

Some cryptographic libraries (especially JIT-optimized implementations) require the ability to generate executable code at runtime. This is a calculated trade-off for performance.

### Why RestrictNamespaces=false?

TUN/TAP interface creation requires network namespace operations. This is fundamental to StealthLink's operation and cannot be disabled.

## Verification

### Test configuration validation:

```bash
# Should succeed
/usr/local/bin/stealthlink-gateway -config /etc/stealthlink/gateway.yaml -validate

# Should fail with descriptive error
/usr/local/bin/stealthlink-gateway -config /tmp/invalid.yaml -validate
```

### Test service startup:

```bash
# Start service
sudo systemctl start stealthlink-gateway

# Check status
sudo systemctl status stealthlink-gateway

# View logs
sudo journalctl -u stealthlink-gateway -n 50
```

### Test security settings:

```bash
# Verify capabilities
sudo systemctl show stealthlink-gateway | grep -i cap

# Verify file system protection
sudo systemctl show stealthlink-gateway | grep -i protect

# Verify restrictions
sudo systemctl show stealthlink-gateway | grep -i restrict
```

## References

1. [Red Hat systemd Unit File Best Practices](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_basic_system_settings/assembly_working-with-systemd-unit-files_configuring-basic-system-settings)
2. [systemd.exec(5) - Execution environment configuration](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)
3. [systemd.service(5) - Service unit configuration](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
4. [Linux Capabilities man page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
5. [systemd Security Hardening Guide](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Security)

## Maintenance

When updating the service file:

1. Test changes in a non-production environment
2. Run `systemd-analyze security` to check impact
3. Verify all required capabilities are present
4. Test configuration validation
5. Monitor logs for permission errors
6. Document any new security trade-offs

## Future Improvements

Potential enhancements for future versions:

1. **Dynamic User**: Investigate using DynamicUser=true with capability ambient sets
2. **Seccomp Filters**: Add syscall filtering with SystemCallFilter=
3. **AppArmor/SELinux**: Add mandatory access control profiles
4. **Capability Reduction**: Minimize capabilities per mode (e.g., Mode 4a doesn't need CAP_NET_RAW)
5. **Socket Activation**: Use systemd socket activation for zero-downtime restarts
