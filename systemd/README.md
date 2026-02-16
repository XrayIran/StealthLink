# StealthLink Systemd Service Files

This directory contains systemd service unit files for StealthLink components.

## Service Files

- `stealthlink-gateway.service` - Gateway service (server-side)
- `stealthlink-agent.service` - Agent service (client-side)

## Installation

These files are automatically installed by `stealthlink-ctl install` command.

Manual installation:

```bash
# Copy service file
sudo cp stealthlink-gateway.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable stealthlink-gateway

# Start service
sudo systemctl start stealthlink-gateway

# Check status
sudo systemctl status stealthlink-gateway
```

## Configuration

Service files expect:
- Binary: `/usr/local/bin/stealthlink-gateway` or `/usr/local/bin/stealthlink-agent`
- Config: `/etc/stealthlink/gateway.yaml` or `/etc/stealthlink/agent.yaml`
- Log directory: `/var/log/stealthlink`
- Data directory: `/var/lib/stealthlink`

## Security Hardening

The service files include comprehensive security hardening options following Red Hat systemd best practices:

### Basic Hardening
- `NoNewPrivileges=true` - Prevents privilege escalation
- `PrivateTmp=true` - Private /tmp directory
- `ProtectSystem=strict` - Read-only system directories
- `ProtectHome=true` - Inaccessible home directories

### Kernel Protection
- `ProtectKernelTunables=true` - Prevents modification of kernel tunables
- `ProtectKernelModules=true` - Prevents loading/unloading kernel modules
- `ProtectControlGroups=true` - Makes cgroup filesystem read-only

### System Call Restrictions
- `RestrictRealtime=true` - Prevents realtime scheduling
- `RestrictNamespaces=false` - Allows namespace creation (required for TUN)
- `RestrictSUIDSGID=true` - Prevents SUID/SGID file creation
- `LockPersonality=true` - Prevents personality changes
- `SystemCallArchitectures=native` - Restricts to native architecture syscalls

### Memory Protection
- `MemoryDenyWriteExecute=false` - Allows W^X (required for some crypto operations)

### File System Access
- `ReadWritePaths=` - Explicit write access to required directories
- `ReadOnlyPaths=/proc/sys/net` - Read-only access to network tunables

### Capabilities
StealthLink requires specific Linux capabilities for network operations:
- `CAP_NET_ADMIN` - Required for TUN interface creation and configuration
- `CAP_NET_RAW` - Required for raw socket operations (FakeTCP mode)
- `CAP_NET_BIND_SERVICE` - Required for binding to privileged ports (<1024)

These capabilities are set via:
- `AmbientCapabilities=` - Capabilities inherited by child processes
- `CapabilityBoundingSet=` - Maximum set of capabilities the service can acquire

## Configuration Validation

The service includes a pre-start validation step:
```
ExecStartPre=/usr/local/bin/stealthlink-gateway -config /etc/stealthlink/gateway.yaml -validate
```

This ensures the configuration is valid before starting the service. The validation checks:
- YAML syntax correctness
- Required fields presence
- Value type correctness
- Mode-specific configuration validity
- Network configuration sanity

If validation fails, the service will not start and systemd will log the error.

## Network Dependencies

The service depends on network availability:
```
After=network-online.target
Wants=network-online.target
```

This ensures:
- Service starts after network is fully configured
- Service waits for network interfaces to be up
- Service can bind to network addresses immediately

## References

- [Red Hat systemd Unit File Best Practices](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_basic_system_settings/assembly_working-with-systemd-unit-files_configuring-basic-system-settings)
- [systemd.exec(5) - Execution environment configuration](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)
- [systemd.service(5) - Service unit configuration](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [systemd.unit(5) - Unit configuration](https://www.freedesktop.org/software/systemd/man/systemd.unit.html)

## Troubleshooting

View logs:
```bash
# Follow logs in real-time
sudo journalctl -u stealthlink-gateway -f

# View recent logs
sudo journalctl -u stealthlink-gateway -n 100

# View logs since boot
sudo journalctl -u stealthlink-gateway -b
```

Check service status:
```bash
sudo systemctl status stealthlink-gateway
```

Restart service:
```bash
sudo systemctl restart stealthlink-gateway
```

Analyze security settings:
```bash
# Run systemd security analysis
sudo systemd-analyze security stealthlink-gateway

# Check for security issues
sudo systemd-analyze security stealthlink-gateway | grep -E "UNSAFE|MEDIUM"
```
