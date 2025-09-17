# HOMESERVER Vault Management Suite

Professional-grade system administration tools for the HOMESERVER digital sovereignty platform. This suite provides enterprise-level infrastructure management, security hardening, and hardware validation capabilities for on-premise data centers.

## Overview

The Vault Management Suite is designed for system administrators who require complete control over their digital infrastructure. These tools enable secure drive management, encrypted storage, VPN integration, and automated service orchestration - all essential components of a professional digital sovereignty platform.

## Components

### Core System Management

- **`init.sh`** - System initialization and service orchestration
  - Automated drive detection and mounting
  - Service startup and health monitoring
  - Boot-time system validation

- **`mountDrive.sh`** - Advanced drive mounting with systemd integration
  - LUKS encrypted drive support
  - Automatic filesystem detection
  - Systemd service generation for persistent mounts

- **`unmountDrive.sh`** - Safe drive unmounting and cleanup
  - Graceful service shutdown
  - LUKS container closure
  - Process cleanup and cache management

### Security and Encryption

- **`exportNAS.sh`** - Secure key management for encrypted drives
  - Integration with HOMESERVER keyman system
  - Secure password extraction and validation
  - Error handling for key system initialization

- **`closeNAS.sh`** - Forced unmounting and LUKS cleanup
  - Process termination and cache clearing
  - Multiple unmount strategies (standard, lazy, force)
  - Device mapper cleanup

### Network and VPN Integration

- **`transmission.py`** - VPN-isolated Transmission management
  - Network namespace isolation
  - Dynamic port forwarding with PIA VPN
  - Professional-grade error handling and teardown
  - Modular architecture with comprehensive logging

## Features

### Enterprise-Grade Reliability
- Comprehensive error handling and recovery
- Lock file management to prevent concurrent execution
- Detailed logging and debugging capabilities
- Graceful degradation and cleanup procedures

### Security-First Design
- LUKS encryption support for all storage operations
- Network namespace isolation for VPN services
- Secure key management integration
- Process isolation and resource management

### Professional System Integration
- Full systemd service integration
- Automatic service dependency management
- Boot-time initialization support
- Health monitoring and status reporting

## Usage

### Basic Drive Management

```bash
# Mount an encrypted drive
./mountDrive.sh mount /dev/sdb1 /mnt/nas encrypted_sdb1

# Unmount a drive safely
./unmountDrive.sh /dev/sdb1 /mnt/nas encrypted_sdb1
```

### System Initialization

```bash
# Run full system initialization
./init.sh
```

### VPN-Isolated Transmission

```bash
# Start VPN and Transmission with port forwarding
python3 transmission.py 3

# Stop VPN and Transmission services
python3 transmission.py --stop
```

## Architecture

The Vault Management Suite follows enterprise system administration patterns:

- **Modular Design**: Each component handles specific functionality
- **Service Integration**: Full systemd integration for persistent operations
- **Error Recovery**: Comprehensive cleanup and recovery procedures
- **Security Focus**: Encryption and isolation as core principles
- **Professional Logging**: Detailed logging for troubleshooting and auditing

## Legal Notice

These tools are provided for legitimate system administration purposes. Users are responsible for compliance with applicable laws and regulations. The HOMESERVER platform is designed for digital sovereignty and professional infrastructure management.

## Support

For technical support and documentation, visit the [HOMESERVER documentation](https://github.com/homeserversltd) or contact the development team.

## License

This software is provided as part of the HOMESERVER digital sovereignty platform. See individual component headers for specific licensing information.

---

**HOMESERVER LLC** - Professional Digital Sovereignty Solutions
