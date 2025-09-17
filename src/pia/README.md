# PIA VPN Integration Module for HOMESERVER

## Overview

The PIA VPN Integration Module provides a complete Python-based replacement for the legacy bash script VPN system in HOMESERVER. This module offers professional-grade VPN management with comprehensive error handling, real API integration, and seamless integration with existing HOMESERVER infrastructure.

## Architecture Overview

The module is organized into several specialized components that work together to provide a complete VPN solution:

```
PIA VPN Integration Module
├── api_client.py      # Core API communication with PIA services
├── auth.py           # Authentication, token management, and credentials
├── regions.py        # Server discovery, latency testing, and selection
├── wireguard.py      # WireGuard protocol implementation and management
├── openvpn.py        # OpenVPN protocol implementation and management
├── portforward.py    # Port forwarding management with keepalive
├── integration.py    # Main integration layer and compatibility bridge
└── __init__.py       # Module exports and version information
```

## General Flow

### 1. Authentication Flow
```
Credentials → Token Generation → Session Management → API Access
```

### 2. Server Selection Flow
```
API Server List → Region Filtering → Latency Testing → Optimal Server Selection
```

### 3. Connection Flow
```
Server Selection → Protocol Setup → Interface Creation → Connection Establishment
```

### 4. Port Forwarding Flow
```
Connection → Signature Acquisition → Port Binding → Keepalive Process
```

## Core Components

### API Client (`api_client.py`)
- **Purpose**: Handles all HTTP communication with PIA services
- **Features**: Retry logic, SSL verification, comprehensive error handling
- **Key Methods**: `generate_token()`, `wireguard_add_key()`, `get_port_signature()`

### Authentication (`auth.py`)
- **Purpose**: Manages PIA credentials, tokens, and dedicated IP handling
- **Features**: Encrypted credential storage, automatic token renewal, session management
- **Key Classes**: `CredentialManager`, `PiaTokenGenerator`, `DedicatedIpHandler`, `SessionManager`

### Server Selection (`regions.py`)
- **Purpose**: Discovers and selects optimal PIA servers
- **Features**: Real-time latency testing, port forwarding filtering, region validation
- **Key Classes**: `ServerSelector`, `LatencyTester`

### Protocol Managers
- **WireGuard** (`wireguard.py`): Modern, fast VPN protocol with key management
- **OpenVPN** (`openvpn.py`): Traditional VPN protocol with process management

### Port Forwarding (`portforward.py`)
- **Purpose**: Manages PIA port forwarding with automatic keepalive
- **Features**: Background refresh, expiration handling, status monitoring

## Integration Interface

The main entry point for integrating with the PIA VPN system is through the `PiaVpnIntegrator` class in `integration.py`. This class provides a drop-in replacement for existing VPN functionality.

### Basic Usage Example

```python
from initialization.files.vault.scripts.setup.pia.integration import PiaVpnIntegrator

# Initialize the integrator
integrator = PiaVpnIntegrator()

# Connect to VPN
credentials = {
    "pia": {
        "username": "p1234567",
        "password": "your_password"
    }
}

# Establish VPN connection
vpn_port = integrator.connect_vpn_replacement(
    credentials=credentials,
    protocol="wireguard",  # or "openvpn_udp_standard"
    enable_port_forwarding=True
)

if vpn_port:
    print(f"VPN connected successfully on port {vpn_port}")
else:
    print("VPN connection failed")
```

### Advanced Usage with Dedicated IP

```python
# Connect with dedicated IP token
vpn_port = integrator.connect_vpn_replacement(
    credentials=credentials,
    protocol="wireguard",
    enable_port_forwarding=True,
    dip_token="DIP123456789012345678901234567890"
)
```

### Protocol-Specific Examples

#### WireGuard Connection
```python
# WireGuard with custom settings
connection_result = integrator._connect_wireguard(
    token="your_token",
    server_info={
        'ip': '1.2.3.4',
        'hostname': 'server.pia.com',
        'port_forward': True
    },
    dip_token=None,
    namespace="vpn",
    dns_servers=["10.0.0.242"],
    use_pia_dns=True
)
```

#### OpenVPN Connection
```python
# OpenVPN with specific transport and encryption
connection_result = integrator._connect_openvpn(
    token="your_token",
    server_info={
        'ip': '1.2.3.4',
        'hostname': 'server.pia.com',
        'servers': {
            'ovpnudp': [{'ip': '1.2.3.4', 'cn': 'server.pia.com'}]
        }
    },
    protocol="openvpn_udp_strong",  # udp + strong encryption
    dip_token=None,
    namespace="vpn",
    dns_servers=["10.0.0.242"],
    use_pia_dns=True
)
```

### Server Selection Examples

```python
# Get optimal server with port forwarding
server_info = integrator._select_optimal_server(
    token="your_token",
    require_port_forwarding=True
)

# Test server latencies
from initialization.files.vault.scripts.setup.pia.regions import LatencyTester
latency_tester = LatencyTester()
fastest_server = latency_tester.find_fastest_server(
    servers=[server_info],
    max_latency=0.1  # 100ms max
)
```

### Port Forwarding Examples

```python
# Setup port forwarding
vpn_port = integrator._setup_port_forwarding(
    token="your_token",
    server_info=server_info,
    connection_result=connection_result
)

# Manual port forwarding management
from initialization.files.vault.scripts.setup.pia.portforward import PortForwardManager
pf_manager = PortForwardManager()

# Get and bind port
port = pf_manager.get_and_bind_port(
    pf_hostname="server.pia.com",
    pf_gateway="1.2.3.4",
    token="your_token"
)

# Start keepalive process
if pf_manager.payload and pf_manager.signature:
    pf_manager.start_keepalive(
        pf_hostname="server.pia.com",
        pf_gateway="1.2.3.4",
        payload=pf_manager.payload,
        signature=pf_manager.signature
    )
```

### Authentication Examples

```python
# Complete authentication flow
from initialization.files.vault.scripts.setup.pia.auth import SessionManager
session_manager = SessionManager()

# Authenticate and get token
auth_result = session_manager.authenticate(
    username="p1234567",
    password="your_password",
    dip_token="DIP123456789012345678901234567890"  # Optional
)

token = auth_result['token']
dedicated_ip = auth_result.get('dedicated_ip')

# Check token validity
if session_manager.refresh_token_if_needed():
    print("Token is valid")
else:
    print("Token needs refresh")
```

### Error Handling Examples

```python
from initialization.files.vault.scripts.setup.pia.api_client import (
    ApiError, ConnectionError, AuthenticationError
)

try:
    vpn_port = integrator.connect_vpn_replacement(credentials, "wireguard")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
    # Handle invalid credentials
except ConnectionError as e:
    print(f"Network error: {e}")
    # Handle network issues
except ApiError as e:
    print(f"API error: {e}")
    # Handle PIA service issues
except Exception as e:
    print(f"Unexpected error: {e}")
    # Handle other errors
```

## Integration with Existing HOMESERVER Code

### Replacing Existing VPN Calls

**Before (bash script calls):**
```python
# Old way - calling bash scripts
subprocess.run(["./connect_to_wireguard_with_token.sh", server_ip, token])
```

**After (Python integration):**
```python
# New way - using Python integration
from initialization.files.vault.scripts.setup.pia.integration import get_pia_integrator

integrator = get_pia_integrator()
connection_result = integrator._connect_wireguard(token, server_info)
```

### Drop-in Replacement Functions

The module provides several drop-in replacement functions for easy migration:

```python
# These functions can replace existing VPN calls
from initialization.files.vault.scripts.setup.pia.integration import (
    pia_connect_vpn,
    pia_cleanup_vpn,
    pia_get_status
)

# Replace connect_vpn() calls
vpn_port = pia_connect_vpn(credentials, protocol="wireguard")

# Replace cleanup calls
pia_cleanup_vpn()

# Replace status checks
status = pia_get_status()
```

## Configuration and Customization

### Environment Variables

```bash
# Optional: Set custom working directories
export PIA_WORK_DIR="/opt/piavpn-manual"
export PIA_WIREGUARD_DIR="/etc/wireguard"
```

### Custom API Client Configuration

```python
from initialization.files.vault.scripts.setup.pia.api_client import PiaApiClient

# Custom timeout and retry settings
api_client = PiaApiClient(
    timeout=60,  # 60 second timeout
    ca_cert_path="/path/to/custom/ca.crt"
)
```

### Custom Server Selection Criteria

```python
from initialization.files.vault.scripts.setup.pia.regions import ServerSelector

selector = ServerSelector()

# Custom server filtering
servers = selector.get_available_servers(
    token="your_token",
    port_forward_required=True,
    max_latency=0.05,  # 50ms max latency
    preferred_region="ca_toronto"  # Specific region
)
```

## Monitoring and Status

### Connection Status Monitoring

```python
# Get comprehensive connection status
status = integrator.get_connection_status()

if status['connected']:
    print(f"VPN connected via {status['protocol']}")
    print(f"Server: {status['server_ip']}")
    if status['port_forwarding']:
        print(f"Port forwarding active on port {status['assigned_port']}")
else:
    print("VPN not connected")
```

### Port Forwarding Status

```python
from initialization.files.vault.scripts.setup.pia.portforward import PortForwardManager

pf_manager = PortForwardManager()
pf_status = pf_manager.get_status()

if pf_status['active']:
    print(f"Port forwarding active on port {pf_status['port']}")
    print(f"Keepalive: {'Active' if pf_status['keepalive_active'] else 'Inactive'}")
    if pf_status['expires_at']:
        print(f"Expires at: {pf_status['expires_at']}")
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Authentication Failures
```python
# Check credential format
from initialization.files.vault.scripts.setup.pia.auth import PiaTokenGenerator

token_gen = PiaTokenGenerator()
if not token_gen.validate_credentials("p1234567", "password"):
    print("Invalid credential format")
```

#### 2. Server Selection Issues
```python
# Force server list refresh
from initialization.files.vault.scripts.setup.pia.regions import ServerSelector

selector = ServerSelector()
servers = selector.get_server_list(force_refresh=True)
```

#### 3. Connection Failures
```python
# Check interface conflicts
from initialization.files.vault.scripts.setup.pia.wireguard import WireGuardManager

wg_manager = WireGuardManager()
status = wg_manager.get_status()
print(f"Interface exists: {status['interface_exists']}")
```

#### 4. Port Forwarding Issues
```python
# Check port expiration
from initialization.files.vault.scripts.setup.pia.portforward import PortForwardManager

pf_manager = PortForwardManager()
if pf_manager.is_port_expired():
    print("Port has expired, need to refresh")
```

## Performance Considerations

### Latency Testing
- Multi-threaded latency testing for faster server selection
- Configurable timeout values (default: 100ms)
- Caching of server lists (5-minute TTL)

### Connection Management
- Automatic cleanup of stale connections
- Resource cleanup on failures
- Efficient process management

### Memory Usage
- Minimal memory footprint for long-running connections
- Automatic cleanup of temporary files
- Efficient threading for keepalive processes

## Security Features

### Credential Management
- Encrypted storage of sensitive data
- Automatic cleanup of credentials
- Secure file permissions (600 for credential files)

### Network Isolation
- Network namespace support for VPN connections
- Isolated DNS configuration
- Secure key generation and management

### API Security
- SSL certificate validation with PIA CA
- Token-based authentication
- Secure key exchange protocols

## Migration Guide

### From Bash Scripts to Python

1. **Replace script calls** with Python function calls
2. **Update credential handling** to use the new credential manager
3. **Modify error handling** to catch Python exceptions
4. **Update status checking** to use the new status methods

### Example Migration

**Before:**
```bash
#!/bin/bash
./get_token.sh "$USERNAME" "$PASSWORD"
TOKEN=$(cat /opt/piavpn-manual/token)
./connect_to_wireguard_with_token.sh "$SERVER_IP" "$TOKEN"
```

**After:**
```python
from initialization.files.vault.scripts.setup.pia.integration import PiaVpnIntegrator

integrator = PiaVpnIntegrator()
vpn_port = integrator.connect_vpn_replacement(credentials, "wireguard")
```

## Testing and Validation

### Unit Testing
```python
# Test individual components
from initialization.files.vault.scripts.setup.pia.auth import PiaTokenGenerator

token_gen = PiaTokenGenerator()
assert token_gen.validate_credentials("p1234567", "password123")
```

### Integration Testing
```python
# Test complete VPN flow
integrator = PiaVpnIntegrator()
try:
    vpn_port = integrator.connect_vpn_replacement(test_credentials, "wireguard")
    assert vpn_port is not None
    integrator.cleanup_connection()
except Exception as e:
    print(f"Integration test failed: {e}")
```

## Support and Maintenance

### Logging
The module uses the HOMESERVER logging system with fallback to print statements:
- Level 0: Critical errors
- Level 1: Errors
- Level 2: Warnings
- Level 3: Info
- Level 4: Debug
- Level 5: Verbose debug

### Error Reporting
All errors include detailed context and recovery suggestions. Check the logs for specific error details and recommended actions.

### Updates
The module is designed for easy updates and maintenance. All configuration is externalized and the modular design allows for component-level updates.

## Conclusion

The PIA VPN Integration Module provides a robust, maintainable replacement for the legacy bash script system while maintaining full compatibility with existing HOMESERVER infrastructure. The modular design, comprehensive error handling, and professional-grade implementation make it suitable for production use in digital sovereignty environments.

For additional support or questions, refer to the individual module documentation or the HOMESERVER project documentation.
