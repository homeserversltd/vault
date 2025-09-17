"""
PIA VPN Integration Module for HOMESERVER

This module provides comprehensive Private Internet Access (PIA) VPN integration
for the HOMESERVER digital sovereignty platform. It replaces the bash-based
manual-connections scripts with professional Python implementations.

Key Features:
- Professional authentication and token management
- Intelligent server selection with latency testing
- WireGuard and OpenVPN protocol support
- Automatic port forwarding with keepalive
- Seamless integration with existing HOMESERVER infrastructure

The module follows HOMESERVER principles:
- Digital sovereignty through secure, isolated networking
- Professional-grade error handling and logging
- Comprehensive configuration management
- Maintainable, well-documented code

Architecture:
- auth: Authentication, token management, and credential handling
- regions: Server discovery, latency testing, and selection
- wireguard: WireGuard protocol implementation
- openvpn: OpenVPN protocol implementation
- portforward: Port forwarding management with keepalive
- setup_wizard: Interactive configuration and setup
- api_client: Robust PIA API client with retry logic
"""

from .auth import PiaTokenGenerator, DedicatedIpHandler, CredentialManager
from .regions import LatencyTester, ServerSelector
from .wireguard import WireGuardManager, WireGuardKeyManager
from .openvpn import OpenVpnManager, OpenVpnConfigManager
from .portforward import PortForwardManager
from .api_client import PiaApiClient, ApiError, ConnectionError

__all__ = [
    # Authentication components
    'PiaTokenGenerator',
    'DedicatedIpHandler', 
    'CredentialManager',
    
    # Server discovery and selection
    'LatencyTester',
    'ServerSelector',
    
    # Protocol implementations
    'WireGuardManager',
    'WireGuardKeyManager',
    'OpenVpnManager',
    'OpenVpnConfigManager',
    
    # Port forwarding
    'PortForwardManager',
    
    # API and utilities
    'PiaApiClient',
    'ApiError',
    'ConnectionError',
]

__version__ = "1.0.0"
__author__ = "HOMESERVER Team"
__description__ = "Professional PIA VPN integration for digital sovereignty"
