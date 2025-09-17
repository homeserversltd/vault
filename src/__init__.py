"""
VPN and Transmission Management Setup Module

This module provides a modular approach to managing VPN connections and Transmission daemon
within network namespaces. It breaks down the functionality into logical components:

- logger: Logging setup and configuration
- utils: Utility functions for command execution, credential management, and process handling
- vpn: VPN-specific functionality including network setup, connection management, and firewall rules
- transmissionLauncher: Main orchestrator script that coordinates all components

The module is designed to provide digital sovereignty through secure, isolated network operations.
"""

from .logger import setup_logging, log_message
from .utils import (
    run_command, read_credentials, generate_compliant_mac_address,
    remove_rules_by_comment, terminate_processes, find_pids
)
from .vpn import (
    initialize_network_interface, connect_vpn, connect_vpn_legacy, deconstruct_vpn_and_services,
    get_vpn_port, set_vpn_port, VPN_NS, VPN_IF, TRANSMISSION_PORT, TRANSMISSION_CONFIG_DIR,
    disconnect_vpn_python
)
from .teardown import (
    perfect_teardown, emergency_teardown, verify_teardown,
    teardown_processes, teardown_firewall_rules, teardown_files,
    teardown_network_devices, teardown_namespace,
    namespace_exists
)
from .config import (
    Config, get_config, reset_config,
    get_network_config, get_path_config, get_service_config, 
    get_security_config, get_logging_config, get_environment_config,
    NetworkConfig, PathConfig, ServiceConfig, SecurityConfig, 
    LoggingConfig, EnvironmentConfig
)
from .templateEngine import (
    generate_transmission_config, cleanup_transmission_configs,
    TransmissionTemplateEngine
)
from .rpc import (
    TransmissionRPCManager, RPCConfig, TransmissionRPCError,
    create_rpc_manager, set_transmission_peer_port
)

__all__ = [
    # Logger functions
    'setup_logging',
    'log_message',
    
    # Utility functions
    'run_command',
    'read_credentials',
    'generate_compliant_mac_address',
    'remove_rules_by_comment',
    'terminate_processes',
    'find_pids',
    
    # VPN functions
    'initialize_network_interface',
    'connect_vpn',
    'connect_vpn_legacy',
    'deconstruct_vpn_and_services',
    'get_vpn_port',
    'set_vpn_port',
    'disconnect_vpn_python',
    
    # Teardown functions
    'perfect_teardown',
    'emergency_teardown',
    'verify_teardown',
    'teardown_processes',
    'teardown_firewall_rules',
    'teardown_files',
    'teardown_network_devices',
    'teardown_namespace',
    'namespace_exists',
    
    # Configuration management
    'Config',
    'get_config',
    'reset_config',
    'get_network_config',
    'get_path_config', 
    'get_service_config',
    'get_security_config',
    'get_logging_config',
    'get_environment_config',
    'NetworkConfig',
    'PathConfig',
    'ServiceConfig', 
    'SecurityConfig',
    'LoggingConfig',
    'EnvironmentConfig',
    
    # Template engine
    'generate_transmission_config',
    'cleanup_transmission_configs',
    'TransmissionTemplateEngine',
    
    # RPC management
    'TransmissionRPCManager',
    'RPCConfig',
    'TransmissionRPCError',
    'create_rpc_manager',
    'set_transmission_peer_port',
    
    # Constants
    'VPN_NS',
    'VPN_IF',
    'TRANSMISSION_PORT',
    'TRANSMISSION_CONFIG_DIR',
]

__version__ = "1.0.0"
__author__ = "HOMESERVER Team"
__description__ = "Professional-grade VPN and Transmission management for digital sovereignty"
