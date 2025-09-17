#!/usr/bin/env python3

"""
Configuration Management Module for HOMESERVER VPN/Transmission Infrastructure

This module provides centralized configuration management with:
- Single source of truth for all settings
- Environment-specific configurations
- Configuration validation and type checking
- Professional error handling for configuration issues
- Support for configuration file loading and validation

The configuration follows HOMESERVER principles of digital sovereignty through
secure, validated, and maintainable configuration management.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field
# Note: log_message is imported dynamically to avoid circular dependencies


@dataclass
class NetworkConfig:
    """Network interface and addressing configuration."""
    wan_interface: str = "enp1s0"
    lan_interface: str = "enp2s0"
    vpn_interface: str = "veth0"
    vpn_peer_interface: str = "veth1"
    vpn_namespace: str = "vpn"
    
    # IP addressing
    host_veth_ip: str = "192.168.2.1"
    namespace_veth_ip: str = "192.168.2.2"
    veth_subnet: str = "24"
    dns_server: str = "1.1.1.1"
    
    def __post_init__(self):
        """Validate network configuration after initialization."""
        self._validate_interfaces()
        self._validate_ip_addresses()
    
    def _validate_interfaces(self):
        """Validate interface names are non-empty strings."""
        interfaces = [
            self.wan_interface, self.lan_interface, 
            self.vpn_interface, self.vpn_peer_interface, self.vpn_namespace
        ]
        for interface in interfaces:
            if not isinstance(interface, str) or not interface.strip():
                raise ValueError(f"Invalid interface name: {interface}")
    
    def _validate_ip_addresses(self):
        """Validate IP addresses are in correct format."""
        import ipaddress
        try:
            ipaddress.IPv4Address(self.host_veth_ip)
            ipaddress.IPv4Address(self.namespace_veth_ip)
            ipaddress.IPv4Address(self.dns_server)
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid IP address in network config: {e}")


@dataclass
class PathConfig:
    """File system paths and directory configuration."""
    vault_dir: Path = field(default_factory=lambda: Path("/vault"))
    keys_dir: Path = field(init=False)
    scripts_dir: Path = field(init=False)
    keyman_script: Path = field(init=False)
    pia_connection_script: Path = field(init=False)
    
    # Runtime paths
    ramdisk_mount: Path = field(default_factory=lambda: Path("/mnt/ramdisk"))
    logs_dir: Path = field(init=False)
    log_file: Path = field(init=False)
    port_file: Path = field(default_factory=lambda: Path("/tmp/port.pid"))
    key_exchange_dir: Path = field(default_factory=lambda: Path("/mnt/keyexchange"))
    
    # System paths
    transmission_config_dir: Path = field(default_factory=lambda: Path("/etc/transmission-daemon"))
    
    def __post_init__(self):
        """Initialize derived paths and validate configuration."""
        # Derived paths from vault_dir
        self.keys_dir = self.vault_dir / ".keys"
        self.scripts_dir = self.vault_dir / "scripts"
        self.keyman_script = self.vault_dir / "keyman" / "exportkey.sh"
        self.pia_connection_script = self.scripts_dir / "manual-connections" / "run_setup.sh"
        
        # Derived paths from ramdisk_mount
        self.logs_dir = self.ramdisk_mount / "logs"
        self.log_file = self.logs_dir / "transmission.log"
        
        self._validate_paths()
    
    def _validate_paths(self):
        """Validate that critical paths exist or can be created."""
        # Check if vault directory exists
        if not self.vault_dir.exists():
            raise ValueError(f"Vault directory does not exist: {self.vault_dir}")
        
        # Validate that critical scripts exist
        critical_files = [self.keyman_script, self.pia_connection_script]
        for file_path in critical_files:
            if not file_path.exists():
                # Use print instead of log_message during config validation
                print(f"Warning: Critical file does not exist: {file_path}")


@dataclass
class ServiceConfig:
    """Service-specific configuration settings."""
    # Service names
    pia_service_name: str = "pia"
    transmission_service_name: str = "transmission"
    
    # Transmission settings
    transmission_port: int = 9091
    transmission_bind_ip: str = "0.0.0.0"
    
    # VPN settings
    vpn_max_retries: int = 5
    vpn_retry_delay: int = 30  # seconds
    vpn_file_check_retries: int = 3
    vpn_file_check_delay: int = 10  # seconds
    
    # Transmission settings
    transmission_max_retries: int = 3
    transmission_retry_delay: int = 10  # seconds
    transmission_startup_delay: int = 5  # seconds
    transmission_config_delay: int = 5  # seconds
    
    def __post_init__(self):
        """Validate service configuration."""
        self._validate_ports()
        self._validate_timeouts()
    
    def _validate_ports(self):
        """Validate port numbers are in valid range."""
        if not (1 <= self.transmission_port <= 65535):
            raise ValueError(f"Invalid transmission port: {self.transmission_port}")
    
    def _validate_timeouts(self):
        """Validate timeout values are positive."""
        timeouts = [
            self.vpn_retry_delay, self.vpn_file_check_delay,
            self.transmission_retry_delay, self.transmission_startup_delay,
            self.transmission_config_delay
        ]
        for timeout in timeouts:
            if timeout <= 0:
                raise ValueError(f"Invalid timeout value: {timeout}")


@dataclass
class SecurityConfig:
    """Security-related configuration settings."""
    # Credential handling
    secure_credential_cleanup: bool = True
    auth_file_permissions: int = 0o600
    
    # Process security
    require_sudo: bool = True
    validate_sudo_access: bool = True
    
    # File security
    secure_temp_files: bool = True
    
    def __post_init__(self):
        """Validate security configuration."""
        # Validate file permissions are octal
        if not isinstance(self.auth_file_permissions, int):
            raise ValueError("auth_file_permissions must be an integer (octal)")


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    default_verbosity: int = 3
    log_to_file: bool = True
    log_to_console_on_debug: bool = True
    log_format: str = '%(asctime)s - %(levelname)s: %(message)s'
    log_date_format: str = '%Y-%m-%d %H:%M:%S'
    
    # Log level mappings
    log_levels: Dict[int, int] = field(default_factory=lambda: {
        5: 10,  # DEBUG
        4: 10,  # VARIABLES (Mapped to DEBUG)
        3: 20,  # INFO
        2: 20,  # SUCCESS (Mapped to INFO)
        1: 40,  # ERROR
        0: 20,  # STATUS (Mapped to INFO)
    })
    
    def __post_init__(self):
        """Validate logging configuration."""
        if not (0 <= self.default_verbosity <= 5):
            raise ValueError(f"Invalid default verbosity: {self.default_verbosity}")


@dataclass
class EnvironmentConfig:
    """Environment-specific configuration."""
    environment: str = "production"  # production, development, testing
    debug_mode: bool = False
    strict_validation: bool = True
    
    def __post_init__(self):
        """Validate environment configuration."""
        valid_environments = ["production", "development", "testing"]
        if self.environment not in valid_environments:
            raise ValueError(f"Invalid environment: {self.environment}. Must be one of {valid_environments}")
        
        # Auto-enable debug mode for development
        if self.environment == "development":
            self.debug_mode = True


class Config:
    """
    Main configuration class that aggregates all configuration sections.
    
    Provides a single point of access for all configuration settings with
    validation, environment support, and professional error handling.
    """
    
    def __init__(self, config_file: Optional[Union[str, Path]] = None, environment: str = "production"):
        """
        Initialize configuration.
        
        Args:
            config_file: Optional path to configuration file
            environment: Target environment (production, development, testing)
        """
        self.environment = environment
        self._load_configuration(config_file)
    
    def _load_configuration(self, config_file: Optional[Union[str, Path]] = None):
        """Load configuration from file or use defaults."""
        config_data = {}
        
        if config_file:
            config_data = self._load_config_file(config_file)
        
        # Load environment-specific overrides
        env_config = self._load_environment_config()
        config_data.update(env_config)
        
        # Initialize configuration sections
        self.network = NetworkConfig(**config_data.get('network', {}))
        self.paths = PathConfig(**config_data.get('paths', {}))
        self.services = ServiceConfig(**config_data.get('services', {}))
        self.security = SecurityConfig(**config_data.get('security', {}))
        self.logging = LoggingConfig(**config_data.get('logging', {}))
        self.environment_config = EnvironmentConfig(
            environment=self.environment,
            **config_data.get('environment', {})
        )
        
        # Configuration loaded successfully
    
    def _load_config_file(self, config_file: Union[str, Path]) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        config_path = Path(config_file)
        
        if not config_path.exists():
            print(f"Configuration file not found: {config_path}")
            return {}
        
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            print(f"Loaded configuration from: {config_path}")
            return config_data
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in configuration file {config_path}: {e}")
            return {}
        except Exception as e:
            print(f"Error loading configuration file {config_path}: {e}")
            return {}
    
    def _load_environment_config(self) -> Dict[str, Any]:
        """Load environment-specific configuration from environment variables."""
        env_config = {}
        
        # Network configuration from environment
        if os.getenv('HOMESERVER_WAN_INTERFACE'):
            env_config.setdefault('network', {})['wan_interface'] = os.getenv('HOMESERVER_WAN_INTERFACE')
        
        if os.getenv('HOMESERVER_LAN_INTERFACE'):
            env_config.setdefault('network', {})['lan_interface'] = os.getenv('HOMESERVER_LAN_INTERFACE')
        
        # Service configuration from environment
        if os.getenv('HOMESERVER_TRANSMISSION_PORT'):
            try:
                port = int(os.getenv('HOMESERVER_TRANSMISSION_PORT'))
                env_config.setdefault('services', {})['transmission_port'] = port
            except ValueError:
                print("Invalid HOMESERVER_TRANSMISSION_PORT environment variable")
        
        # Debug mode from environment
        if os.getenv('HOMESERVER_DEBUG') in ['1', 'true', 'True', 'TRUE']:
            env_config.setdefault('environment', {})['debug_mode'] = True
        
        return env_config
    
    def validate(self) -> bool:
        """
        Validate complete configuration.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # All validation is done in __post_init__ methods
            # If we get here, configuration is valid
            return True
        except Exception as e:
            print(f"Configuration validation failed: {e}")
            return False
    
    def get_required_commands(self) -> list:
        """Get list of system commands required for operation."""
        return [
            'ip', 'nft', 'tee', 'sysctl', 'pgrep', 'kill',
            'transmission-daemon', 'transmission-remote', 'env', 'rm',
            'mount', 'umount', 'netstat'
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary for serialization."""
        return {
            'network': {
                'wan_interface': self.network.wan_interface,
                'lan_interface': self.network.lan_interface,
                'vpn_interface': self.network.vpn_interface,
                'vpn_peer_interface': self.network.vpn_peer_interface,
                'vpn_namespace': self.network.vpn_namespace,
                'host_veth_ip': self.network.host_veth_ip,
                'namespace_veth_ip': self.network.namespace_veth_ip,
                'veth_subnet': self.network.veth_subnet,
                'dns_server': self.network.dns_server,
            },
            'services': {
                'pia_service_name': self.services.pia_service_name,
                'transmission_service_name': self.services.transmission_service_name,
                'transmission_port': self.services.transmission_port,
                'transmission_bind_ip': self.services.transmission_bind_ip,
                'vpn_max_retries': self.services.vpn_max_retries,
                'vpn_retry_delay': self.services.vpn_retry_delay,
                'transmission_max_retries': self.services.transmission_max_retries,
                'transmission_retry_delay': self.services.transmission_retry_delay,
            },
            'environment': {
                'environment': self.environment_config.environment,
                'debug_mode': self.environment_config.debug_mode,
                'strict_validation': self.environment_config.strict_validation,
            }
        }
    
    def save_config(self, config_file: Union[str, Path]):
        """Save current configuration to file."""
        config_path = Path(config_file)
        
        try:
            with open(config_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)
            print(f"Configuration saved to: {config_path}")
        except Exception as e:
            print(f"Error saving configuration to {config_path}: {e}")
            raise


# Global configuration instance
_config_instance: Optional[Config] = None


def get_config(config_file: Optional[Union[str, Path]] = None, environment: str = "production") -> Config:
    """
    Get the global configuration instance.
    
    Args:
        config_file: Optional path to configuration file
        environment: Target environment
        
    Returns:
        Configuration instance
    """
    global _config_instance
    
    if _config_instance is None:
        _config_instance = Config(config_file, environment)
    
    return _config_instance


def reset_config():
    """Reset the global configuration instance (primarily for testing)."""
    global _config_instance
    _config_instance = None


# Convenience functions for accessing configuration sections
def get_network_config() -> NetworkConfig:
    """Get network configuration."""
    return get_config().network


def get_path_config() -> PathConfig:
    """Get path configuration.""" 
    return get_config().paths


def get_service_config() -> ServiceConfig:
    """Get service configuration."""
    return get_config().services


def get_security_config() -> SecurityConfig:
    """Get security configuration."""
    return get_config().security


def get_logging_config() -> LoggingConfig:
    """Get logging configuration."""
    return get_config().logging


def get_environment_config() -> EnvironmentConfig:
    """Get environment configuration."""
    return get_config().environment_config
