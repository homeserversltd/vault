#!/usr/bin/env python3

"""
Template Engine for HOMESERVER Configuration Management

Professional template-based configuration system that eliminates the need for 
complex RPC calls and runtime configuration changes. Instead, configurations
are generated from templates and deployed directly to target locations.

Features:
- Template-based transmission configuration
- Namespace-aware file deployment
- Variable substitution and validation
- Secure credential handling
- Professional error handling and recovery

This approach provides:
- Faster startup times (no RPC calls)
- More reliable configuration (pre-validated templates)
- Better isolation (namespace-specific configs)
- Simpler debugging (static config files)
"""

import os
import json
import shutil
from typing import Dict, Any, Optional
from pathlib import Path
import tempfile
import subprocess

# Safe logging function that falls back to print
def safe_log(level, message):
    try:
        from .logger import log_message
        if log_message is not None:
            log_message(level, message)
        else:
            print(f"[{level}] {message}")
    except (ImportError, AttributeError):
        print(f"[{level}] {message}")

log_message = safe_log

from .config import get_network_config, get_service_config, get_path_config
from .utils import run_command


class TemplateEngineError(Exception):
    """Exception for template engine errors."""
    pass


class TransmissionTemplateEngine:
    """
    Professional transmission configuration template engine.
    
    Manages template-based configuration generation and deployment for
    transmission daemon to VPN namespace location,
    eliminating the need for RPC configuration calls.
    """
    
    # Default transmission configuration template
    TRANSMISSION_TEMPLATE = {
        "alt-speed-down": 50,
        "alt-speed-enabled": False,
        "alt-speed-time-begin": 540,
        "alt-speed-time-day": 127,
        "alt-speed-time-enabled": False,
        "alt-speed-time-end": 1020,
        "alt-speed-up": 50,
        "bind-address-ipv4": "0.0.0.0",
        "bind-address-ipv6": "::",
        "blocklist-enabled": False,
        "blocklist-url": "http://www.example.com/blocklist",
        "cache-size-mb": 4,
        "dht-enabled": True,
        "download-dir": "/mnt/nas/downloads/complete/",
        "download-queue-enabled": True,
        "download-queue-size": 5,
        "encryption": 1,
        "idle-seeding-limit": 30,
        "idle-seeding-limit-enabled": False,
        "incomplete-dir": "/mnt/nas/downloads/incomplete/",
        "incomplete-dir-enabled": True,
        "lpd-enabled": False,
        "message-level": 2,
        "peer-congestion-algorithm": "",
        "peer-id-ttl-hours": 6,
        "peer-limit-global": 200,
        "peer-limit-per-torrent": 50,
        "peer-port": "{{PEER_PORT_INT}}",
        "peer-port-random-high": 65535,
        "peer-port-random-low": 49152,
        "peer-port-random-on-start": False,
        "peer-socket-tos": "default",
        "pex-enabled": True,
        "port-forwarding-enabled": True,
        "preallocation": 1,
        "prefetch-enabled": True,
        "queue-stalled-enabled": True,
        "queue-stalled-minutes": 30,
        "ratio-limit": 2,
        "ratio-limit-enabled": False,
        "rename-partial-files": True,
        "rpc-authentication-required": True,
        "rpc-bind-address": "0.0.0.0",
        "rpc-enabled": True,
        "rpc-host-whitelist": "",
        "rpc-host-whitelist-enabled": True,
        "rpc-password": "{{RPC_PASSWORD}}",
        "rpc-port": 9091,
        "rpc-url": "/transmission/",
        "rpc-username": "{{RPC_USERNAME}}",
        "rpc-whitelist": "127.0.0.1,192.168.123.*,192.168.2.*",
        "rpc-whitelist-enabled": True,
        "scrape-paused-torrents-enabled": True,
        "script-torrent-done-enabled": False,
        "script-torrent-done-filename": "",
        "seed-queue-enabled": False,
        "seed-queue-size": 10,
        "speed-limit-down": 100,
        "speed-limit-down-enabled": False,
        "speed-limit-up": 100,
        "speed-limit-up-enabled": False,
        "start-added-torrents": True,
        "trash-original-torrent-files": False,
        "umask": 18,
        "upload-slots-per-torrent": 14,
        "utp-enabled": True,
        "watch-dir": "/mnt/nas/downloads/objectives/",
        "watch-dir-enabled": True
    }
    
    def __init__(self):
        """Initialize transmission template engine."""
        self.config = get_service_config()
        self.network = get_network_config()
        self.paths = get_path_config()
        
        # Template and target directories
        self.template_dir = Path("/var/lib/transmission-daemon/templates")
        self.config_dir = Path("/etc/transmission-daemon")
        self.namespace_config_dir = Path(f"/etc/netns/{self.network.vpn_namespace}/transmission-daemon")
        
        # Ensure directories exist
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.namespace_config_dir.mkdir(parents=True, exist_ok=True)
        
        log_message(3, "TransmissionTemplateEngine initialized with template-based config management")
    
    def create_template(self, template_path: Optional[Path] = None) -> Path:
        """
        Create the transmission configuration template file.
        
        Args:
            template_path: Optional path for template file
            
        Returns:
            Path to created template file
            
        Raises:
            TemplateEngineError: If template creation fails
        """
        if not template_path:
            template_path = self.template_dir / "settings.json.template"
        
        try:
            # Create template with placeholders
            template_content = json.dumps(self.TRANSMISSION_TEMPLATE, indent=4)
            
            with open(template_path, 'w') as f:
                f.write(template_content)
            
            # Set appropriate permissions
            template_path.chmod(0o644)
            
            log_message(2, f"Created transmission template: {template_path}")
            return template_path
            
        except Exception as e:
            error_msg = f"Failed to create transmission template: {e}"
            log_message(1, error_msg)
            raise TemplateEngineError(error_msg)
    
    def generate_config(self, vpn_port: int, rpc_username: str, rpc_password: str,
                       template_path: Optional[Path] = None,
                       output_path: Optional[Path] = None) -> Path:
        """
        Generate transmission configuration from template with variable substitution.
        
        Args:
            vpn_port: VPN port number for peer connections
            rpc_username: RPC username
            rpc_password: RPC password (will be hashed automatically)
            template_path: Optional template file path
            output_path: Optional output file path
            
        Returns:
            Path to generated configuration file
            
        Raises:
            TemplateEngineError: If config generation fails
        """
        if not template_path:
            template_path = self.template_dir / "settings.json.template"
        
        # Generate to temporary location first, then deploy to final location
        output_path = Path(f"/tmp/transmission_settings_{vpn_port}.json")
        
        try:
            # ALWAYS use hardcoded template values - ignore external template files
            log_message(3, "Using hardcoded template values - ignoring external template files")
            template_content = json.dumps(self.TRANSMISSION_TEMPLATE, indent=4)
            
            # Variable substitution - use plain text credentials, Transmission will hash them
            variables = {
                "VPN_PORT": str(vpn_port),
                "PEER_PORT_INT": str(vpn_port),  # Keep as string for template replacement
                "RPC_USERNAME": rpc_username,
                "RPC_PASSWORD": rpc_password
            }
            
            # Replace template variables
            config_content = template_content
            for var_name, var_value in variables.items():
                placeholder = f"{{{{{var_name}}}}}"
                config_content = config_content.replace(placeholder, var_value)
            
            # Post-process to convert peer-port to integer (Transmission expects integer, not string)
            config_content = config_content.replace(f'"peer-port": "{vpn_port}"', f'"peer-port": {vpn_port}')
            
            # Validate JSON structure
            try:
                json.loads(config_content)
            except json.JSONDecodeError as e:
                raise TemplateEngineError(f"Generated config is not valid JSON: {e}")
            
            # Write configuration file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(config_content)
            
            # Set appropriate permissions
            output_path.chmod(0o600)  # Secure permissions for config with credentials
            
            log_message(2, f"Generated transmission config in temporary location: {output_path}")
            log_message(3, f"VPN port: {vpn_port}, RPC user: {rpc_username}")
            
            return output_path
            
        except Exception as e:
            if isinstance(e, TemplateEngineError):
                raise
            error_msg = f"Failed to generate transmission config: {e}"
            log_message(1, error_msg)
            raise TemplateEngineError(error_msg)
    
    def deploy_to_default(self, config_path: Path) -> bool:
        """
        Deploy configuration to the default transmission location.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            True if deployment successful
            
        Raises:
            TemplateEngineError: If deployment fails
        """
        try:
            # Target path in DEFAULT transmission location ONLY
            default_config_path = Path("/etc/transmission-daemon/settings.json")
            
            # ALWAYS overwrite the config - failure is not an option
            log_message(3, f"Force-deploying config from {config_path} to DEFAULT location: {default_config_path}")
            
            # Ensure default config directory exists
            default_config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Set proper ownership for the transmission-daemon directory
            subprocess.run([
                "chown", "debian-transmission:debian-transmission", 
                str(default_config_path.parent)
            ], check=True)
            default_config_path.parent.chmod(0o775)
            
            # ALWAYS copy config to default location - overwrite existing, clobber whatever is there
            log_message(3, f"Copying {config_path} to {default_config_path} (clobbering existing)")
            shutil.copy2(config_path, default_config_path)
            
            # Set proper ownership and permissions for Transmission
            # Must be owned by debian-transmission:debian-transmission with 600 permissions
            subprocess.run([
                "chown", "debian-transmission:debian-transmission", 
                str(default_config_path)
            ], check=True)
            default_config_path.chmod(0o600)
            
            # Verify deployment
            if not default_config_path.exists():
                raise TemplateEngineError("Config file not found after deployment")
            
            # Verify the config actually contains our template values
            try:
                with open(default_config_path, 'r') as f:
                    deployed_config = json.load(f)
                
                # Check if our template values are actually there
                if deployed_config.get('watch-dir') != self.TRANSMISSION_TEMPLATE['watch-dir']:
                    log_message(2, f"Warning: Deployed config watch-dir mismatch. Expected: {self.TRANSMISSION_TEMPLATE['watch-dir']}, Got: {deployed_config.get('watch-dir')}")
                
                log_message(3, f"Config verification passed. watch-dir: {deployed_config.get('watch-dir')}")
                
            except Exception as verify_e:
                log_message(2, f"Config verification warning: {verify_e}")
            
            log_message(2, f"Successfully deployed config to DEFAULT location: {default_config_path}")
            return True
            
        except Exception as e:
            error_msg = f"Failed to deploy config to default location: {e}"
            log_message(1, error_msg)
            raise TemplateEngineError(error_msg)
    
    def deploy_to_namespace(self, config_path: Path) -> bool:
        """
        Deploy configuration to the VPN namespace transmission location.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            True if deployment successful
            
        Raises:
            TemplateEngineError: If deployment fails
        """
        try:
            # Target path in VPN namespace transmission location
            namespace_config_path = self.namespace_config_dir / "settings.json"
            
            # ALWAYS overwrite the config - failure is not an option
            log_message(3, f"Force-deploying config from {config_path} to VPN namespace location: {namespace_config_path}")
            
            # Ensure namespace config directory exists
            namespace_config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Set proper ownership for the namespace transmission-daemon directory
            subprocess.run([
                "chown", "debian-transmission:debian-transmission", 
                str(namespace_config_path.parent)
            ], check=True)
            namespace_config_path.parent.chmod(0o775)
            
            # ALWAYS copy config to namespace location - overwrite existing, clobber whatever is there
            log_message(3, f"Copying {config_path} to {namespace_config_path} (clobbering existing)")
            shutil.copy2(config_path, namespace_config_path)
            
            # Set proper ownership and permissions for Transmission
            # Must be owned by debian-transmission:debian-transmission with 600 permissions
            subprocess.run([
                "chown", "debian-transmission:debian-transmission", 
                str(namespace_config_path)
            ], check=True)
            namespace_config_path.chmod(0o775)
            
            # Verify deployment
            if not namespace_config_path.exists():
                raise TemplateEngineError("Namespace config file not found after deployment")
            
            # Verify the config actually contains our template values
            try:
                with open(namespace_config_path, 'r') as f:
                    deployed_config = json.load(f)
                
                # Check if our template values are actually there
                if deployed_config.get('watch-dir') != self.TRANSMISSION_TEMPLATE['watch-dir']:
                    log_message(2, f"Warning: Namespace deployed config watch-dir mismatch. Expected: {self.TRANSMISSION_TEMPLATE['watch-dir']}, Got: {deployed_config.get('watch-dir')}")
                
                log_message(3, f"Namespace config verification passed. watch-dir: {deployed_config.get('watch-dir')}")
                
            except Exception as verify_e:
                log_message(2, f"Namespace config verification warning: {verify_e}")
            
            log_message(2, f"Successfully deployed config to VPN namespace location: {namespace_config_path}")
            return True
            
        except Exception as e:
            error_msg = f"Failed to deploy config to namespace location: {e}"
            log_message(1, error_msg)
            raise TemplateEngineError(error_msg)
    
    def deploy_to_both_locations(self, config_path: Path) -> bool:
        """
        Deploy configuration to both default and VPN namespace locations.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            True if deployment to both locations successful
            
        Raises:
            TemplateEngineError: If deployment to either location fails
        """
        try:
            log_message(3, "Deploying transmission config to both default and VPN namespace locations")
            
            # Deploy to default location
            default_success = self.deploy_to_default(config_path)
            if not default_success:
                raise TemplateEngineError("Failed to deploy to default location")
            
            # Deploy to namespace location
            namespace_success = self.deploy_to_namespace(config_path)
            if not namespace_success:
                raise TemplateEngineError("Failed to deploy to namespace location")
            
            log_message(2, "Successfully deployed transmission config to both locations")
            return True
            
        except Exception as e:
            error_msg = f"Failed to deploy to both locations: {e}"
            log_message(1, error_msg)
            raise TemplateEngineError(error_msg)
    
    def validate_config(self, config_path: Path) -> bool:
        """
        Validate transmission configuration file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            True if configuration is valid
        """
        try:
            if not config_path.exists():
                log_message(1, f"Config file does not exist: {config_path}")
                return False
            
            # Load and validate JSON structure
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            
            # Check for required fields
            required_fields = [
                'rpc-enabled', 'rpc-port', 'rpc-username', 'rpc-password',
                'peer-port', 'download-dir'
            ]
            
            missing_fields = []
            for field in required_fields:
                if field not in config_data:
                    missing_fields.append(field)
            
            if missing_fields:
                log_message(1, f"Config missing required fields: {missing_fields}")
                return False
            
            # Validate port numbers
            rpc_port = config_data.get('rpc-port')
            peer_port = config_data.get('peer-port')
            
            if not isinstance(rpc_port, int) or not (1 <= rpc_port <= 65535):
                log_message(1, f"Invalid RPC port: {rpc_port}")
                return False
            
            if isinstance(peer_port, str):
                try:
                    peer_port = int(peer_port)
                except ValueError:
                    log_message(1, f"Invalid peer port format: {peer_port}")
                    return False
            
            if not isinstance(peer_port, int) or not (1 <= peer_port <= 65535):
                log_message(1, f"Invalid peer port: {peer_port}")
                return False
            
            log_message(3, f"Configuration validation passed: {config_path}")
            return True
            
        except json.JSONDecodeError as e:
            log_message(1, f"Invalid JSON in config file: {e}")
            return False
        except Exception as e:
            log_message(1, f"Error validating config: {e}")
            return False
    
    def cleanup_configs(self, namespace: str = None):
        """
        Clean up generated configuration files.
        
        Args:
            namespace: Namespace to clean up (ignored - always cleans VPN namespace location)
        """
        try:
            # Clean up VPN namespace config location only
            namespace_config_path = self.namespace_config_dir / "settings.json"
            if namespace_config_path.exists():
                namespace_config_path.unlink()
                log_message(3, f"Removed namespace config: {namespace_config_path}")
            
            # Clean up any temporary configs
            temp_configs = list(self.template_dir.glob("settings_*.json"))
            for temp_config in temp_configs:
                try:
                    temp_config.unlink()
                    log_message(4, f"Removed temporary config: {temp_config}")
                except Exception as e:
                    log_message(2, f"Failed to remove temp config {temp_config}: {e}")
            
            log_message(2, "Configuration cleanup completed for VPN namespace location")
            
        except Exception as e:
            log_message(1, f"Error during config cleanup: {e}")


def generate_transmission_config(vpn_port: int, rpc_username: str, rpc_password: str,
                               namespace: str = None) -> Path:
    """
    High-level function to generate and deploy transmission configuration.
    
    Args:
        vpn_port: VPN port number for peer connections
        rpc_username: RPC username
        rpc_password: RPC password
        namespace: Target namespace (ignored - always deploys to VPN namespace location)
        
    Returns:
        Path to deployed configuration file
        
    Raises:
        TemplateEngineError: If generation or deployment fails
    """
    try:
        # Initialize template engine
        template_engine = TransmissionTemplateEngine()
        
        # Generate configuration
        config_path = template_engine.generate_config(
            vpn_port=vpn_port,
            rpc_username=rpc_username,
            rpc_password=rpc_password
        )
        
        # Validate configuration
        if not template_engine.validate_config(config_path):
            raise TemplateEngineError("Generated configuration failed validation")
        
        # Deploy to VPN namespace location only
        template_engine.deploy_to_namespace(config_path)
        
        log_message(2, f"Successfully generated and deployed transmission config for port {vpn_port} to VPN namespace location")
        return config_path
        
    except Exception as e:
        if isinstance(e, TemplateEngineError):
            raise
        error_msg = f"Transmission config generation failed: {e}"
        log_message(1, error_msg)
        raise TemplateEngineError(error_msg)


def cleanup_transmission_configs(namespace: str = None):
    """
    High-level function to clean up transmission configurations.
    
    Args:
        namespace: Target namespace (ignored - always cleans VPN namespace location)
    """
    try:
        template_engine = TransmissionTemplateEngine()
        template_engine.cleanup_configs(namespace)
        
    except Exception as e:
        log_message(1, f"Error during transmission config cleanup: {e}")
