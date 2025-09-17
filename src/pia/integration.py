#!/usr/bin/env python3

"""
PIA Integration Module for HOMESERVER VPN System

This module provides seamless integration between the new PIA Python modules
and the existing HOMESERVER VPN infrastructure. It replaces the bash script
dependencies in vpn.py with professional Python implementations.

Key Integration Points:
- Replace manual-connections bash scripts with Python API calls
- Maintain compatibility with existing namespace and firewall systems
- Integrate with transmission launcher and port management
- Preserve all existing logging and error handling patterns

This module serves as the bridge between the legacy system and the new
PIA implementation, ensuring a smooth transition while maintaining all
existing functionality.
"""

import os
import sys
import time
import json
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

from .auth import PiaTokenGenerator, DedicatedIpHandler, CredentialManager, SessionManager
from .regions import ServerSelector, LatencyTester
from .wireguard import WireGuardManager
from .openvpn import OpenVpnManager
from .portforward import PortForwardManager
from .api_client import ApiError, ConnectionError, AuthenticationError

from ..config import get_network_config, get_service_config, get_path_config
from ..utils import run_command, find_pids, terminate_processes

# Safe logging function that falls back to print
def safe_log(level, message):
    try:
        from ..logger import log_message
        if log_message is not None:
            log_message(level, message)
        else:
            print(f"[{level}] {message}")
    except (ImportError, AttributeError):
        print(f"[{level}] {message}")

log_message = safe_log


class PiaVpnIntegrator:
    """
    Main integration class that replaces the bash script VPN connection logic
    with professional Python implementations while maintaining compatibility
    with the existing HOMESERVER infrastructure.
    """
    
    def __init__(self):
        """Initialize PIA VPN integrator with existing system configuration."""
        self.network_config = get_network_config()
        self.service_config = get_service_config()
        self.path_config = get_path_config()
        
        # Initialize PIA components
        self.session_manager = SessionManager()
        self.server_selector = ServerSelector()
        self.latency_tester = LatencyTester()
        self.wireguard_manager = WireGuardManager()
        self.openvpn_manager = OpenVpnManager()
        self.portforward_manager = PortForwardManager()
        
        # Port file for compatibility with existing system
        self.port_file = Path("/tmp/port.pid")
        
        log_message(3, "PIA VPN integrator initialized")
    
    def connect_vpn_replacement(self, credentials: Dict[str, Any], 
                              protocol: str = "openvpn_udp_standard",
                              enable_port_forwarding: bool = True,
                              dip_token: Optional[str] = None) -> Optional[int]:
        """
        Replace the existing connect_vpn function with PIA Python implementation.
        
        This function maintains the same interface as the original connect_vpn
        but uses the new PIA modules instead of bash scripts.
        
        Args:
            credentials: Credential dictionary (compatible with existing format)
            protocol: VPN protocol to use (wireguard, openvpn_udp_standard, etc.)
            enable_port_forwarding: Whether to enable port forwarding
            dip_token: Optional dedicated IP token
            
        Returns:
            VPN port number if successful, None if failed
            
        Raises:
            SystemExit: On critical failures (maintains compatibility)
        """
        log_message(3, f"Starting PIA VPN connection with protocol: {protocol}")
        
        try:
            # Extract PIA credentials from the existing credential format
            pia_creds = credentials.get("pia", {})
            username = pia_creds.get("username")
            password = pia_creds.get("password")
            
            if not username or not password:
                log_message(1, "PIA credentials not found in credential dictionary")
                sys.exit(1)
            
            # Step 1: Authenticate and get token
            log_message(3, "Authenticating with PIA...")
            auth_result = self.session_manager.authenticate(username, password)
            token = auth_result['token']
            
            # Handle dedicated IP if provided
            dip_info = None
            if dip_token and dip_token.lower() != "no":
                dip_info = auth_result.get('dedicated_ip')
            
            # Step 2: Select server (use dedicated IP if available, otherwise auto-select)
            if dip_info:
                log_message(3, "Using dedicated IP server")
                server_info = {
                    'ip': dip_info['ip_address'],
                    'hostname': dip_info['hostname'],
                    'port_forward': dip_info.get('pf_capable', True)
                }
            else:
                log_message(3, "Selecting optimal server...")
                server_info = self._select_optimal_server(token, enable_port_forwarding)
            
            # Step 3: Establish VPN connection based on protocol
            connection_result = None
            if protocol == "wireguard":
                connection_result = self._connect_wireguard(token, server_info, dip_token)
            elif protocol.startswith("openvpn"):
                connection_result = self._connect_openvpn(token, server_info, protocol, dip_token)
            else:
                log_message(1, f"Unsupported protocol: {protocol}")
                sys.exit(1)
            
            if not connection_result:
                log_message(1, "VPN connection failed")
                sys.exit(1)
            
            # Step 4: Setup port forwarding if enabled and supported
            vpn_port = None
            if enable_port_forwarding and server_info.get('port_forward', False):
                log_message(3, "Setting up port forwarding...")
                vpn_port = self._setup_port_forwarding(token, server_info, connection_result)
                
                if vpn_port:
                    # Write port to file for compatibility with existing system
                    self._write_port_file(vpn_port)
                    log_message(2, f"Port forwarding enabled on port: {vpn_port}")
                else:
                    log_message(1, "Port forwarding setup failed")
            else:
                log_message(3, "Port forwarding not requested or not supported")
            
            log_message(0, f"PIA VPN connection established successfully (Protocol: {protocol})")
            return vpn_port
            
        except AuthenticationError as e:
            log_message(1, f"Authentication failed: {e}")
            sys.exit(1)
        except ApiError as e:
            log_message(1, f"API error: {e}")
            sys.exit(1)
        except Exception as e:
            log_message(1, f"Unexpected error during VPN connection: {e}")
            sys.exit(1)
    
    def _select_optimal_server(self, token: str, require_port_forwarding: bool) -> Dict[str, Any]:
        """Select optimal server based on latency and requirements."""
        log_message(3, "Testing server latencies...")
        
        try:
            # Get server list and test latencies
            servers = self.server_selector.get_available_servers(
                token=token,
                port_forward_required=require_port_forwarding,
                max_latency=0.1  # 100ms max latency
            )
            
            if not servers:
                raise ApiError("No suitable servers found")
            
            # Test latencies and select best server
            best_server = self.latency_tester.find_fastest_server(servers, max_latency=0.1)
            
            if not best_server:
                raise ApiError("No responsive servers found")
            
            log_message(2, f"Selected server: {best_server['hostname']} (latency: {best_server.get('latency', 'unknown')}s)")
            return best_server
            
        except Exception as e:
            log_message(1, f"Server selection failed: {e}")
            raise
    
    def _connect_wireguard(self, token: str, server_info: Dict[str, Any], dip_token: Optional[str]) -> Dict[str, Any]:
        """Establish WireGuard VPN connection."""
        log_message(3, "Establishing WireGuard connection...")
        
        try:
            # Setup WireGuard in the existing VPN namespace
            connection_result = self.wireguard_manager.connect(
                server_ip=server_info['ip'],
                server_hostname=server_info['hostname'],
                token=token,
                dip_token=dip_token,
                namespace=self.network_config.vpn_namespace,
                dns_servers=["10.0.0.242"]  # PIA DNS
            )
            
            log_message(2, "WireGuard connection established")
            return connection_result
            
        except Exception as e:
            log_message(1, f"WireGuard connection failed: {e}")
            raise
    
    def _connect_openvpn(self, token: str, server_info: Dict[str, Any], protocol: str, dip_token: Optional[str]) -> Dict[str, Any]:
        """Establish OpenVPN connection."""
        log_message(3, f"Establishing OpenVPN connection ({protocol})...")
        
        try:
            # Parse protocol settings
            protocol_parts = protocol.split('_')
            transport = protocol_parts[1] if len(protocol_parts) > 1 else 'udp'
            encryption = protocol_parts[2] if len(protocol_parts) > 2 else 'standard'
            
            # Get the correct OpenVPN server for this transport protocol
            servers = server_info.get('servers', {})
            openvpn_server = None
            
            if transport == 'udp':
                ovpn_servers = servers.get('ovpnudp', [])
                if ovpn_servers:
                    openvpn_server = ovpn_servers[0]
            else:  # tcp
                ovpn_servers = servers.get('ovpntcp', [])
                if ovpn_servers:
                    openvpn_server = ovpn_servers[0]
            
            if not openvpn_server:
                raise Exception(f"No OpenVPN {transport.upper()} servers available for region {server_info['region_name']}")
            
            # Use OpenVPN-specific server details
            server_ip = openvpn_server.get('ip')
            server_hostname = openvpn_server.get('cn')
            
            log_message(2, f"Using OpenVPN server: {server_hostname} ({server_ip})")
            
            # Setup OpenVPN in the existing VPN namespace
            connection_result = self.openvpn_manager.connect(
                server_ip=server_ip,
                server_hostname=server_hostname,
                token=token,
                dip_token=dip_token,
                transport=transport,
                encryption=encryption,
                namespace=self.network_config.vpn_namespace,
                dns_servers=["10.0.0.242"]  # PIA DNS
            )
            
            log_message(2, "OpenVPN connection established")
            return connection_result
            
        except Exception as e:
            log_message(1, f"OpenVPN connection failed: {e}")
            raise
    
    def _setup_port_forwarding(self, token: str, server_info: Dict[str, Any], connection_result: Dict[str, Any]) -> Optional[int]:
        """Setup port forwarding and return the assigned port."""
        try:
            # Get gateway IP from connection result
            gateway_ip = connection_result.get('gateway_ip', server_info['ip'])
            
            # Setup port forwarding (stub implementation)
            vpn_port = self.portforward_manager.get_and_bind_port(
                pf_hostname=server_info['hostname'],
                pf_gateway=gateway_ip,
                token=token
            )
            
            if vpn_port:
                # Start keepalive process with real payload and signature
                if self.portforward_manager.payload and self.portforward_manager.signature:
                    self.portforward_manager.start_keepalive(
                        pf_hostname=server_info['hostname'],
                        pf_gateway=gateway_ip,
                        payload=self.portforward_manager.payload,
                        signature=self.portforward_manager.signature
                    )
                else:
                    log_message(1, "Cannot start keepalive: missing payload or signature from port forwarding setup")
                    
                
                return vpn_port
            
            return None
            
        except Exception as e:
            log_message(1, f"Port forwarding setup failed: {e}")
            return None
    
    def _write_port_file(self, port: int):
        """Write port to file for compatibility with existing system."""
        try:
            with open(self.port_file, 'w') as f:
                f.write(str(port))
            
            # Set appropriate permissions
            os.chmod(self.port_file, 0o644)
            log_message(5, f"Wrote port {port} to {self.port_file}")
            
        except Exception as e:
            log_message(1, f"Failed to write port file: {e}")
    
    def start_vpn_keepalive(self, token: str, server_info: Dict[str, Any], connection_result: Dict[str, Any]):
        """
        Start perpetual VPN keepalive loop that mirrors the shell script behavior.
        
        This method stays alive perpetually and performs keepalive operations every 15 minutes:
        - Refreshes port forwarding binding
        - Monitors VPN connection health
        - Maintains the connection indefinitely
        """
        log_message(0, "Starting perpetual VPN keepalive mode...")
        log_message(0, "This process will stay alive to maintain the VPN connection.")
        
        try:
            while True:
                # Perform keepalive operations every 15 minutes
                time.sleep(900)  # 15 minutes
                
                log_message(3, "Performing VPN keepalive operations...")
                
                # 1. Refresh port forwarding binding (like shell scripts do)
                if self.portforward_manager.payload and self.portforward_manager.signature:
                    success = self.portforward_manager.bind_port(
                        pf_hostname=server_info['hostname'],
                        pf_gateway=connection_result.get('gateway_ip', server_info['ip']),
                        payload=self.portforward_manager.payload,
                        signature=self.portforward_manager.signature
                    )
                    
                    if success:
                        log_message(3, "Port forwarding keepalive successful")
                        # Update port file timestamp
                        self._touch_port_file()
                    else:
                        log_message(1, "Port forwarding keepalive failed")
                else:
                    log_message(1, "Cannot perform port forwarding keepalive: missing payload or signature")
                
                # 2. Check VPN connection health
                connection_status = self.get_connection_status()
                if connection_status.get('connected'):
                    log_message(4, f"VPN connection health check passed - {connection_status.get('protocol')}")
                else:
                    log_message(1, "VPN connection health check failed - connection appears down")
                
                # 3. Log keepalive status
                log_message(3, f"VPN keepalive cycle completed, next check in 15 minutes")
                
        except KeyboardInterrupt:
            log_message(0, "VPN keepalive interrupted, performing cleanup...")
            self.cleanup_connection()
    
    def _touch_port_file(self):
        """Update port file timestamp to show active connection (like shell scripts do)."""
        try:
            if self.port_file.exists():
                os.utime(self.port_file, None)  # Update access/modify times
                log_message(4, "Updated port file timestamp")
        except Exception as e:
            log_message(2, f"Failed to update port file timestamp: {e}")
    
    def cleanup_connection(self):
        """Clean up PIA VPN connection and associated resources."""
        log_message(3, "Cleaning up PIA VPN connection...")
        
        try:
            # Stop port forwarding keepalive
            self.portforward_manager.stop_keepalive()
            
            # Disconnect VPN protocols
            self.wireguard_manager.disconnect()
            self.openvpn_manager.disconnect()
            
            # Clean up session data
            self.session_manager.cleanup_credentials()
            
            # Remove port file
            if self.port_file.exists():
                self.port_file.unlink()
                log_message(3, "Removed port file")
            
            log_message(2, "PIA VPN cleanup completed")
            
        except Exception as e:
            log_message(1, f"Error during PIA VPN cleanup: {e}")
    
    def get_connection_status(self) -> Dict[str, Any]:
        """Get current VPN connection status."""
        try:
            status = {
                'connected': False,
                'protocol': None,
                'server_ip': None,
                'port_forwarding': False,
                'assigned_port': None
            }
            
            # Check WireGuard status
            wg_status = self.wireguard_manager.get_status()
            if wg_status.get('connected'):
                status.update({
                    'connected': True,
                    'protocol': 'wireguard',
                    'server_ip': wg_status.get('server_ip')
                })
            
            # Check OpenVPN status if WireGuard not connected
            if not status['connected']:
                ovpn_status = self.openvpn_manager.get_status()
                if ovpn_status.get('connected'):
                    status.update({
                        'connected': True,
                        'protocol': 'openvpn',
                        'server_ip': ovpn_status.get('server_ip')
                    })
            
            # Check port forwarding status
            pf_status = self.portforward_manager.get_status()
            if pf_status.get('active'):
                status.update({
                    'port_forwarding': True,
                    'assigned_port': pf_status.get('port')
                })
            
            return status
            
        except Exception as e:
            log_message(1, f"Error getting connection status: {e}")
            return {'connected': False, 'error': str(e)}


# Global instance for easy integration
_pia_integrator = None

def get_pia_integrator() -> PiaVpnIntegrator:
    """Get or create the global PIA integrator instance."""
    global _pia_integrator
    if _pia_integrator is None:
        _pia_integrator = PiaVpnIntegrator()
    return _pia_integrator


def pia_connect_vpn(credentials: Dict[str, Any], **kwargs) -> Optional[int]:
    """
    Drop-in replacement for the existing connect_vpn function.
    
    This function can be used to replace the connect_vpn call in vpn.py
    with minimal changes to the existing codebase.
    """
    integrator = get_pia_integrator()
    return integrator.connect_vpn_replacement(credentials, **kwargs)


def pia_cleanup_vpn():
    """
    Drop-in replacement for VPN cleanup operations.
    """
    integrator = get_pia_integrator()
    integrator.cleanup_connection()


def pia_get_status() -> Dict[str, Any]:
    """
    Get current PIA VPN connection status.
    """
    integrator = get_pia_integrator()
    return integrator.get_connection_status()
