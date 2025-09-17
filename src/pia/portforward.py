#!/usr/bin/env python3

"""
PIA Port Forwarding Management Module

Complete implementation of PIA port forwarding functionality.
Replaces the bash-based port forwarding logic with professional Python implementation
featuring real API calls, keepalive management, and comprehensive error handling.

Features:
- Real PIA port forwarding API integration
- Automatic signature acquisition and port binding
- Background keepalive process with 15-minute refresh cycle
- Payload validation and expiration handling
- Comprehensive error handling and recovery
- Process management for keepalive daemon
"""

import time
import json
import base64
import threading
import subprocess
import signal
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

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

# Import API client for port forwarding communication
try:
    from .api_client import PiaApiClient, ApiError, ConnectionError
except ImportError:
    log_message(1, "Warning: Could not import PIA API client, using fallback")
    PiaApiClient = None
    ApiError = Exception
    ConnectionError = Exception


class PortForwardError(Exception):
    """Exception for port forwarding errors."""
    pass


class PortForwardManager:
    """
    Professional PIA port forwarding management with real API integration.
    
    Provides methods for:
    - Signature acquisition from PIA API
    - Port binding and activation
    - Background keepalive process management
    - Port status monitoring and validation
    - Automatic cleanup on failure
    """
    
    def __init__(self, api_client: Optional[PiaApiClient] = None):
        """
        Initialize port forwarding manager.
        
        Args:
            api_client: Optional PIA API client instance
        """
        self.api_client = api_client or (PiaApiClient() if PiaApiClient else None)
        self.port_file = Path("/tmp/port.pid")
        self.keepalive_file = Path("/tmp/pf_keepalive.pid")
        
        # Keepalive process management
        self.keepalive_thread = None
        self.keepalive_stop_event = threading.Event()
        
        # Port forwarding data
        self.current_port = None
        self.payload = None
        self.signature = None
        self.expires_at = None
        
        log_message(3, "PortForwardManager initialized with real PIA API integration")
    
    def get_port_signature(self, pf_hostname: str, pf_gateway: str, token: str) -> Tuple[str, str]:
        """
        Get port forwarding signature from PIA API.
        
        Args:
            pf_hostname: PIA server hostname
            pf_gateway: Gateway IP address
            token: Authentication token
            
        Returns:
            Tuple of (payload, signature)
            
        Raises:
            PortForwardError: If signature acquisition fails
        """
        if not self.api_client:
            raise PortForwardError("No API client available for port forwarding")
        
        try:
            log_message(3, f"Getting port signature from {pf_hostname} ({pf_gateway})")
            
            signature_data = self.api_client.get_port_signature(pf_hostname, pf_gateway, token)
            
            payload = signature_data['payload']
            signature = signature_data['signature']
            
            # Decode and validate payload
            try:
                payload_decoded = json.loads(base64.b64decode(payload).decode())
                port = payload_decoded.get('port')
                expires_at = payload_decoded.get('expires_at')
                
                if not port or not expires_at:
                    raise PortForwardError("Invalid payload data - missing port or expiration")
                
                # Store port forwarding data
                self.current_port = port
                self.payload = payload
                self.signature = signature
                self.expires_at = expires_at
                
                log_message(2, f"Successfully acquired port signature for port: {port}")
                log_message(3, f"Port expires at: {expires_at}")
                
                return payload, signature
                
            except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
                raise PortForwardError(f"Failed to decode payload: {e}")
                
        except ApiError as e:
            error_msg = f"Failed to get port signature: {e}"
            log_message(1, error_msg)
            raise PortForwardError(error_msg)
    
    def bind_port(self, pf_hostname: str, pf_gateway: str, payload: str, signature: str) -> bool:
        """
        Bind port using signature and payload.
        
        Args:
            pf_hostname: PIA server hostname
            pf_gateway: Gateway IP address
            payload: Base64 encoded payload
            signature: Port signature
            
        Returns:
            True if binding successful, False otherwise
            
        Raises:
            PortForwardError: If port binding fails
        """
        if not self.api_client:
            raise PortForwardError("No API client available for port binding")
        
        try:
            log_message(3, f"Binding port on {pf_hostname} ({pf_gateway})")
            
            bind_data = self.api_client.bind_port(pf_hostname, pf_gateway, payload, signature)
            
            if bind_data.get('status') == 'OK':
                log_message(2, "Successfully bound port")
                
                # Update port file timestamp to show active connection
                if self.port_file.exists():
                    self.port_file.touch()
                
                return True
            else:
                error_msg = f"Port binding failed: {bind_data}"
                log_message(1, error_msg)
                raise PortForwardError(error_msg)
                
        except ApiError as e:
            error_msg = f"Failed to bind port: {e}"
            log_message(1, error_msg)
            raise PortForwardError(error_msg)
    
    def get_and_bind_port(self, pf_hostname: str, pf_gateway: str, token: str) -> Optional[int]:
        """
        Complete port forwarding setup: get signature and bind port.
        
        Args:
            pf_hostname: PIA server hostname
            pf_gateway: Gateway IP address
            token: Authentication token
            
        Returns:
            Port number if successful, None otherwise
        """
        try:
            # Get port signature
            payload, signature = self.get_port_signature(pf_hostname, pf_gateway, token)
            
            # Bind the port
            if self.bind_port(pf_hostname, pf_gateway, payload, signature):
                # Write port to file
                if self.current_port:
                    with open(self.port_file, 'w') as f:
                        f.write(str(self.current_port))
                    self.port_file.chmod(0o644)
                    
                    log_message(2, f"Port forwarding successful: port {self.current_port}")
                    return self.current_port
            
            return None
            
        except Exception as e:
            log_message(1, f"Port forwarding setup failed: {e}")
            self.cleanup()
            return None
    
    def _keepalive_worker(self, pf_hostname: str, pf_gateway: str, payload: str, signature: str):
        """
        Background worker for port forwarding keepalive.
        
        Args:
            pf_hostname: PIA server hostname
            pf_gateway: Gateway IP address
            payload: Base64 encoded payload
            signature: Port signature
        """
        log_message(3, "Port forwarding keepalive worker started")
        
        while not self.keepalive_stop_event.is_set():
            try:
                # Bind port to keep it alive
                success = self.bind_port(pf_hostname, pf_gateway, payload, signature)
                
                if success:
                    # Parse payload to get expiration info
                    try:
                        payload_decoded = json.loads(base64.b64decode(payload).decode())
                        expires_at = payload_decoded.get('expires_at')
                        
                        current_time = datetime.now(timezone.utc).isoformat()
                        log_message(4, f"Port forwarding refreshed at {current_time}")
                        if expires_at:
                            log_message(4, f"Port expires at {expires_at}")
                            
                    except Exception as e:
                        log_message(2, f"Failed to parse payload for logging: {e}")
                else:
                    log_message(1, "Port forwarding keepalive failed")
                    break
                    
            except Exception as e:
                log_message(1, f"Keepalive worker error: {e}")
                break
            
            # Wait 15 minutes (900 seconds) before next refresh
            if self.keepalive_stop_event.wait(900):  # Returns True if stop event was set
                break
        
        log_message(3, "Port forwarding keepalive worker stopped")
    
    def start_keepalive(self, pf_hostname: str, pf_gateway: str, payload: str, signature: str):
        """
        Start background keepalive process for port forwarding.
        
        Args:
            pf_hostname: PIA server hostname
            pf_gateway: Gateway IP address
            payload: Base64 encoded payload
            signature: Port signature
        """
        if self.keepalive_thread and self.keepalive_thread.is_alive():
            log_message(2, "Keepalive process already running")
            return
        
        # Reset stop event
        self.keepalive_stop_event.clear()
        
        # Start keepalive thread
        self.keepalive_thread = threading.Thread(
            target=self._keepalive_worker,
            args=(pf_hostname, pf_gateway, payload, signature),
            daemon=True
        )
        self.keepalive_thread.start()
        
        # Write keepalive PID file
        try:
            with open(self.keepalive_file, 'w') as f:
                f.write(str(os.getpid()))
            self.keepalive_file.chmod(0o644)
            
            log_message(2, "Port forwarding keepalive process started")
            
        except Exception as e:
            log_message(1, f"Failed to write keepalive PID file: {e}")
    
    def stop_keepalive(self):
        """Stop the keepalive process."""
        if self.keepalive_thread and self.keepalive_thread.is_alive():
            log_message(3, "Stopping port forwarding keepalive process")
            
            # Signal the thread to stop
            self.keepalive_stop_event.set()
            
            # Wait for thread to finish (with timeout)
            self.keepalive_thread.join(timeout=5)
            
            if self.keepalive_thread.is_alive():
                log_message(1, "Keepalive thread did not stop gracefully")
            else:
                log_message(2, "Port forwarding keepalive process stopped")
        
        # Clean up keepalive PID file
        try:
            if self.keepalive_file.exists():
                self.keepalive_file.unlink()
        except OSError as e:
            log_message(2, f"Failed to remove keepalive PID file: {e}")
    
    def get_current_port(self) -> Optional[int]:
        """
        Get the current forwarded port.
        
        Returns:
            Port number if active, None otherwise
        """
        try:
            if self.port_file.exists():
                with open(self.port_file, 'r') as f:
                    port = int(f.read().strip())
                    
                # Check if port file is recent (updated within last 20 minutes)
                file_age = time.time() - self.port_file.stat().st_mtime
                if file_age > 1200:  # 20 minutes
                    log_message(2, f"Port file is stale ({file_age:.0f}s old)")
                    return None
                    
                return port
                
        except (ValueError, IOError, OSError):
            pass
        
        return None
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get comprehensive port forwarding status.
        
        Returns:
            Status dictionary with port, expiration, and keepalive info
        """
        try:
            current_port = self.get_current_port()
            keepalive_active = (self.keepalive_thread and 
                              self.keepalive_thread.is_alive() and 
                              self.keepalive_file.exists())
            
            status = {
                'active': current_port is not None,
                'port': current_port,
                'keepalive_active': keepalive_active,
                'expires_at': self.expires_at
            }
            
            # Add file timestamps if available
            if self.port_file.exists():
                status['port_file_age'] = time.time() - self.port_file.stat().st_mtime
            
            if self.keepalive_file.exists():
                status['keepalive_file_age'] = time.time() - self.keepalive_file.stat().st_mtime
            
            return status
            
        except Exception as e:
            log_message(2, f"Error getting port forwarding status: {e}")
            return {
                'active': False,
                'port': None,
                'keepalive_active': False,
                'expires_at': None,
                'error': str(e)
            }
    
    def is_port_expired(self) -> bool:
        """
        Check if the current port has expired.
        
        Returns:
            True if port is expired, False otherwise
        """
        if not self.expires_at:
            return True
        
        try:
            # Parse expiration timestamp
            if isinstance(self.expires_at, str):
                # Handle ISO format timestamp
                expires_dt = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
            else:
                # Handle Unix timestamp
                expires_dt = datetime.fromtimestamp(self.expires_at, tz=timezone.utc)
            
            current_dt = datetime.now(timezone.utc)
            is_expired = current_dt >= expires_dt
            
            if is_expired:
                log_message(2, f"Port expired at {self.expires_at}")
            
            return is_expired
            
        except Exception as e:
            log_message(2, f"Error checking port expiration: {e}")
            return True  # Assume expired on error
    
    def cleanup(self):
        """Clean up all port forwarding resources."""
        log_message(3, "Cleaning up port forwarding resources")
        
        # Stop keepalive process
        self.stop_keepalive()
        
        # Clean up port file
        try:
            if self.port_file.exists():
                self.port_file.unlink()
                log_message(4, "Removed port file")
        except OSError as e:
            log_message(2, f"Failed to remove port file: {e}")
        
        # Clean up keepalive PID file
        try:
            if self.keepalive_file.exists():
                self.keepalive_file.unlink()
                log_message(4, "Removed keepalive PID file")
        except OSError as e:
            log_message(2, f"Failed to remove keepalive PID file: {e}")
        
        # Reset internal state
        self.current_port = None
        self.payload = None
        self.signature = None
        self.expires_at = None
        
        log_message(2, "Port forwarding cleanup completed")


def setup_port_forwarding(pf_hostname: str, pf_gateway: str, token: str, 
                         start_keepalive: bool = True) -> Optional[int]:
    """
    High-level function to set up PIA port forwarding.
    
    This function replicates the logic from the bash port_forwarding.sh script:
    1. Get port signature from PIA API
    2. Bind the port
    3. Start keepalive process if requested
    
    Args:
        pf_hostname: PIA server hostname
        pf_gateway: Gateway IP address
        token: Authentication token
        start_keepalive: Whether to start the keepalive process
        
    Returns:
        Port number if successful, None otherwise
        
    Raises:
        PortForwardError: If port forwarding setup fails
    """
    try:
        # Initialize port forward manager
        api_client = PiaApiClient() if PiaApiClient else None
        pf_manager = PortForwardManager(api_client)
        
        # Get and bind port
        port = pf_manager.get_and_bind_port(pf_hostname, pf_gateway, token)
        
        if port and start_keepalive:
            # Start keepalive process
            if pf_manager.payload and pf_manager.signature:
                pf_manager.start_keepalive(
                    pf_hostname, pf_gateway, 
                    pf_manager.payload, pf_manager.signature
                )
            else:
                log_message(1, "Cannot start keepalive: missing payload or signature")
        
        return port
        
    except Exception as e:
        if isinstance(e, PortForwardError):
            raise
        error_msg = f"Port forwarding setup failed: {e}"
        log_message(1, error_msg)
        raise PortForwardError(error_msg)
