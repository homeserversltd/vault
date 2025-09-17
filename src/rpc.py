#!/usr/bin/env python3
"""
Transmission RPC Management Module

This module provides RPC-based configuration management for Transmission daemon,
allowing dynamic port setting and configuration updates without relying on
config file deployment that gets overwritten by the daemon.

The module handles:
- RPC authentication and connection management
- Dynamic peer port configuration
- Configuration validation and error handling
- Retry logic for transient connection issues

This solves the core issue where Transmission daemon overwrites our config file
with port 0 during startup, by using RPC calls to set the port dynamically.
"""

import json
import time
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass

from .utils import run_command
from .vpn import VPN_NS, TRANSMISSION_PORT

# We'll get log_message from the calling context to avoid import dependency issues

# Constants for RPC operations
TRANSMISSION_RPC_HOST = "127.0.0.1"
TRANSMISSION_RPC_PORT = 9091
TRANSMISSION_RPC_PATH = "/transmission/rpc/"
TRANSMISSION_REMOTE_PATH = "/usr/bin/transmission-remote"

# RPC request headers
RPC_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# Retry configuration
MAX_RPC_RETRIES = 3
RPC_RETRY_DELAY = 2  # seconds
RPC_TIMEOUT = 10  # seconds


@dataclass
class RPCConfig:
    """Configuration for Transmission RPC operations."""
    host: str = TRANSMISSION_RPC_HOST
    port: int = TRANSMISSION_RPC_PORT
    username: Optional[str] = None
    password: Optional[str] = None
    namespace: Optional[str] = None
    timeout: int = RPC_TIMEOUT


class TransmissionRPCError(Exception):
    """Custom exception for Transmission RPC operation failures."""
    pass


class TransmissionRPCManager:
    """
    Manages Transmission daemon configuration via RPC calls.
    
    This class provides methods to configure Transmission daemon settings
    dynamically after startup, bypassing the issue where the daemon
    overwrites our config file with default values.
    """
    
    def __init__(self, config: RPCConfig, log_message_func=None):
        """
        Initialize the RPC manager with connection configuration.
        
        Args:
            config: RPC connection configuration including credentials and namespace
            log_message_func: Optional logging function to use (avoids import dependency)
        """
        self.config = config
        self.session_id = None
        self.log_message = log_message_func or (lambda level, msg: None)  # Default no-op logger
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate the RPC configuration parameters."""
        if not self.config.username or not self.config.password:
            raise ValueError("Username and password are required for RPC operations")
        
        if self.config.port <= 0 or self.config.port > 65535:
            raise ValueError(f"Invalid RPC port: {self.config.port}")
    
    def _build_remote_command(self, args: list) -> list:
        """
        Build a transmission-remote command with proper namespace and authentication.
        
        Args:
            args: Additional arguments for transmission-remote
            
        Returns:
            Complete command list for execution
        """
        cmd = [TRANSMISSION_REMOTE_PATH]
        
        # Add namespace execution if specified
        if self.config.namespace:
            cmd = ["ip", "netns", "exec", self.config.namespace] + cmd
        
        # Add connection parameters
        cmd.extend([
            f"{self.config.host}:{self.config.port}",
            "-n", f"{self.config.username}:{self.config.password}"
        ])
        
        # Add the actual command arguments
        cmd.extend(args)
        
        return cmd
    
    def _execute_rpc_command(self, args: list, retries: int = MAX_RPC_RETRIES) -> subprocess.CompletedProcess:
        """
        Execute a transmission-remote command with retry logic.
        
        Args:
            args: Arguments for transmission-remote
            retries: Number of retry attempts
            
        Returns:
            Completed process result
            
        Raises:
            TransmissionRPCError: If all retry attempts fail
        """
        cmd = self._build_remote_command(args)
        
        for attempt in range(1, retries + 1):
            try:
                self.log_message(4, f"Executing RPC command (attempt {attempt}/{retries}): {' '.join(cmd)}")
                
                result = run_command(
                    cmd,
                    netns=None,  # We handle namespace in the command
                    sudo=True,
                    capture_output=True,
                    check=False,
                    timeout=self.config.timeout
                )
                
                if result.returncode == 0:
                    self.log_message(4, f"RPC command successful: {result.stdout.strip()}")
                    return result
                
                self.log_message(3, f"RPC command failed (attempt {attempt}): {result.stderr.strip()}")
                
                # Don't retry on authentication errors
                if "401" in result.stderr or "authentication" in result.stderr.lower():
                    raise TransmissionRPCError(f"Authentication failed: {result.stderr.strip()}")
                
                # Don't retry on invalid port errors
                if "connection refused" in result.stderr.lower():
                    raise TransmissionRPCError(f"Connection refused: {result.stderr.strip()}")
                
            except subprocess.TimeoutExpired:
                self.log_message(2, f"RPC command timed out (attempt {attempt})")
                if attempt == retries:
                    raise TransmissionRPCError("RPC command timed out after all retry attempts")
            except Exception as e:
                self.log_message(2, f"RPC command error (attempt {attempt}): {e}")
                if attempt == retries:
                    raise TransmissionRPCError(f"RPC command failed after all retry attempts: {e}")
            
            # Wait before retry (except on last attempt)
            if attempt < retries:
                self.log_message(3, f"Retrying RPC command in {RPC_RETRY_DELAY} seconds...")
                time.sleep(RPC_RETRY_DELAY)
        
        raise TransmissionRPCError(f"RPC command failed after {retries} attempts")
    
    def test_connection(self) -> bool:
        """
        Test the RPC connection to Transmission daemon.
        
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            # Use session-info to test connection (lightweight operation)
            result = self._execute_rpc_command(["--session-info"])
            return result.returncode == 0
        except Exception as e:
            self.log_message(2, f"RPC connection test failed: {e}")
            return False
    
    def set_peer_port(self, port: int) -> bool:
        """
        Set the peer port for incoming connections via RPC.
        
        Args:
            port: The port number to set for peer connections
            
        Returns:
            True if port was set successfully, False otherwise
            
        Raises:
            TransmissionRPCError: If the operation fails
        """
        if port <= 0 or port > 65535:
            raise ValueError(f"Invalid peer port: {port}")
        
        self.log_message(3, f"Setting Transmission peer port to {port} via RPC...")
        
        try:
            # Set the peer port using the port option
            result = self._execute_rpc_command([
                "--port", str(port)
            ])
            
            if result.returncode == 0:
                self.log_message(2, f"Successfully set Transmission peer port to {port}")
                
                # Verify the port was actually set
                if self.verify_peer_port(port):
                    self.log_message(2, f"Verified Transmission peer port is now {port}")
                    return True
                else:
                    self.log_message(1, f"Failed to verify peer port was set to {port}")
                    return False
            else:
                raise TransmissionRPCError(f"Failed to set peer port: {result.stderr.strip()}")
                
        except Exception as e:
            self.log_message(1, f"Error setting peer port to {port}: {e}")
            raise TransmissionRPCError(f"Failed to set peer port: {e}")
    
    def verify_peer_port(self, expected_port: int) -> bool:
        """
        Verify that the peer port was set correctly.
        
        Args:
            expected_port: The port number we expect to be set
            
        Returns:
            True if the port matches, False otherwise
        """
        try:
            # Get current session settings
            result = self._execute_rpc_command(["--session-info"])
            
            if result.returncode == 0:
                try:
                    # Parse the session info output to find the peer port
                    output = result.stdout.strip()
                    # Look for "Listenport: <port>" in the output (actual field name from session-info)
                    for line in output.split('\n'):
                        if 'Listenport:' in line:
                            current_port = int(line.split(':')[1].strip())
                            if current_port == expected_port:
                                self.log_message(4, f"Peer port verification successful: {current_port}")
                                return True
                            else:
                                self.log_message(3, f"Peer port mismatch: expected {expected_port}, got {current_port}")
                                return False
                    
                    # If we didn't find the peer port in the output 
                    self.log_message(2, "Could not find peer port in session info")
                    return False
                        
                except (ValueError, IndexError) as e:
                    self.log_message(2, f"Failed to parse session info: {e}")
                    return False
            else:
                self.log_message(2, f"Failed to get session info: {result.stderr.strip()}")
                return False
                
        except Exception as e:
            self.log_message(2, f"Error verifying peer port: {e}")
            return False
    
    def get_current_peer_port(self) -> Optional[int]:
        """
        Get the current peer port setting from Transmission.
        
        Returns:
            Current peer port number, or None if unable to retrieve
        """
        try:
            result = self._execute_rpc_command(["--session-info"])
            
            if result.returncode == 0:
                try:
                    # Parse the session info output to find the peer port
                    output = result.stdout.strip()
                    # Look for "Listenport: <port>" in the output (actual field name from session-info)
                    for line in output.split('\n'):
                        if 'Listenport:' in line:
                            return int(line.split(':')[1].strip())
                    
                    # If we didn't find the peer port in the output
                    self.log_message(2, "Could not find peer port in session info")
                    return None
                        
                except (ValueError, IndexError) as e:
                    self.log_message(2, f"Failed to parse session info: {e}")
                    return None
            else:
                self.log_message(2, f"Failed to get session info: {result.stderr.strip()}")
                return None
                
        except Exception as e:
            self.log_message(2, f"Error getting current peer port: {e}")
            return None
    
    def wait_for_daemon_ready(self, max_wait: int = 30) -> bool:
        """
        Wait for Transmission daemon to be ready for RPC connections.
        
        Args:
            max_wait: Maximum time to wait in seconds
            
        Returns:
            True if daemon becomes ready, False if timeout
        """
        self.log_message(3, f"Waiting for Transmission daemon to be ready (max {max_wait}s)...")
        
        start_time = time.time()
        while time.time() - start_time < max_wait:
            if self.test_connection():
                self.log_message(2, "Transmission daemon is ready for RPC connections")
                return True
            
            self.log_message(4, "Transmission daemon not ready yet, waiting...")
            time.sleep(2)
        
        self.log_message(1, f"Transmission daemon not ready after {max_wait} seconds")
        return False

    def rescan_directories(self, directories: list) -> bool:
        """
        Rescan directories to reattach to existing torrents and incomplete downloads.
        
        This implements the correct workflow:
        1. Add any .torrent files from watch directories
        2. Use --find on each torrent to locate existing data
        
        Args:
            directories: List of directory paths to rescan
            
        Returns:
            True if rescan was successful, False otherwise
            
        Raises:
            TransmissionRPCError: If the operation fails
        """
        if not directories:
            raise ValueError("At least one directory must be specified for rescan")
        
        self.log_message(3, f"Rescanning {len(directories)} directories for existing torrent data...")
        
        try:
            # Step 1: Add any .torrent files from watch directories
            watch_dirs = [d for d in directories if "objectives" in d or "watch" in d]
            if watch_dirs:
                self.log_message(3, "Scanning watch directories for .torrent files...")
                for watch_dir in watch_dirs:
                    if Path(watch_dir).exists():
                        # Find all .torrent files
                        torrent_files = list(Path(watch_dir).glob("*.torrent*"))
                        for torrent_file in torrent_files:
                            self.log_message(4, f"Adding torrent file: {torrent_file}")
                            try:
                                result = self._execute_rpc_command(["-a", str(torrent_file)])
                                if result.returncode == 0:
                                    self.log_message(4, f"Successfully added torrent: {torrent_file}")
                                else:
                                    self.log_message(2, f"Warning: Failed to add torrent {torrent_file}: {result.stderr.strip()}")
                            except Exception as e:
                                self.log_message(2, f"Warning: Failed to add torrent {torrent_file}: {e}")
            
            # Step 2: Get list of all torrents
            self.log_message(3, "Getting current torrent list...")
            try:
                result = self._execute_rpc_command(["-l"])
                if result.returncode != 0:
                    self.log_message(2, "Could not get torrent list, skipping data location")
                    return True
                
                # Parse torrent list to get IDs
                torrent_ids = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and line[0].isdigit():
                        # Parse "ID   Done   Have  ETA..." format
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            torrent_ids.append(parts[0])
                
                if not torrent_ids:
                    self.log_message(3, "No torrents found to rescan")
                    return True
                
                self.log_message(3, f"Found {len(torrent_ids)} torrents to rescan")
                
                # Step 3: Use --find on each torrent for each data directory
                data_dirs = [d for d in directories if "objectives" not in d and "watch" not in d]
                if not data_dirs:
                    self.log_message(2, "No data directories found for --find operations")
                    return True
                
                for torrent_id in torrent_ids:
                    for data_dir in data_dirs:
                        if Path(data_dir).exists():
                            self.log_message(4, f"Using --find on torrent {torrent_id} for directory: {data_dir}")
                            try:
                                result = self._execute_rpc_command([
                                    "-t", torrent_id,
                                    "--find", data_dir
                                ])
                                if result.returncode == 0:
                                    self.log_message(4, f"Successfully used --find on torrent {torrent_id} for {data_dir}")
                                else:
                                    self.log_message(2, f"Warning: --find failed on torrent {torrent_id} for {data_dir}: {result.stderr.strip()}")
                            except Exception as e:
                                self.log_message(2, f"Warning: --find failed on torrent {torrent_id} for {data_dir}: {e}")
                
            except Exception as e:
                self.log_message(2, f"Error during torrent rescan: {e}")
                # Continue anyway - we've at least added the torrent files
            
            self.log_message(2, "Directory rescan completed")
            return True
            
        except Exception as e:
            self.log_message(1, f"Error during directory rescan: {e}")
            raise TransmissionRPCError(f"Failed to rescan directories: {e}")
    
    def rescan_default_directories(self) -> bool:
        """
        Rescan the default Transmission directories for existing torrent data.
        
        This will rescan the download directory, incomplete directory, and watch
        directory to reattach to existing torrents.
        
        Returns:
            True if rescan was successful, False otherwise
        """
        try:
            # Get current session settings to find configured directories
            result = self._execute_rpc_command(["--session-info"])
            
            if result.returncode != 0:
                self.log_message(2, "Could not get session info, using default directories")
                # Fall back to common default directories
                default_dirs = [
                    "/mnt/nas/downloads/complete/",
                    "/mnt/nas/downloads/incomplete/",
                    "/mnt/nas/downloads/objectives/"
                ]
                return self.rescan_directories(default_dirs)
            
            # Parse session info to find configured directories
            directories = []
            output = result.stdout.strip()
            
            for line in output.split('\n'):
                if 'Download directory:' in line:
                    download_dir = line.split(':', 1)[1].strip()
                    if download_dir and Path(download_dir).exists():
                        directories.append(download_dir)
                elif 'Incomplete directory:' in line:
                    incomplete_dir = line.split(':', 1)[1].strip()
                    if incomplete_dir and Path(incomplete_dir).exists():
                        directories.append(incomplete_dir)
                elif 'Watch directory:' in line:
                    watch_dir = line.split(':', 1)[1].strip()
                    if watch_dir and Path(watch_dir).exists():
                        directories.append(watch_dir)
            
            # Always add the watch directory we know exists
            watch_dir = "/mnt/nas/downloads/objectives/"
            if watch_dir not in directories and Path(watch_dir).exists():
                directories.append(watch_dir)
            
            if not directories:
                self.log_message(2, "No configured directories found, using defaults")
                default_dirs = [
                    "/mnt/nas/downloads/complete/",
                    "/mnt/nas/downloads/incomplete/",
                    "/mnt/nas/downloads/objectives/"
                ]
                directories = [d for d in default_dirs if Path(d).exists()]
            
            if directories:
                return self.rescan_directories(directories)
            else:
                self.log_message(2, "No valid directories found to rescan")
                return False
                
        except Exception as e:
            self.log_message(1, f"Error during default directory rescan: {e}")
            return False


def create_rpc_manager(
    username: str,
    password: str,
    namespace: Optional[str] = None,
    host: str = TRANSMISSION_RPC_HOST,
    port: int = TRANSMISSION_RPC_PORT,
    log_message_func=None
) -> TransmissionRPCManager:
    """
    Factory function to create a TransmissionRPCManager instance.
    
    Args:
        username: Transmission RPC username
        password: Transmission RPC password
        namespace: Network namespace (e.g., 'vpn')
        host: RPC host address
        port: RPC port number
        
    Returns:
        Configured TransmissionRPCManager instance
    """
    config = RPCConfig(
        host=host,
        port=port,
        username=username,
        password=password,
        namespace=namespace
    )
    
    return TransmissionRPCManager(config, log_message_func)


def set_transmission_peer_port(
    port: int,
    username: str,
    password: str,
    namespace: Optional[str] = None,
    wait_for_ready: bool = True,
    log_message_func=None
) -> bool:
    """
    Convenience function to set Transmission peer port via RPC.
    
    Args:
        port: The peer port number to set
        username: Transmission RPC username
        password: Transmission RPC password
        namespace: Network namespace (e.g., 'vpn')
        wait_for_ready: Whether to wait for daemon to be ready
        log_message_func: Optional logging function to use
        
    Returns:
        True if port was set successfully, False otherwise
    """
    try:
        rpc_manager = create_rpc_manager(username, password, namespace, log_message_func=log_message_func)
        
        if wait_for_ready:
            if not rpc_manager.wait_for_daemon_ready():
                if log_message_func:
                    log_message_func(1, "Transmission daemon not ready for RPC operations")
                return False
        
        return rpc_manager.set_peer_port(port)
        
    except Exception as e:
        if log_message_func:
            log_message_func(1, f"Failed to set Transmission peer port: {e}")
        return False


def rescan_transmission_directories(
    username: str,
    password: str,
    directories: Optional[list] = None,
    namespace: Optional[str] = None,
    host: str = TRANSMISSION_RPC_HOST,
    port: int = TRANSMISSION_RPC_PORT,
    log_message_func=None
) -> bool:
    """
    Convenience function to rescan Transmission directories for existing torrent data.
    
    Args:
        username: Transmission RPC username
        password: Transmission RPC password
        directories: Optional list of specific directories to rescan.
                   If None, will rescan default directories.
        namespace: Network namespace (e.g., 'vpn')
        host: RPC host address
        port: RPC port number
        log_message_func: Optional logging function to use
        
    Returns:
        True if rescan was successful, False otherwise
    """
    try:
        rpc_manager = create_rpc_manager(username, password, namespace, host, port, log_message_func=log_message_func)
        
        if directories:
            return rpc_manager.rescan_directories(directories)
        else:
            return rpc_manager.rescan_default_directories()
        
    except Exception as e:
        if log_message_func:
            log_message_func(1, f"Failed to rescan Transmission directories: {e}")
        return False


# Export main classes and functions
__all__ = [
    'TransmissionRPCManager',
    'RPCConfig',
    'TransmissionRPCError',
    'create_rpc_manager',
    'set_transmission_peer_port',
    'rescan_transmission_directories'
]
