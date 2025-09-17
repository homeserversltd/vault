#!/usr/bin/env python3

"""
PIA Server Selection Module

Complete implementation of PIA server discovery and selection functionality.
Replaces the bash-based server selection logic with professional Python implementation
featuring real API calls, latency testing, and comprehensive error handling.

Features:
- Real PIA server list retrieval from official API
- Multi-threaded latency testing for performance
- Port forwarding server filtering
- Region validation and selection
- Comprehensive error handling and recovery
"""

import time
import concurrent.futures
from typing import Dict, Any, List, Optional
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

# Import API client for server communication
try:
    from .api_client import PiaApiClient, ApiError, ConnectionError
except ImportError:
    log_message(1, "Warning: Could not import PIA API client, using fallback")
    PiaApiClient = None
    ApiError = Exception
    ConnectionError = Exception


class ServerSelectionError(Exception):
    """Exception for server selection errors."""
    pass


class ServerSelector:
    """
    Professional PIA server selection with real API integration.
    
    Provides methods for:
    - Retrieving live server list from PIA API
    - Filtering servers by port forwarding support
    - Region validation and selection
    - Server metadata extraction
    """
    
    def __init__(self, api_client: Optional[PiaApiClient] = None):
        """
        Initialize server selector.
        
        Args:
            api_client: Optional PIA API client instance
        """
        self.api_client = api_client or (PiaApiClient() if PiaApiClient else None)
        self._server_cache = None
        self._cache_timestamp = 0
        self._cache_ttl = 300  # 5 minutes cache TTL
        
        log_message(3, "ServerSelector initialized with real PIA API integration")
    
    def get_server_list(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get PIA server list with caching.
        
        Args:
            force_refresh: Force refresh of cached data
            
        Returns:
            Complete server list data from PIA API
            
        Raises:
            ServerSelectionError: If server list cannot be retrieved
        """
        current_time = time.time()
        
        # Return cached data if valid and not forcing refresh
        if (not force_refresh and 
            self._server_cache and 
            current_time - self._cache_timestamp < self._cache_ttl):
            log_message(4, "Using cached server list")
            return self._server_cache
        
        if not self.api_client:
            raise ServerSelectionError("No API client available for server list retrieval")
        
        try:
            log_message(3, "Retrieving fresh server list from PIA API")
            server_data = self.api_client.get_server_list()
            
            # Validate server data structure
            if not isinstance(server_data, dict) or 'regions' not in server_data:
                raise ServerSelectionError("Invalid server list format received")
            
            regions = server_data['regions']
            if not isinstance(regions, list) or len(regions) == 0:
                raise ServerSelectionError("No regions found in server list")
            
            # Cache the data
            self._server_cache = server_data
            self._cache_timestamp = current_time
            
            log_message(2, f"Successfully retrieved server list with {len(regions)} regions")
            return server_data
            
        except ApiError as e:
            error_msg = f"Failed to retrieve server list: {e}"
            log_message(1, error_msg)
            raise ServerSelectionError(error_msg)
    
    def get_available_servers(self, token: str, port_forward_required: bool = False, 
                            max_latency: float = 0.1, preferred_region: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get available servers based on criteria.
        
        Args:
            token: Authentication token
            port_forward_required: Filter for port forwarding support
            max_latency: Maximum acceptable latency in seconds
            preferred_region: Specific region ID to select
            
        Returns:
            List of available servers matching criteria
            
        Raises:
            ServerSelectionError: If no servers match criteria
        """
        try:
            server_data = self.get_server_list()
            regions = server_data['regions']
            
            available_servers = []
            
            for region in regions:
                region_id = region.get('id')
                region_name = region.get('name')
                port_forward = region.get('port_forward', False)
                geo_located = region.get('geo', False)
                
                # Skip if specific region requested and this isn't it
                if preferred_region and region_id != preferred_region:
                    continue
                
                # Skip if port forwarding required but not supported
                if port_forward_required and not port_forward:
                    log_message(4, f"Skipping region {region_name} - no port forwarding")
                    continue
                
                # Extract server information for different protocols
                servers = region.get('servers', {})
                
                # Get meta server (for general connectivity)
                meta_servers = servers.get('meta', [])
                if meta_servers:
                    meta_server = meta_servers[0]  # Use first meta server
                    server_info = {
                        'region_id': region_id,
                        'region_name': region_name,
                        'ip': meta_server.get('ip'),
                        'hostname': meta_server.get('cn'),
                        'port_forward': port_forward,
                        'geo_located': geo_located,
                        'servers': servers  # Include all server types
                    }
                    available_servers.append(server_info)
                    log_message(4, f"Added server: {region_name} ({region_id}) - IP: {server_info['ip']}")
            
            if not available_servers:
                if preferred_region:
                    raise ServerSelectionError(f"No servers found for region: {preferred_region}")
                else:
                    criteria = []
                    if port_forward_required:
                        criteria.append("port forwarding")
                    raise ServerSelectionError(f"No servers match criteria: {', '.join(criteria) if criteria else 'none'}")
            
            log_message(2, f"Found {len(available_servers)} available servers")
            return available_servers
            
        except Exception as e:
            if isinstance(e, ServerSelectionError):
                raise
            error_msg = f"Error getting available servers: {e}"
            log_message(1, error_msg)
            raise ServerSelectionError(error_msg)
    
    def validate_region(self, region_id: str) -> bool:
        """
        Validate that a region ID exists.
        
        Args:
            region_id: Region ID to validate
            
        Returns:
            True if region exists, False otherwise
        """
        try:
            server_data = self.get_server_list()
            regions = server_data['regions']
            
            for region in regions:
                if region.get('id') == region_id:
                    log_message(4, f"Region {region_id} is valid")
                    return True
            
            log_message(2, f"Region {region_id} not found")
            return False
            
        except Exception as e:
            log_message(1, f"Error validating region {region_id}: {e}")
            return False
    
    def get_region_info(self, region_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific region.
        
        Args:
            region_id: Region ID to get info for
            
        Returns:
            Region information dict or None if not found
        """
        try:
            server_data = self.get_server_list()
            regions = server_data['regions']
            
            for region in regions:
                if region.get('id') == region_id:
                    log_message(3, f"Retrieved info for region: {region.get('name')} ({region_id})")
                    return region
            
            log_message(2, f"Region {region_id} not found")
            return None
            
        except Exception as e:
            log_message(1, f"Error getting region info for {region_id}: {e}")
            return None


class LatencyTester:
    """
    Professional latency testing with multi-threading and comprehensive error handling.
    
    Provides methods for:
    - Multi-threaded latency testing for performance
    - Server ranking by response time
    - Timeout and error handling
    - Connection validation
    """
    
    def __init__(self, api_client: Optional[PiaApiClient] = None):
        """
        Initialize latency tester.
        
        Args:
            api_client: Optional PIA API client instance
        """
        self.api_client = api_client or (PiaApiClient() if PiaApiClient else None)
        self.max_workers = 10  # Limit concurrent connections
        
        log_message(3, "LatencyTester initialized with multi-threading support")
    
    def test_server_latency(self, server: Dict[str, Any], timeout: float = 0.1) -> Optional[float]:
        """
        Test latency to a single server.
        
        Args:
            server: Server information dict
            timeout: Connection timeout in seconds
            
        Returns:
            Latency in seconds or None if unreachable
        """
        server_ip = server.get('ip')
        if not server_ip:
            log_message(2, f"No IP address for server: {server.get('hostname', 'unknown')}")
            return None
        
        if self.api_client:
            return self.api_client.test_latency(server_ip, timeout)
        else:
            # Fallback implementation using basic socket connection
            import socket
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((server_ip, 443))
                sock.close()
                
                if result == 0:
                    latency = time.time() - start_time
                    log_message(5, f"Latency to {server_ip}: {latency:.3f}s")
                    return latency
                else:
                    log_message(5, f"Connection failed to {server_ip}")
                    return None
                    
            except Exception as e:
                log_message(5, f"Latency test failed for {server_ip}: {e}")
                return None
    
    def find_fastest_server(self, servers: List[Dict[str, Any]], max_latency: float = 0.5) -> Optional[Dict[str, Any]]:
        """
        Find the fastest server from a list using multi-threaded latency testing.
        
        Args:
            servers: List of server information dicts
            max_latency: Maximum acceptable latency in seconds
            
        Returns:
            Server with lowest latency or None if none are acceptable
        """
        if not servers:
            log_message(2, "No servers provided for latency testing")
            return None
        
        log_message(3, f"Testing latency for {len(servers)} servers (max: {max_latency}s)")
        
        # Test latency for all servers concurrently
        server_latencies = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all latency tests
            future_to_server = {
                executor.submit(self.test_server_latency, server, max_latency): server
                for server in servers
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_server):
                server = future_to_server[future]
                try:
                    latency = future.result()
                    if latency is not None and latency <= max_latency:
                        server_copy = server.copy()
                        server_copy['latency'] = latency
                        server_latencies.append(server_copy)
                        
                        region_name = server.get('region_name', 'unknown')
                        log_message(4, f"Server {region_name}: {latency:.3f}s latency")
                    else:
                        region_name = server.get('region_name', 'unknown')
                        if latency:
                            log_message(4, f"Server {region_name}: {latency:.3f}s (too slow)")
                        else:
                            log_message(4, f"Server {region_name}: unreachable")
                            
                except Exception as e:
                    region_name = server.get('region_name', 'unknown')
                    log_message(2, f"Latency test failed for {region_name}: {e}")
        
        if not server_latencies:
            log_message(1, f"No servers responded within {max_latency}s timeout")
            return None
        
        # Sort by latency and return the fastest
        server_latencies.sort(key=lambda x: x['latency'])
        fastest_server = server_latencies[0]
        
        log_message(2, f"Fastest server: {fastest_server.get('region_name')} "
                      f"({fastest_server.get('region_id')}) - {fastest_server['latency']:.3f}s")
        
        return fastest_server
    
    def rank_servers_by_latency(self, servers: List[Dict[str, Any]], max_latency: float = 0.1) -> List[Dict[str, Any]]:
        """
        Rank all servers by latency.
        
        Args:
            servers: List of server information dicts
            max_latency: Maximum acceptable latency in seconds
            
        Returns:
            List of servers sorted by latency (fastest first)
        """
        if not servers:
            return []
        
        log_message(3, f"Ranking {len(servers)} servers by latency")
        
        server_latencies = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all latency tests
            future_to_server = {
                executor.submit(self.test_server_latency, server, max_latency): server
                for server in servers
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_server):
                server = future_to_server[future]
                try:
                    latency = future.result()
                    if latency is not None and latency <= max_latency:
                        server_copy = server.copy()
                        server_copy['latency'] = latency
                        server_latencies.append(server_copy)
                        
                except Exception as e:
                    region_name = server.get('region_name', 'unknown')
                    log_message(4, f"Latency test failed for {region_name}: {e}")
        
        # Sort by latency
        server_latencies.sort(key=lambda x: x['latency'])
        
        log_message(2, f"Ranked {len(server_latencies)} servers by latency")
        return server_latencies


def select_optimal_server(token: str, port_forward_required: bool = False, 
                         max_latency: float = 0.5, preferred_region: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    High-level function to select the optimal PIA server.
    
    This function replicates the logic from the bash get_region.sh script:
    1. Get available servers based on criteria
    2. Test latency to all servers
    3. Return the fastest server within acceptable latency
    
    Args:
        token: PIA authentication token
        port_forward_required: Require port forwarding support
        max_latency: Maximum acceptable latency in seconds
        preferred_region: Specific region to use (skip latency testing)
        
    Returns:
        Optimal server information or None if none found
        
    Raises:
        ServerSelectionError: If server selection fails
    """
    try:
        # Initialize components
        api_client = PiaApiClient() if PiaApiClient else None
        server_selector = ServerSelector(api_client)
        latency_tester = LatencyTester(api_client)
        
        # Get available servers
        servers = server_selector.get_available_servers(
            token=token,
            port_forward_required=port_forward_required,
            max_latency=max_latency,
            preferred_region=preferred_region
        )
        
        if not servers:
            raise ServerSelectionError("No servers available matching criteria")
        
        # If specific region requested, return first server (already filtered)
        if preferred_region:
            server = servers[0]
            log_message(2, f"Using preferred region: {server['region_name']} ({server['region_id']})")
            return server
        
        # Find fastest server through latency testing
        optimal_server = latency_tester.find_fastest_server(servers, max_latency)
        
        if not optimal_server:
            raise ServerSelectionError(f"No servers responded within {max_latency}s")
        
        return optimal_server
        
    except Exception as e:
        if isinstance(e, ServerSelectionError):
            raise
        error_msg = f"Server selection failed: {e}"
        log_message(1, error_msg)
        raise ServerSelectionError(error_msg)
