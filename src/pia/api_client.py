#!/usr/bin/env python3

"""
PIA API Client Module

Provides robust API client for PIA services with professional error handling,
retry logic, and timeout management. Replaces the curl-based API calls from
the manual-connections bash scripts with proper Python HTTP client.

Features:
- Automatic retry with exponential backoff
- Comprehensive error handling and recovery
- SSL certificate validation with PIA CA
- Request/response logging for debugging
- Connection pooling for performance
- Timeout handling for reliability
"""

import json
import time
import base64
import logging
from typing import Dict, Any, Optional, Union, List
from pathlib import Path
from urllib.parse import urlencode
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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


class ApiError(Exception):
    """Base exception for PIA API errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class ConnectionError(ApiError):
    """Exception for network connection errors."""
    pass


class AuthenticationError(ApiError):
    """Exception for authentication failures."""
    pass


class ServerError(ApiError):
    """Exception for server-side errors."""
    pass


class PiaApiClient:
    """
    Professional PIA API client with comprehensive error handling and retry logic.
    
    Provides methods for:
    - Token generation and validation
    - Server list retrieval and caching
    - Dedicated IP management
    - WireGuard key exchange
    - Port forwarding signature acquisition
    """
    
    # PIA API endpoints
    BASE_URLS = {
        'auth': 'https://www.privateinternetaccess.com/api/client/v2',
        'servers': 'https://serverlist.piaservers.net/vpninfo/servers/v6',
        'wireguard': 'https://{hostname}:1337',
        'portforward': 'https://{hostname}:19999',
    }
    
    # Default timeouts (in seconds)
    DEFAULT_TIMEOUT = 30
    CONNECT_TIMEOUT = 10
    READ_TIMEOUT = 30
    
    # Retry configuration
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 1.0
    RETRY_STATUS_CODES = [500, 502, 503, 504]
    
    def __init__(self, ca_cert_path: Optional[Path] = None, timeout: Optional[int] = None):
        """
        Initialize PIA API client.
        
        Args:
            ca_cert_path: Path to PIA CA certificate for SSL verification
            timeout: Default timeout for requests
        """
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.ca_cert_path = ca_cert_path or Path(__file__).parent / "ca.rsa.4096.crt"
        
        # Initialize session with retry strategy
        self.session = requests.Session()
        self._setup_retry_strategy()
        
        log_message(3, f"PIA API client initialized with timeout: {self.timeout}s")
        if self.ca_cert_path.exists():
            log_message(3, f"Using CA certificate: {self.ca_cert_path}")
        else:
            log_message(1, f"Warning: CA certificate not found at {self.ca_cert_path}")
    
    def _setup_retry_strategy(self):
        """Configure retry strategy for HTTP requests."""
        retry_strategy = Retry(
            total=self.MAX_RETRIES,
            backoff_factor=self.BACKOFF_FACTOR,
            status_forcelist=self.RETRY_STATUS_CODES,
            allowed_methods=["HEAD", "GET", "POST"],
            raise_on_status=False
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        log_message(5, f"Configured retry strategy: {self.MAX_RETRIES} retries, backoff factor: {self.BACKOFF_FACTOR}")
    
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make HTTP request with error handling and logging.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: Additional arguments for requests
            
        Returns:
            Response object
            
        Raises:
            ConnectionError: For network connection issues
            ApiError: For API-specific errors
        """
        # Set default timeout if not provided
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.CONNECT_TIMEOUT, self.READ_TIMEOUT)
        
        # Only use PIA CA certificate for VPN-specific endpoints, not for main website
        if 'pia.vpn' in url or '1337' in url or '19999' in url:
            # VPN endpoints - use PIA CA certificate
            if self.ca_cert_path.exists() and kwargs.get('verify', True):
                kwargs['verify'] = str(self.ca_cert_path)
                log_message(5, f"Using PIA CA certificate for VPN endpoint: {url}")
        else:
            # Main PIA website - use system default CA certificates
            kwargs['verify'] = True
            log_message(5, f"Using system CA certificates for main website: {url}")
        
        log_message(5, f"Making {method} request to: {url}")
        
        try:
            response = self.session.request(method, url, **kwargs)
            
            # Log response details
            log_message(5, f"Response status: {response.status_code}")
            if response.headers.get('content-type', '').startswith('application/json'):
                try:
                    response_data = response.json()
                    log_message(5, f"Response data: {json.dumps(response_data, indent=2)}")
                except json.JSONDecodeError:
                    log_message(5, f"Response body: {response.text[:200]}...")
            
            return response
            
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error for {url}: {e}"
            log_message(1, error_msg)
            raise ConnectionError(error_msg)
        
        except requests.exceptions.Timeout as e:
            error_msg = f"Timeout error for {url}: {e}"
            log_message(1, error_msg)
            raise ConnectionError(error_msg)
        
        except requests.exceptions.RequestException as e:
            error_msg = f"Request error for {url}: {e}"
            log_message(1, error_msg)
            raise ApiError(error_msg)
    
    def _handle_response(self, response: requests.Response, expected_status: int = 200) -> Dict[str, Any]:
        """
        Handle API response and extract JSON data.
        
        Args:
            response: HTTP response object
            expected_status: Expected HTTP status code
            
        Returns:
            Parsed JSON response data
            
        Raises:
            AuthenticationError: For authentication failures
            ServerError: For server-side errors
            ApiError: For other API errors
        """
        if response.status_code == 401:
            raise AuthenticationError("Authentication failed - invalid credentials")
        
        if response.status_code == 403:
            raise AuthenticationError("Access forbidden - insufficient permissions")
        
        if response.status_code >= 500:
            raise ServerError(f"Server error: {response.status_code} - {response.text}")
        
        if response.status_code != expected_status:
            error_msg = f"Unexpected status code: {response.status_code} - {response.text}"
            log_message(1, error_msg)
            raise ApiError(error_msg, response.status_code)
        
        try:
            # Special handling for PIA server list endpoint which may have extra data
            if 'serverlist.piaservers.net' in response.url:
                # PIA server list returns multiple lines, we only need the first line (JSON)
                response_text = response.text.strip()
                first_line = response_text.split('\n')[0]
                data = json.loads(first_line)
            else:
                data = response.json()
            
            # Check for API-level error indicators
            if isinstance(data, dict):
                if data.get('status') == 'error':
                    error_msg = data.get('message', 'Unknown API error')
                    raise ApiError(f"API error: {error_msg}", response.status_code, data)
                
                if 'error' in data:
                    error_msg = data['error']
                    raise ApiError(f"API error: {error_msg}", response.status_code, data)
            
            return data
            
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON response: {e}"
            log_message(1, error_msg)
            raise ApiError(error_msg, response.status_code)
    
    def generate_token(self, username: str, password: str) -> Dict[str, Any]:
        """
        Generate authentication token from PIA credentials.
        
        Args:
            username: PIA username
            password: PIA password
            
        Returns:
            Token data with expiration information
            
        Raises:
            AuthenticationError: For invalid credentials
            ApiError: For other API errors
        """
        log_message(3, f"Generating token for user: {username}")
        
        url = f"{self.BASE_URLS['auth']}/token"
        data = {
            'username': username,
            'password': password
        }
        
        response = self._make_request('POST', url, data=data)
        token_data = self._handle_response(response)
        
        if not token_data.get('token'):
            raise ApiError("No token in response", response.status_code, token_data)
        
        log_message(2, "Successfully generated authentication token")
        return token_data
    
    def get_server_list(self) -> Dict[str, Any]:
        """
        Retrieve PIA server list.
        
        Returns:
            Server list data with regions and server information
            
        Raises:
            ApiError: For API errors
        """
        log_message(3, "Retrieving PIA server list")
        
        response = self._make_request('GET', self.BASE_URLS['servers'])
        server_data = self._handle_response(response)
        
        # Validate server list structure
        if not isinstance(server_data, dict) or 'regions' not in server_data:
            raise ApiError("Invalid server list format")
        
        regions = server_data['regions']
        if not isinstance(regions, list) or len(regions) == 0:
            raise ApiError("No regions found in server list")
        
        log_message(2, f"Retrieved server list with {len(regions)} regions")
        return server_data
    
    def get_dedicated_ip_info(self, token: str, dip_token: str) -> Dict[str, Any]:
        """
        Get dedicated IP information.
        
        Args:
            token: Authentication token
            dip_token: Dedicated IP token
            
        Returns:
            Dedicated IP information
            
        Raises:
            ApiError: For API errors
        """
        log_message(3, f"Getting dedicated IP info for token: {dip_token[:8]}...")
        
        url = f"{self.BASE_URLS['auth']}/dedicated_ip"
        headers = {'Authorization': f'Token {token}'}
        data = {'tokens': [dip_token]}
        
        response = self._make_request('POST', url, json=data, headers=headers)
        dip_data = self._handle_response(response)
        
        if not isinstance(dip_data, list) or len(dip_data) == 0:
            raise ApiError("No dedicated IP data returned")
        
        ip_info = dip_data[0]
        if ip_info.get('status') != 'active':
            raise ApiError(f"Dedicated IP not active: {ip_info.get('status')}")
        
        log_message(2, f"Retrieved dedicated IP: {ip_info.get('ip')}")
        return ip_info
    
    def wireguard_add_key(self, hostname: str, server_ip: str, token: str, public_key: str, 
                         dip_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Add WireGuard public key to PIA server.
        
        Args:
            hostname: Server hostname
            server_ip: Server IP address
            token: Authentication token
            public_key: WireGuard public key
            dip_token: Optional dedicated IP token
            
        Returns:
            WireGuard connection parameters
            
        Raises:
            ApiError: For API errors
        """
        log_message(3, f"Adding WireGuard key to server: {hostname}")
        
        url = self.BASE_URLS['wireguard'].format(hostname=hostname) + "/addKey"
        
        # Prepare request parameters
        params = {'pubkey': public_key}
        auth = None
        
        if dip_token:
            # Use dedicated IP authentication
            auth = (f"dedicated_ip_{dip_token}", server_ip)
            log_message(5, "Using dedicated IP authentication")
        else:
            # Use token authentication
            params['pt'] = token
            log_message(5, "Using token authentication")
        
        # Make request with custom connection settings
        response = self._make_request(
            'GET', 
            url, 
            params=params,
            auth=auth,
            headers={'Host': hostname} if auth else None
        )
        
        wg_data = self._handle_response(response)
        
        # Validate WireGuard response
        if wg_data.get('status') != 'OK':
            raise ApiError(f"WireGuard key addition failed: {wg_data}")
        
        required_fields = ['server_key', 'peer_ip', 'server_port', 'dns_servers']
        for field in required_fields:
            if field not in wg_data:
                raise ApiError(f"Missing required field in WireGuard response: {field}")
        
        log_message(2, f"Successfully added WireGuard key, peer IP: {wg_data['peer_ip']}")
        return wg_data
    
    def get_port_signature(self, hostname: str, gateway_ip: str, token: str) -> Dict[str, Any]:
        """
        Get port forwarding signature from PIA server.
        
        This replicates the bash script's --connect-to behavior by connecting
        to the gateway IP while using the hostname for SSL verification.
        The request must be made from outside the VPN namespace.
        
        Args:
            hostname: Server hostname (for SSL/TLS verification)
            gateway_ip: Gateway IP address (actual connection target)
            token: Authentication token
            
        Returns:
            Port signature and payload data
            
        Raises:
            ApiError: For API errors
        """
        log_message(3, f"Getting port signature from gateway: {gateway_ip}")
        
        # Port forwarding API must be called from within the VPN namespace
        # Use curl via ip netns exec to access the API from inside the namespace
        import subprocess
        
        try:
            # Port forwarding API is only accessible from within the VPN namespace
            cmd = [
                'ip', 'netns', 'exec', 'vpn',
                'curl', '-s', '-m', '5',  # Keep original 5 second timeout like bash script
                '--connect-to', f'{hostname}::{gateway_ip}:',  # Exact bash script syntax
                '--cacert', str(self.ca_cert_path),
                '-G', '--data-urlencode', f'token={token}',
                f'https://{hostname}:19999/getSignature'
            ]
            
            log_message(5, f"Executing curl command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            log_message(5, f"Curl exit code: {result.returncode}")
            log_message(5, f"Curl stdout: {result.stdout}")
            log_message(5, f"Curl stderr: {result.stderr}")
            
            if result.returncode != 0:
                error_msg = f"Curl command failed (exit {result.returncode})"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                if result.stdout:
                    error_msg += f" (stdout: {result.stdout})"
                raise ApiError(error_msg)
            
            # Parse JSON response
            try:
                signature_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise ApiError(f"Invalid JSON response from curl: {e}. Raw output: {result.stdout}")
            
        except subprocess.TimeoutExpired:
            raise ApiError("Port signature request timed out")
        except Exception as e:
            raise ApiError(f"Port signature request failed: {e}")
        
        # Validate signature response
        if signature_data.get('status') != 'OK':
            raise ApiError(f"Port signature request failed: {signature_data}")
        
        required_fields = ['payload', 'signature']
        for field in required_fields:
            if field not in signature_data:
                raise ApiError(f"Missing required field in signature response: {field}")
        
        # Decode and validate payload
        try:
            payload_data = json.loads(base64.b64decode(signature_data['payload']).decode())
            port = payload_data.get('port')
            expires_at = payload_data.get('expires_at')
            
            if not port or not expires_at:
                raise ApiError("Invalid payload data - missing port or expiration")
            
            log_message(2, f"Retrieved port signature for port: {port}")
            return signature_data
            
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ApiError(f"Failed to decode payload: {e}")
    
    def bind_port(self, hostname: str, gateway_ip: str, payload: str, signature: str) -> Dict[str, Any]:
        """
        Bind port using signature and payload.
        
        This must also be called from within the VPN namespace like get_port_signature.
        
        Args:
            hostname: Server hostname
            gateway_ip: Gateway IP address
            payload: Base64 encoded payload
            signature: Port signature
            
        Returns:
            Port binding confirmation
            
        Raises:
            ApiError: For API errors
        """
        log_message(3, f"Binding port on gateway: {gateway_ip}")
        
        # Port binding API must also be called from within the VPN namespace
        # Use curl via ip netns exec to access the API from inside the namespace
        import subprocess
        
        try:
            # Port binding API is only accessible from within the VPN namespace
            cmd = [
                'ip', 'netns', 'exec', 'vpn',
                'curl', '-s', '-m', '5',  # Keep original 5 second timeout like bash script
                '--connect-to', f'{hostname}::{gateway_ip}:',  # Exact bash script syntax
                '--cacert', str(self.ca_cert_path),
                '-G', '--data-urlencode', f'payload={payload}',
                '--data-urlencode', f'signature={signature}',
                f'https://{hostname}:19999/bindPort'
            ]
            
            log_message(5, f"Executing curl command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            log_message(5, f"Curl exit code: {result.returncode}")
            log_message(5, f"Curl stdout: {result.stdout}")
            log_message(5, f"Curl stderr: {result.stderr}")
            
            if result.returncode != 0:
                error_msg = f"Curl command failed (exit {result.returncode})"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                if result.stdout:
                    error_msg += f" (stdout: {result.stdout})"
                raise ApiError(error_msg)
            
            # Parse JSON response
            try:
                bind_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise ApiError(f"Invalid JSON response from curl: {e}. Raw output: {result.stdout}")
            
        except subprocess.TimeoutExpired:
            raise ApiError("Port binding request timed out")
        except Exception as e:
            raise ApiError(f"Port binding request failed: {e}")
        
        # Validate bind response
        if bind_data.get('status') != 'OK':
            raise ApiError(f"Port binding failed: {bind_data}")
        
        log_message(2, "Successfully bound port")
        return bind_data
    
    def test_latency(self, server_ip: str, timeout: float = 0.1) -> Optional[float]:
        """
        Test latency to a PIA server using TCP connection test.
        
        This matches the original bash script approach of testing connectivity
        via TCP connection rather than full HTTP requests.
        
        Args:
            server_ip: Server IP address to test
            timeout: Connection timeout in seconds
            
        Returns:
            Latency in seconds, or None if unreachable
        """
        log_message(5, f"Testing latency to server: {server_ip}")
        
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
                log_message(5, f"Server {server_ip} unreachable")
                return None
                
        except Exception as e:
            log_message(5, f"Latency test failed for {server_ip}: {e}")
            return None
    
    def close(self):
        """Close the HTTP session."""
        if hasattr(self, 'session'):
            self.session.close()
            log_message(5, "Closed API client session")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
