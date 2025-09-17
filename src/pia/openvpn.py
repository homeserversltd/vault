#!/usr/bin/env python3

"""
PIA OpenVPN Management Module

Complete implementation of PIA OpenVPN connection management.
Replaces the bash-based OpenVPN logic with professional Python implementation
featuring real process management, config generation, and comprehensive error handling.

Features:
- Real OpenVPN process management in network namespaces
- Dynamic config generation from templates
- DNS configuration and restoration
- Connection monitoring and status reporting
- Comprehensive error handling and recovery
- Process cleanup and resource management
"""

import os
import time
import subprocess
import signal
import threading
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
import tempfile

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


class OpenVpnError(Exception):
    """Exception for OpenVPN errors."""
    pass


class OpenVpnConfigManager:
    """
    Professional OpenVPN configuration management.
    
    Provides methods for:
    - Dynamic config generation from templates
    - Credential file management
    - Up/down script configuration
    - Transport and encryption settings
    """
    
    # OpenVPN port mappings
    PORT_MAP = {
        ('udp', 'standard'): 1198,
        ('udp', 'strong'): 1197,
        ('tcp', 'standard'): 502,
        ('tcp', 'strong'): 501
    }
    
    # Standard OpenVPN config template
    STANDARD_CONFIG = """client
dev tun06
resolv-retry infinite
nobind
persist-key
persist-tun
cipher aes-128-cbc
auth sha1
tls-client
remote-cert-tls server

auth-user-pass {credentials_path}
compress
verb 1
reneg-sec 0

<ca>
-----BEGIN CERTIFICATE-----
MIIFqzCCBJOgAwIBAgIJAKZ7D5Yv87qDMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzM1
MThaFw0zNDA0MTIxNzM1MThaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
bmV0YWNjZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPXD
L1L9tX6DGf36liA7UBTy5I869z0UVo3lImfOs/GSiFKPtInlesP65577nd7UNzzX
lH/P/CnFPdBWlLp5ze3HRBCc/Avgr5CdMRkEsySL5GHBZsx6w2cayQ2EcRhVTwWp
cdldeNO+pPr9rIgPrtXqT4SWViTQRBeGM8CDxAyTopTsobjSiYZCF9Ta1gunl0G/
8Vfp+SXfYCC+ZzWvP+L1pFhPRqzQQ8k+wMZIovObK1s+nlwPaLyayzw9a8sUnvWB
/5rGPdIYnQWPgoNlLN9HpSmsAcw2z8DXI9pIxbr74cb3/HSfuYGOLkRqrOk6h4RC
OfuWoTrZup1uEOn+fw8CAwEAAaOCAVQwggFQMB0GA1UdDgQWBBQv63nQ/pJAt5tL
y8VJcbHe22ZOsjCCAR8GA1UdIwSCARYwggESgBQv63nQ/pJAt5tLy8VJcbHe22ZO
sqGB7qSB6zCB6DELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRMwEQYDVQQHEwpM
b3NBbmdlbGVzMSAwHgYDVQQKExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4G
A1UECxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBAMTF1ByaXZhdGUg
SW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQpExdQcml2YXRlIEludGVybmV0IEFjY2Vz
czEvMC0GCSqGSIb3DQEJARYgc2VjdXJlQHByaXZhdGVpbnRlcm5ldGFjY2Vzcy5j
b22CCQCmew+WL/O6gzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAQAn
a5PgrtxfwTumD4+3/SYvwoD66cB8IcK//h1mCzAduU8KgUXocLx7QgJWo9lnZ8xU
ryXvWab2usg4fqk7FPi00bED4f4qVQFVfGfPZIH9QQ7/48bPM9RyfzImZWUCenK3
7pdw4Bvgoys2rHLHbGen7f28knT2j/cbMxd78tQc20TIObGjo8+ISTRclSTRBtyC
GohseKYpTS9himFERpUgNtefvYHbn70mIOzfOJFTVqfrptf9jXa9N8Mpy3ayfodz
1wiqdteqFXkTYoSDctgKMiZ6GdocK9nMroQipIQtpnwd4yBDWIyC6Bvlkrq5TQUt
YDQ8z9v+DMO6iwyIDRiU
-----END CERTIFICATE-----
</ca>

disable-occ
script-security 2
up {up_script}
down {down_script}
remote {server_ip} {port} {transport}
"""

    # Strong OpenVPN config template
    STRONG_CONFIG = """client
dev tun06
resolv-retry infinite
nobind
persist-key
persist-tun
cipher aes-256-cbc
auth sha256
tls-client
remote-cert-tls server

auth-user-pass {credentials_path}
compress
verb 1
reneg-sec 0

<ca>
-----BEGIN CERTIFICATE-----
MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw
MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk
hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN
De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K
V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ
25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND
fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl
p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p
Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj
tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi
jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz
meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz
1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV
HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt
yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl
cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw
HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0
ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl
aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt
pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv
Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G
tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu
LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs
6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3
5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX
JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ
iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l
8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW
+no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=
-----END CERTIFICATE-----
</ca>

disable-occ
script-security 2
up {up_script}
down {down_script}
remote {server_ip} {port} {transport}
"""

    def __init__(self, work_dir: Path = None):
        """
        Initialize OpenVPN config manager.
        
        Args:
            work_dir: Working directory for config files
        """
        self.work_dir = work_dir or Path("/opt/piavpn-manual")
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        log_message(3, "OpenVpnConfigManager initialized with real config generation")
    
    def create_credentials_file(self, token: str, dip_token: Optional[str] = None) -> Path:
        """
        Create OpenVPN credentials file.
        
        Args:
            token: PIA authentication token
            dip_token: Optional dedicated IP token
            
        Returns:
            Path to credentials file
        """
        credentials_path = self.work_dir / "credentials"
        
        try:
            if dip_token:
                # Use dedicated IP authentication
                split_token = f"dedicated_ip_{dip_token}"
                credentials_content = f"{split_token[:62]}\n{split_token[62:]}"
                log_message(3, "Created credentials file with dedicated IP token")
            else:
                # Use regular token authentication
                credentials_content = f"{token[:62]}\n{token[62:]}"
                log_message(3, "Created credentials file with authentication token")
            
            with open(credentials_path, 'w') as f:
                f.write(credentials_content)
            
            # Set secure permissions
            credentials_path.chmod(0o600)
            
            return credentials_path
            
        except Exception as e:
            raise OpenVpnError(f"Failed to create credentials file: {e}")
    
    def create_up_script(self, namespace: str = "vpn", use_pia_dns: bool = False) -> Path:
        """
        Create OpenVPN up script.
        
        Args:
            namespace: Network namespace name
            use_pia_dns: Whether to use PIA DNS servers
            
        Returns:
            Path to up script
        """
        up_script_path = self.work_dir / "openvpn_up.sh"
        
        if use_pia_dns:
            up_script_content = f"""#!/usr/bin/env bash

# Write gateway IP for reference
echo "$route_vpn_gateway" > {self.work_dir}/route_info

# Back up resolv.conf and create new one with PIA DNS
cat /etc/resolv.conf > {self.work_dir}/resolv_conf_backup
ip netns exec {namespace} bash -c "echo '# Generated by PIA VPN
nameserver 10.0.0.241' > /etc/resolv.conf"
"""
        else:
            up_script_content = f"""#!/usr/bin/env bash

# Write gateway IP for reference
echo "$route_vpn_gateway" > {self.work_dir}/route_info
"""
        
        try:
            with open(up_script_path, 'w') as f:
                f.write(up_script_content)
            
            up_script_path.chmod(0o755)
            log_message(3, f"Created up script: {up_script_path}")
            
            return up_script_path
            
        except Exception as e:
            raise OpenVpnError(f"Failed to create up script: {e}")
    
    def create_down_script(self, namespace: str = "vpn", use_pia_dns: bool = False) -> Path:
        """
        Create OpenVPN down script.
        
        Args:
            namespace: Network namespace name
            use_pia_dns: Whether PIA DNS was used
            
        Returns:
            Path to down script
        """
        down_script_path = self.work_dir / "openvpn_down.sh"
        
        if use_pia_dns:
            down_script_content = f"""#!/usr/bin/env bash

# Remove process and route information when connection closes
rm -rf {self.work_dir}/pia_pid {self.work_dir}/route_info

# Restore namespace DNS when closing
ip netns exec {namespace} bash -c "cat {self.work_dir}/resolv_conf_backup > /etc/resolv.conf"
"""
        else:
            down_script_content = f"""#!/usr/bin/env bash

# Remove process and route information when connection closes
rm -rf {self.work_dir}/pia_pid {self.work_dir}/route_info
"""
        
        try:
            with open(down_script_path, 'w') as f:
                f.write(down_script_content)
            
            down_script_path.chmod(0o755)
            log_message(3, f"Created down script: {down_script_path}")
            
            return down_script_path
            
        except Exception as e:
            raise OpenVpnError(f"Failed to create down script: {e}")
    
    def generate_config(self, server_ip: str, server_hostname: str, transport: str = "udp",
                       encryption: str = "standard", namespace: str = "vpn",
                       use_pia_dns: bool = False) -> Tuple[Path, Path, Path, Path]:
        """
        Generate complete OpenVPN configuration.
        
        Args:
            server_ip: PIA server IP address
            server_hostname: PIA server hostname
            transport: Transport protocol (udp/tcp)
            encryption: Encryption level (standard/strong)
            namespace: Network namespace name
            use_pia_dns: Whether to use PIA DNS servers
            
        Returns:
            Tuple of (config_path, credentials_path, up_script_path, down_script_path)
            
        Raises:
            OpenVpnError: If config generation fails
        """
        try:
            # Get port for transport/encryption combination
            port = self.PORT_MAP.get((transport, encryption))
            if not port:
                raise OpenVpnError(f"Invalid transport/encryption combination: {transport}/{encryption}")
            
            # Create up and down scripts
            up_script_path = self.create_up_script(namespace, use_pia_dns)
            down_script_path = self.create_down_script(namespace, use_pia_dns)
            
            # Select config template
            if encryption == "strong":
                config_template = self.STRONG_CONFIG
            else:
                config_template = self.STANDARD_CONFIG
            
            # Generate config content
            config_content = config_template.format(
                server_ip=server_ip,
                port=port,
                transport=transport,
                credentials_path=str(self.work_dir / "credentials"),
                up_script=str(up_script_path),
                down_script=str(down_script_path)
            )
            
            # Write config file
            config_path = self.work_dir / "pia.ovpn"
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            config_path.chmod(0o644)
            
            log_message(2, f"Generated OpenVPN config: {config_path}")
            log_message(3, f"Server: {server_hostname} ({server_ip}:{port}/{transport})")
            log_message(3, f"Encryption: {encryption}, DNS: {'PIA' if use_pia_dns else 'system'}")
            
            # Return paths (credentials will be created separately)
            return config_path, self.work_dir / "credentials", up_script_path, down_script_path
            
        except Exception as e:
            if isinstance(e, OpenVpnError):
                raise
            error_msg = f"Failed to generate OpenVPN config: {e}"
            log_message(1, error_msg)
            raise OpenVpnError(error_msg)


class OpenVpnManager:
    """
    Professional OpenVPN connection management with real process control.
    
    Provides methods for:
    - OpenVPN process management in network namespaces
    - Connection monitoring and status reporting
    - Gateway IP extraction and routing
    - Process cleanup and resource management
    - Connection validation and error handling
    """
    
    def __init__(self, work_dir: Path = None):
        """
        Initialize OpenVPN manager.
        
        Args:
            work_dir: Working directory for OpenVPN files
        """
        self.work_dir = work_dir or Path("/opt/piavpn-manual")
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        self.config_manager = OpenVpnConfigManager(self.work_dir)
        
        # Process management
        self.process = None
        self.pid_file = self.work_dir / "pia_pid"
        self.log_file = self.work_dir / "debug_info"
        self.route_file = self.work_dir / "route_info"
        
        # Connection state
        self.connected = False
        self.server_ip = None
        self.gateway_ip = None
        self.transport = None
        self.encryption = None
        
        log_message(3, "OpenVpnManager initialized with real process management")
    
    def _check_interface_conflict(self, interface: str = "tun06") -> bool:
        """
        Check if OpenVPN interface already exists.
        
        Args:
            interface: Interface name to check
            
        Returns:
            True if interface exists, False otherwise
        """
        try:
            result = subprocess.run(
                ["ip", "a", "s", interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Interface exists if command succeeds and doesn't contain "does not exist"
            if result.returncode == 0 and "does not exist" not in result.stderr:
                log_message(2, f"Interface {interface} already exists")
                return True
            
            return False
            
        except Exception as e:
            log_message(2, f"Error checking interface {interface}: {e}")
            return False
    
    def _kill_existing_process(self) -> bool:
        """
        Kill existing OpenVPN process if found.
        
        Returns:
            True if process was killed, False if no process found
        """
        try:
            if self.pid_file.exists():
                with open(self.pid_file, 'r') as f:
                    old_pid = int(f.read().strip())
                
                # Check if process is actually OpenVPN
                try:
                    result = subprocess.run(
                        ["ps", "-p", str(old_pid), "-o", "comm="],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0 and "openvpn" in result.stdout:
                        log_message(2, f"Killing existing OpenVPN process: {old_pid}")
                        os.kill(old_pid, signal.SIGTERM)
                        
                        # Wait for process to terminate
                        for _ in range(5):
                            time.sleep(1)
                            try:
                                os.kill(old_pid, 0)  # Check if process still exists
                            except OSError:
                                break  # Process is gone
                        
                        return True
                        
                except (subprocess.TimeoutExpired, OSError, ProcessLookupError):
                    pass
            
            return False
            
        except Exception as e:
            log_message(2, f"Error killing existing process: {e}")
            return False
    
    def _wait_for_connection(self, timeout: int = 10) -> bool:
        """
        Wait for OpenVPN connection to establish.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if connected, False if timeout
        """
        confirmation = "Initialization Sequence Complete"
        
        for i in range(timeout):
            time.sleep(1)
            
            try:
                if self.log_file.exists():
                    with open(self.log_file, 'r') as f:
                        log_content = f.read()
                        if confirmation in log_content:
                            log_message(2, "OpenVPN connection established")
                            return True
                        
                        # Check for common error patterns
                        if "AUTH_FAILED" in log_content:
                            raise OpenVpnError("Authentication failed")
                        if "TLS_ERROR" in log_content:
                            raise OpenVpnError("TLS handshake failed")
                        if "RESOLVE" in log_content and "Cannot resolve host address" in log_content:
                            raise OpenVpnError("Cannot resolve server hostname")
                            
            except Exception as e:
                if isinstance(e, OpenVpnError):
                    raise
                log_message(3, f"Error reading log file: {e}")
        
        return False
    
    def _get_gateway_ip(self) -> Optional[str]:
        """
        Get VPN gateway IP from route info file.
        
        Returns:
            Gateway IP address or None if not found
        """
        try:
            if self.route_file.exists():
                with open(self.route_file, 'r') as f:
                    gateway_ip = f.read().strip()
                    if gateway_ip:
                        log_message(3, f"VPN gateway IP: {gateway_ip}")
                        return gateway_ip
        except Exception as e:
            log_message(2, f"Error reading gateway IP: {e}")
        
        return None
    
    def connect(self, server_ip: str, server_hostname: str, token: str,
               dip_token: Optional[str] = None, transport: str = "udp",
               encryption: str = "standard", namespace: str = "vpn",
               dns_servers: Optional[List[str]] = None, use_pia_dns: bool = False) -> Dict[str, Any]:
        """
        Connect to PIA server via OpenVPN.
        
        Args:
            server_ip: PIA server IP address
            server_hostname: PIA server hostname
            token: Authentication token
            dip_token: Optional dedicated IP token
            transport: Transport protocol (udp/tcp)
            encryption: Encryption level (standard/strong)
            namespace: Network namespace name
            dns_servers: Optional DNS servers (unused, kept for compatibility)
            use_pia_dns: Whether to use PIA DNS servers
            
        Returns:
            Connection information dictionary
            
        Raises:
            OpenVpnError: If connection fails
        """
        try:
            log_message(2, f"Connecting to OpenVPN server: {server_hostname} ({transport}/{encryption})")
            
            # Check for interface conflicts
            if self._check_interface_conflict("tun06"):
                if not self._kill_existing_process():
                    raise OpenVpnError("Interface tun06 exists but no OpenVPN process found")
                
                # Wait a bit for cleanup
                time.sleep(2)
            
            # Generate OpenVPN configuration
            config_path, credentials_path, up_script, down_script = self.config_manager.generate_config(
                server_ip=server_ip,
                server_hostname=server_hostname,
                transport=transport,
                encryption=encryption,
                namespace=namespace,
                use_pia_dns=use_pia_dns
            )
            
            # Create credentials file
            self.config_manager.create_credentials_file(token, dip_token)
            
            # Clean up old files
            for old_file in [self.pid_file, self.log_file, self.route_file]:
                if old_file.exists():
                    old_file.unlink()
            
            # Start OpenVPN process in namespace
            openvpn_cmd = [
                "ip", "netns", "exec", namespace,
                "openvpn",
                "--daemon",
                "--config", str(config_path),
                "--writepid", str(self.pid_file),
                "--log", str(self.log_file)
            ]
            
            log_message(3, f"Starting OpenVPN: {' '.join(openvpn_cmd)}")
            
            result = subprocess.run(
                openvpn_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                error_msg = f"OpenVPN failed to start: {result.stderr}"
                log_message(1, error_msg)
                raise OpenVpnError(error_msg)
            
            # Wait for connection to establish
            if not self._wait_for_connection(timeout=10):
                # Try to get more info from log
                error_info = "Connection timeout"
                if self.log_file.exists():
                    try:
                        with open(self.log_file, 'r') as f:
                            log_content = f.read()
                            # Extract last few lines for error context
                            lines = log_content.strip().split('\n')
                            error_info = f"Connection timeout. Last log entries: {'; '.join(lines[-3:])}"
                    except Exception:
                        pass
                
                self.disconnect()
                raise OpenVpnError(error_info)
            
            # Get process PID and gateway IP
            ovpn_pid = None
            if self.pid_file.exists():
                with open(self.pid_file, 'r') as f:
                    ovpn_pid = int(f.read().strip())
            
            gateway_ip = self._get_gateway_ip()
            
            # Update connection state
            self.connected = True
            self.server_ip = server_ip
            self.gateway_ip = gateway_ip
            self.transport = transport
            self.encryption = encryption
            
            connection_info = {
                'connected': True,
                'protocol': 'openvpn',
                'server_ip': server_ip,
                'server_hostname': server_hostname,
                'gateway_ip': gateway_ip,
                'transport': transport,
                'encryption': encryption,
                'process_id': ovpn_pid,
                'namespace': namespace
            }
            
            log_message(1, f"OpenVPN connection successful - PID: {ovpn_pid}, Gateway: {gateway_ip}")
            
            return connection_info
            
        except Exception as e:
            if isinstance(e, OpenVpnError):
                raise
            error_msg = f"OpenVPN connection failed: {e}"
            log_message(1, error_msg)
            raise OpenVpnError(error_msg)
    
    def disconnect(self):
        """Disconnect OpenVPN and clean up resources."""
        log_message(2, "Disconnecting OpenVPN")
        
        # Kill OpenVPN process
        if self.pid_file.exists():
            try:
                with open(self.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                
                log_message(3, f"Terminating OpenVPN process: {pid}")
                os.kill(pid, signal.SIGTERM)
                
                # Wait for graceful shutdown
                for _ in range(5):
                    time.sleep(1)
                    try:
                        os.kill(pid, 0)  # Check if process still exists
                    except OSError:
                        break  # Process is gone
                else:
                    # Force kill if still running
                    try:
                        os.kill(pid, signal.SIGKILL)
                        log_message(2, "Force killed OpenVPN process")
                    except OSError:
                        pass
                        
            except Exception as e:
                log_message(2, f"Error terminating OpenVPN process: {e}")
        
        # Clean up files
        for cleanup_file in [self.pid_file, self.log_file, self.route_file]:
            try:
                if cleanup_file.exists():
                    cleanup_file.unlink()
            except Exception as e:
                log_message(3, f"Error removing {cleanup_file}: {e}")
        
        # Reset connection state
        self.connected = False
        self.server_ip = None
        self.gateway_ip = None
        self.transport = None
        self.encryption = None
        
        log_message(2, "OpenVPN disconnection completed")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get comprehensive OpenVPN status.
        
        Returns:
            Status dictionary with connection and process info
        """
        try:
            # Check if PID file exists and process is running
            process_running = False
            pid = None
            
            if self.pid_file.exists():
                try:
                    with open(self.pid_file, 'r') as f:
                        pid = int(f.read().strip())
                    
                    # Check if process is actually running
                    os.kill(pid, 0)
                    process_running = True
                    
                except (OSError, ValueError):
                    process_running = False
            
            # Get gateway IP if available
            gateway_ip = self._get_gateway_ip() if process_running else None
            
            status = {
                'connected': process_running and self.connected,
                'process_running': process_running,
                'process_id': pid,
                'server_ip': self.server_ip,
                'gateway_ip': gateway_ip or self.gateway_ip,
                'transport': self.transport,
                'encryption': self.encryption
            }
            
            # Add file status
            status['files'] = {
                'pid_file': self.pid_file.exists(),
                'log_file': self.log_file.exists(),
                'route_file': self.route_file.exists()
            }
            
            return status
            
        except Exception as e:
            log_message(2, f"Error getting OpenVPN status: {e}")
            return {
                'connected': False,
                'process_running': False,
                'error': str(e)
            }


def connect_openvpn(server_ip: str, server_hostname: str, token: str,
                   transport: str = "udp", encryption: str = "standard",
                   namespace: str = "vpn", dip_token: Optional[str] = None,
                   use_pia_dns: bool = False) -> Dict[str, Any]:
    """
    High-level function to connect to PIA via OpenVPN.
    
    This function replicates the logic from the bash connect_to_openvpn_with_token.sh script:
    1. Generate OpenVPN configuration
    2. Create credentials and scripts
    3. Start OpenVPN process in namespace
    4. Wait for connection establishment
    5. Return connection information
    
    Args:
        server_ip: PIA server IP address
        server_hostname: PIA server hostname
        token: Authentication token
        transport: Transport protocol (udp/tcp)
        encryption: Encryption level (standard/strong)
        namespace: Network namespace name
        dip_token: Optional dedicated IP token
        use_pia_dns: Whether to use PIA DNS servers
        
    Returns:
        Connection information dictionary
        
    Raises:
        OpenVpnError: If connection fails
    """
    try:
        # Initialize OpenVPN manager
        ovpn_manager = OpenVpnManager()
        
        # Connect to server
        connection_info = ovpn_manager.connect(
            server_ip=server_ip,
            server_hostname=server_hostname,
            token=token,
            dip_token=dip_token,
            transport=transport,
            encryption=encryption,
            namespace=namespace,
            use_pia_dns=use_pia_dns
        )
        
        return connection_info
        
    except Exception as e:
        if isinstance(e, OpenVpnError):
            raise
        error_msg = f"OpenVPN connection failed: {e}"
        log_message(1, error_msg)
        raise OpenVpnError(error_msg)
