#!/usr/bin/env python3

import subprocess
import os
import time
import sys
from pathlib import Path
# Safe logging function that falls back to print
def safe_log(level, message):
    try:
        from .logger import log_message as real_log_message
        if real_log_message is not None:
            real_log_message(level, message)
        else:
            print(f"[{level}] {message}")
    except (ImportError, AttributeError):
        print(f"[{level}] {message}")

# Alias for backward compatibility
log_message = safe_log
from .utils import (
    run_command, generate_compliant_mac_address, remove_rules_by_comment,
    terminate_processes, find_pids
)

# --- Configuration ---
VAULT_DIR = Path("/vault")
SCRIPTS_DIR = VAULT_DIR / "scripts"
PIA_CONN_SCRIPT = SCRIPTS_DIR / "manual-connections" / "run_setup.sh"
RAMDISK_MNT = Path("/mnt/ramdisk")
LOGS_DIR = RAMDISK_MNT / "logs"
PORT_FILE = Path("/tmp/port.pid")

# Network configuration
WAN_IF = "enp1s0"    # WAN Interface
LAN_IF = "enp2s0"    # LAN Interface
VPN_IF = "veth0"     # Interface in the host, peer is veth1 in namespace
VPN_NS = "vpn"
VPN_PEER_IF = "veth1"
HOST_VETH_IP = "192.168.2.1"
NS_VETH_IP = "192.168.2.2"
VETH_SUBNET = "24"
NS_GATEWAY = HOST_VETH_IP
DNS_SERVER = "1.1.1.1"
TRANSMISSION_PORT = 9091
TRANSMISSION_CONFIG_DIR = "/etc/transmission-daemon"

# Global variable for the VPN port
vpn_port = None


def initialize_network_interface():
    """Sets up the network namespace, veth pair, IPs, routes, and basic firewall rules."""
    log_message(3, "Initializing network interface...")

    # Check/Create Network Namespace
    try:
        result = run_command("ip netns list", capture_output=True, sudo=True)
        if VPN_NS not in result.stdout:
            log_message(3, f"Attempting to create the network namespace '{VPN_NS}'.")
            run_command(f"ip netns add {VPN_NS}", sudo=True)
            log_message(2, f"Created network namespace '{VPN_NS}'.")
        else:
            log_message(5, f"Existing '{VPN_NS}' namespace detected.")
    except Exception as e:
        log_message(1, f"Failed during namespace check/creation: {e}")
        sys.exit(1)

    # Create veth pair if not exists (check one side)
    try:
         result = run_command(f"ip link show {VPN_IF}", check=False, capture_output=True, sudo=True)
         if result.returncode != 0: # Interface does not exist
             log_message(3, "Attempting to create the veth pair.")
             run_command(f"ip link add {VPN_IF} type veth peer name {VPN_PEER_IF}", sudo=True)
             log_message(2, "Created veth pair.")
         else:
             log_message(5, f"veth interface '{VPN_IF}' already exists.")
    except Exception as e:
         log_message(1, f"Failed to create veth pair: {e}")
         sys.exit(1)

    # Assign MACs, move peer to namespace, set IPs, bring up interfaces
    try:
        veth0_mac = generate_compliant_mac_address()
        veth1_mac = generate_compliant_mac_address()
        log_message(4, f"VETH0_MAC={veth0_mac}, VETH1_MAC={veth1_mac}.")

        run_command(f"ip link set dev {VPN_IF} address {veth0_mac}", sudo=True)
        # Check if peer is already in namespace before moving
        result = run_command(f"ip netns exec {VPN_NS} ip link show {VPN_PEER_IF}", check=False, sudo=True, capture_output=True)
        if result.returncode != 0:
             log_message(3, f"Attempting to assign {VPN_PEER_IF} to namespace '{VPN_NS}'.")
             run_command(f"ip link set {VPN_PEER_IF} netns {VPN_NS}", sudo=True)
             log_message(2, f"Assigned {VPN_PEER_IF} to namespace '{VPN_NS}'.")
        else:
             log_message(5, f"{VPN_PEER_IF} already in namespace '{VPN_NS}'.")
        
        run_command(f"ip netns exec {VPN_NS} ip link set dev {VPN_PEER_IF} address {veth1_mac}", sudo=True)

        log_message(3, "Bringing up interfaces.")
        run_command(f"ip link set {VPN_IF} up", sudo=True)
        run_command(f"ip netns exec {VPN_NS} ip link set {VPN_PEER_IF} up", sudo=True)
        run_command(f"ip netns exec {VPN_NS} ip link set lo up", sudo=True)
        log_message(2, "Interfaces brought up.")

        log_message(3, "Assigning IP addresses.")
        run_command(f"ip addr add {HOST_VETH_IP}/{VETH_SUBNET} dev {VPN_IF}", sudo=True)
        run_command(f"ip netns exec {VPN_NS} ip addr add {NS_VETH_IP}/{VETH_SUBNET} dev {VPN_PEER_IF}", sudo=True)
        log_message(2, "IP addresses assigned.")

        log_message(3, f"Adding default route in namespace '{VPN_NS}'.")
        run_command(f"ip netns exec {VPN_NS} ip route add default via {NS_GATEWAY}", sudo=True)
        log_message(2, f"Added default route in namespace '{VPN_NS}'.")

        log_message(3, "Enabling IP forwarding.")
        # Use sysctl command
        run_command("sysctl -w net.ipv4.ip_forward=1", sudo=True)
        log_message(2, "Enabled IP forwarding.")

        log_message(3, "Configuring DNS for the namespace.")
        ns_resolv_dir = Path(f"/etc/netns/{VPN_NS}")
        ns_resolv_dir.mkdir(parents=True, exist_ok=True)
        resolv_conf_path = ns_resolv_dir / "resolv.conf"
        # Write using tee with sudo
        run_command(f'echo "nameserver {DNS_SERVER}" | sudo tee {resolv_conf_path} > /dev/null', shell=True, sudo=False) # sudo is in the command string
        log_message(2, "DNS configured for the namespace.")

        # Add initial firewall rules
        allow_outbound_traffic()
        allow_lan_to_vpn_traffic_port()

    except Exception as e:
        log_message(1, f"Failed during network interface setup: {e}")
        # Consider adding cleanup logic here if partial setup occurred
        sys.exit(1)

    log_message(0, "Network interface initialization complete.")


def allow_lan_to_vpn_traffic_port():
    """Adds nftables rules to allow LAN access to Transmission Web UI and NAT."""
    log_message(3, "Configuring firewall for LAN to VPN communication (Port 9091).")
    port = TRANSMISSION_PORT
    try:
        log_message(3, f"Allowing traffic from {LAN_IF} to {VPN_IF} on port {port}.")
        run_command(f'nft add rule inet filter forward iifname "{LAN_IF}" oifname "{VPN_IF}" tcp dport {port} accept comment "lan-to-vpn-traffic-port"', sudo=True, shell=True)

        log_message(3, f"Allowing return traffic from {VPN_IF} to {LAN_IF} on port {port}.")
        run_command(f'nft add rule inet filter forward iifname "{VPN_IF}" oifname "{LAN_IF}" tcp sport {port} accept comment "vpn-to-lan-traffic-port"', sudo=True, shell=True)

        log_message(3, f"Adding NAT masquerade rule for {VPN_IF}.")
        # Check if rule exists before adding to avoid errors if script reruns
        result = run_command("sudo nft list ruleset", capture_output=True, shell=True)
        if f'oifname "{VPN_IF}" masquerade comment "nat-masquerade-vpn"' not in result.stdout:
            run_command(f'nft add rule ip nat postrouting oifname "{VPN_IF}" masquerade comment "nat-masquerade-vpn"', sudo=True, shell=True)
            log_message(2, f"Added NAT masquerade rule for {VPN_IF}.")
        else:
             log_message(5, f"NAT masquerade rule for {VPN_IF} already exists.")

        log_message(0, f"Added firewall rules to allow LAN/VPN communication on port {port} and NAT.")
    except Exception as e:
        log_message(1, f"Failed to add LAN/VPN firewall rules: {e}")
        # Consider cleanup or exit


def allow_outbound_traffic():
    """Adds nftables rule to allow traffic from VPN namespace out via WAN."""
    log_message(3, "Configuring firewall for VPN outbound traffic.")
    try:
        log_message(3, f"Adding rule to allow outbound traffic from {VPN_IF} to {WAN_IF}.")
         # Check if rule exists before adding
        result = run_command("sudo nft list ruleset", capture_output=True, shell=True)
        if f'iifname "{VPN_IF}" oifname "{WAN_IF}" accept comment "outbound-vpn-traffic"' not in result.stdout:
            run_command(f'nft add rule inet filter forward iifname "{VPN_IF}" oifname "{WAN_IF}" accept comment "outbound-vpn-traffic"', sudo=True, shell=True)
            log_message(2, f"Added rule to allow outbound traffic from {VPN_IF} to {WAN_IF}.")
        else:
            log_message(5, "Outbound VPN traffic rule already exists.")

        log_message(0, "Added firewall rule for VPN outbound traffic.")
    except Exception as e:
        log_message(1, f"Failed to add outbound firewall rule: {e}")
        # Consider cleanup or exit


def allow_port_ingress():
    """Adds nftables rules to allow inbound traffic on the dynamically assigned VPN port."""
    global vpn_port
    if not vpn_port:
        log_message(1, "VPN port not set. Cannot add rule for inbound traffic.")
        return 1 # Return an error code

    log_message(3, f"Configuring firewall for inbound VPN traffic on port {vpn_port}.")
    
    try:
        # Note: The logic of removing/re-adding final drop rule is complex and potentially fragile.
        # Consider alternative approaches if possible (e.g., inserting rule at specific position).
        # For direct translation, we'll replicate the comment-based removal/addition.

        log_message(3, "Temporarily removing final drop rule in input chain (if it exists).")
        remove_rules_by_comment('inet', 'filter', 'input', 'final-drop')

        log_message(3, f"Adding nft rule to allow inbound traffic on port {vpn_port} from {WAN_IF} to host.")
        run_command(f'nft add rule inet filter input iifname "{WAN_IF}" tcp dport {vpn_port} accept comment "inbound-vpn-rule"', sudo=True, shell=True)
        log_message(2, f"Successfully added rule to allow inbound traffic on port {vpn_port}.")

        log_message(3, f"Adding nft rule to forward inbound traffic on port {vpn_port} from {WAN_IF} to {VPN_IF}.")
        run_command(f'nft add rule inet filter forward iifname "{WAN_IF}" oifname "{VPN_IF}" tcp dport {vpn_port} accept comment "wan-to-vpn-traffic-port"', sudo=True, shell=True)
        log_message(2, f"Successfully added forwarding rule from {WAN_IF} to {VPN_IF} on port {vpn_port}.")

        log_message(3, "Re-adding the final drop rule in the input chain.")
        # Check if rule already exists before adding back
        result = run_command("sudo nft list ruleset", capture_output=True, shell=True)
        if 'drop comment "final-drop"' not in result.stdout: # Simplified check
             run_command('nft add rule inet filter input drop comment "final-drop"', sudo=True, shell=True)
             log_message(2, "Successfully re-added the final drop rule in the input chain.")
        else:
             log_message(5, "Final drop rule already exists in input chain.")

        log_message(0, f"Added firewall rules for inbound communication over {vpn_port} to the VPN namespace.")
        return 0 # Success
    except Exception as e:
        log_message(1, f"Failed to add inbound firewall rules for port {vpn_port}. Error: {e}")
        # Try to re-add drop rule even on failure?
        try:
            result = run_command("sudo nft list ruleset", capture_output=True, shell=True)
            if 'drop comment "final-drop"' not in result.stdout:
                run_command('nft add rule inet filter input drop comment "final-drop"', sudo=True, shell=True)
                log_message(3, "Attempted to re-add final drop rule after error.")
        except Exception as final_e:
             log_message(1, f"Failed to re-add final drop rule after error: {final_e}")
        return 1 # Failure


def inject_auth_into_ovpn_config(auth_file):
    """Ensure the OpenVPN config file has the auth-user-pass directive."""
    ovpn_config = "/opt/piavpn-manual/pia.ovpn"
    
    # First check if the file exists - it might be created by the PIA script
    if not os.path.exists(ovpn_config):
        log_message(3, f"OpenVPN config file {ovpn_config} doesn't exist yet. Will inject auth later if needed.")
        return
    
    # Check if auth-user-pass is already in the config
    try:
        with open(ovpn_config, 'r') as f:
            content = f.read()
        
        if 'auth-user-pass' in content:
            # Check if it has a path argument
            auth_line_present = False
            for line in content.splitlines():
                if line.strip().startswith('auth-user-pass'):
                    parts = line.strip().split(None, 1)
                    if len(parts) > 1 and parts[1] == auth_file:
                        log_message(3, f"Auth file {auth_file} already properly configured in {ovpn_config}")
                        auth_line_present = True
                        break
            
            if not auth_line_present:
                # Replace existing auth-user-pass line with our path
                new_content = []
                for line in content.splitlines():
                    if line.strip().startswith('auth-user-pass'):
                        new_content.append(f"auth-user-pass {auth_file}")
                    else:
                        new_content.append(line)
                
                with open(ovpn_config, 'w') as f:
                    f.write('\n'.join(new_content))
                log_message(2, f"Updated auth-user-pass directive in {ovpn_config} to use {auth_file}")
        else:
            # Append auth-user-pass directive
            with open(ovpn_config, 'a') as f:
                f.write(f"\nauth-user-pass {auth_file}\n")
            log_message(2, f"Added auth-user-pass directive to {ovpn_config} using {auth_file}")
    
    except Exception as e:
        log_message(1, f"Error injecting auth into OpenVPN config: {e}")


def connect_vpn(credentials):
    """
    Connects to PIA VPN using the new Python PIA integration system.
    
    This function has been upgraded to use professional Python PIA modules
    instead of bash scripts, while maintaining full compatibility with the
    existing HOMESERVER infrastructure.
    """
    global vpn_port
    log_message(0, "Connecting to PIA VPN using professional Python integration...")

    # Import PIA integration (lazy import to avoid circular dependencies)
    try:
        from .pia.integration import pia_connect_vpn
        log_message(3, "Successfully loaded PIA Python integration")
    except ImportError as e:
        log_message(1, f"Failed to import PIA integration: {e}")
        log_message(1, "Falling back to legacy bash script method...")
        return connect_vpn_legacy(credentials)

    # Ensure required directories are accessible in namespace
    log_message(3, "Ensuring required directories are accessible in VPN namespace...")
    try:
        # Ensure ramdisk directory exists in namespace (handled by fstab, no mount needed)
        run_command(f"mkdir -p {RAMDISK_MNT}", netns=VPN_NS, sudo=True)
        
        # Setup PIA manual directory (shared filesystem, no mounting needed)
        pia_dir = "/opt/piavpn-manual"
        run_command(f"mkdir -p {pia_dir}", sudo=True)  # Create on host - accessible in namespace via shared filesystem
        log_message(2, f"PIA directory {pia_dir} ready - accessible via shared filesystem")

        # Transmission config directory is accessible via shared filesystem - no mounting needed
        log_message(3, f"Transmission config at {TRANSMISSION_CONFIG_DIR} accessible via shared filesystem")

        # Note: We use full paths for binaries instead of mounting /usr/bin
        log_message(3, "Using full paths for transmission binaries - no mounting required")

        # Setup tun device in namespace
        log_message(3, "Setting up tun device in namespace...")
        try:
            # Remove existing tun device if it exists
            run_command(f"ip netns exec {VPN_NS} ip link delete tun06 2>/dev/null || true", shell=True, check=False)
            
            # Create new tun device
            run_command(f"sudo ip netns exec {VPN_NS} ip tuntap add name tun06 mode tun", sudo=True)
            run_command(f"sudo ip netns exec {VPN_NS} ip link set tun06 up", sudo=True)
            log_message(2, f"Successfully setup tun06 in VPN namespace")
            
            # Transmission will use the namespace config directory directly
            # No symlinks needed - let Transmission read the config file from /etc/netns/vpn/transmission-daemon
            log_message(3, "Transmission will use namespace config directory directly - no symlinks needed")

        except Exception as e:
            log_message(1, f"Failed to setup tun device: {e}")
            raise
    except Exception as e:
        log_message(1, f"Failed to setup directories/devices in namespace: {e}")
        sys.exit(1)

    # Use the new PIA Python integration system
    try:
        log_message(3, "Attempting VPN connection with PIA Python integration...")
        
        # Call the new PIA integration system
        vpn_port = pia_connect_vpn(
            credentials=credentials,
            protocol="openvpn_udp_standard",  # Default protocols
            enable_port_forwarding=True,
            dip_token=None  # TODO: Add DIP token support if needed
        )
        
        if vpn_port:
            # Configure firewall rules for the obtained port
            if allow_port_ingress() == 0:
                log_message(0, "PIA VPN connection established successfully with Python integration.")
                return vpn_port
            else:
                log_message(1, "VPN connected but firewall configuration failed")
                sys.exit(1)
        else:
            log_message(1, "PIA VPN connection failed")
            sys.exit(1)
            
    except Exception as e:
        log_message(1, f"PIA Python integration failed: {e}")
        log_message(1, "Python integration is required - legacy bash script method is no longer supported.")
        sys.exit(1)


def connect_vpn_legacy(credentials):
    """
    Legacy VPN connection method using bash scripts.
    
    This is the original connect_vpn implementation that uses the manual-connections
    bash scripts. It's kept as a fallback in case the new Python integration fails.
    """
    global vpn_port
    log_message(3, "Using legacy bash script VPN connection method...")

    MAX_RETRIES = 5
    RETRY_DELAY = 30  # seconds
    FILE_CHECK_RETRIES = 3
    FILE_CHECK_DELAY = 10 # seconds
    VPN_PROCESS = None

    pia_user = credentials.get("pia", {}).get("username")
    pia_pass = credentials.get("pia", {}).get("password")

    if not pia_user or not pia_pass:
        log_message(1, "PIA credentials not found.")
        sys.exit(1)
    
    # Create auth file for OpenVPN to avoid password prompt
    auth_file = f"{RAMDISK_MNT}/openvpn_auth.txt"
    try:
        # Write auth file with username and password
        with open(auth_file, 'w') as f:
            f.write(f"{pia_user}\n{pia_pass}\n")
        # Set secure permissions
        os.chmod(auth_file, 0o600)
        log_message(3, f"Created OpenVPN auth file at {auth_file}")
        
        # Check and update OpenVPN config if it already exists
        inject_auth_into_ovpn_config(auth_file)
    except Exception as e:
        log_message(1, f"Failed to create auth file: {e}")
        sys.exit(1)
    
    # Use direct environment variables rather than env dictionary
    # This ensures variables are correctly passed to the namespace
    
    for attempt in range(1, MAX_RETRIES + 1):
        log_message(3, f"Attempting to start legacy VPN connection, attempt {attempt} of {MAX_RETRIES}.")
        log_message(4, f"Using PIA_USERNAME: {pia_user}")
        log_message(4, "Using PIA_PASSWORD: [REDACTED]")

        try:
            # Create command with explicit environment variables and auth file
            cmd = [
                "sudo", "ip", "netns", "exec", VPN_NS, 
                "env",
                f"VPN_PROTOCOL=openvpn_udp_standard",
                f"DISABLE_IPV6=yes",
                f"DIP_TOKEN=no",
                f"MAX_LATENCY=.1",
                f"AUTOCONNECT=true",
                f"PIA_PF=true",
                f"PIA_DNS=true",
                f"PIA_USER={pia_user}",
                f"PIA_PASS={pia_pass}",
                f"OVPN_AUTH_FILE={auth_file}", # Pass auth file path to PIA script
                str(PIA_CONN_SCRIPT)
            ]
            
            # Create sanitized log version that doesn't show password
            cmd_str_log = ' '.join(cmd[:-3]) + f" PIA_USER={pia_user} PIA_PASS=[REDACTED] {cmd[-1]}"
            log_message(5, f"Running legacy VPN script: {cmd_str_log}")

            # Ensure OpenVPN config exists and has auth directive before starting process
            ovpn_config = "/opt/piavpn-manual/pia.ovpn"
            if os.path.exists(ovpn_config):
                log_message(3, "OpenVPN config exists, ensuring auth directive is present...")
                inject_auth_into_ovpn_config(auth_file)
            
            # Use subprocess.Popen with proper detachment and log file
            vpn_log_file = LOGS_DIR / "vpn_process.log"
            with open(vpn_log_file, "a") as vpn_log:
                VPN_PROCESS = subprocess.Popen(
                    cmd,
                    stdout=vpn_log,
                    stderr=subprocess.STDOUT,  # Redirect stderr to same log file
                    preexec_fn=os.setsid,  # Create new session ID for full detachment
                    text=True,
                    bufsize=1,  # Line buffered
                    universal_newlines=True
                )
            log_message(3, f"Legacy VPN script started (PID: {VPN_PROCESS.pid}) with output redirected to {vpn_log_file}")

            # Wait for initial setup
            time.sleep(30) # Initial wait
            port_found = False
            for check_attempt in range(1, FILE_CHECK_RETRIES + 1):
                if PORT_FILE.exists():
                    try:
                        with open(PORT_FILE, 'r') as f:
                            port_str = f.read().strip()
                            vpn_port = int(port_str) # Validate it's an integer
                        log_message(2, f"Legacy VPN connected. Port file found: using port {vpn_port}.")
                        if allow_port_ingress() == 0: # Success adding firewall rules
                           log_message(0, "Legacy VPN with port forwarding successfully connected.")
                           # Don't wait for threads to complete - let them run in background
                           return vpn_port # Success - return the port
                        else:
                            log_message(1, "Failed to configure firewall for the obtained port. Aborting this attempt.")
                            port_found = False # Treat as failure if firewall rules fail
                            break # Break inner loop
                    except ValueError:
                         log_message(1, f"Invalid content in port file '{PORT_FILE}'.")
                         port_found = False
                         break # Break inner loop
                    except Exception as e:
                         log_message(1, f"Error reading port file or setting firewall: {e}")
                         port_found = False
                         break # Break inner loop
                else:
                    log_message(3, f"Port number file not found, check attempt {check_attempt} of {FILE_CHECK_RETRIES}.")
                    if check_attempt < FILE_CHECK_RETRIES:
                        time.sleep(FILE_CHECK_DELAY)
            
            if not port_found: # If port file wasn't found or firewall failed
                 log_message(1, f"Legacy VPN connection attempt {attempt} failed (port file/firewall issue).")
                 # Terminate the background process if it's still running
                 if VPN_PROCESS and VPN_PROCESS.poll() is None:
                     log_message(3, f"Terminating legacy VPN script process (PID: {VPN_PROCESS.pid}).")
                     VPN_PROCESS.terminate()
                     try:
                         VPN_PROCESS.wait(timeout=5) # Wait briefly for termination
                     except subprocess.TimeoutExpired:
                         log_message(1, f"Legacy VPN script process (PID: {VPN_PROCESS.pid}) did not terminate gracefully, sending KILL signal.")
                         VPN_PROCESS.kill()
                     VPN_PROCESS = None
                 # Also kill stray related processes explicitly
                 terminate_processes(find_pids('port_forwarding.sh'))
                 terminate_processes(find_pids('openvpn'))

        except Exception as e:
            log_message(1, f"Error during legacy VPN connection attempt {attempt}: {e}")
            if VPN_PROCESS and VPN_PROCESS.poll() is None:
                VPN_PROCESS.terminate() # Ensure process is stopped on error
                VPN_PROCESS = None
            terminate_processes(find_pids('port_forwarding.sh'))
            terminate_processes(find_pids('openvpn'))

        # Retry delay if not the last attempt
        if attempt < MAX_RETRIES:
             log_message(3, f"Retrying legacy method after {RETRY_DELAY} seconds.")
             time.sleep(RETRY_DELAY)

    log_message(1, f"Legacy VPN connection failed after {MAX_RETRIES} attempts.")
    # Final cleanup attempt
    terminate_processes(find_pids('port_forwarding.sh'))
    terminate_processes(find_pids('openvpn'))
    # Clean up auth file
    try:
        if os.path.exists(auth_file):
            os.unlink(auth_file)
            log_message(3, f"Removed auth file {auth_file}")
    except Exception as e:
        log_message(1, f"Failed to remove auth file: {e}")
    sys.exit(1)


def disconnect_vpn_python():
    """Disconnect VPN using Python implementation."""
    log_message(3, "Disconnecting VPN using Python implementation...")
    deconstruct_vpn_and_services()
    log_message(2, "VPN disconnected successfully.")


def deconstruct_vpn_and_services():
    """Stops services, removes firewall rules, and performs complete cleanup."""
    log_message(3, "Performing complete deconstruction of services and configurations.")

    # Stop processes
    log_message(3, "Terminating running processes...")
    
    # First try to use the new Python PIA integration for clean disconnection
    if not disconnect_vpn_python():
        log_message(3, "Python disconnection failed, using legacy process termination...")
        terminate_processes(find_pids('port_forwarding.sh'))
        terminate_processes(find_pids('openvpn'))
    
    # Find transmission daemon running *within the namespace*
    terminate_processes(find_pids('transmission-daemon')) 

    # Remove firewall rules (order might matter depending on dependencies)
    log_message(3, "Removing firewall rules...")
    remove_rules_by_comment("inet", "filter", "input", "inbound-vpn-rule")
    remove_rules_by_comment("inet", "filter", "forward", "wan-to-vpn-traffic-port")
    remove_rules_by_comment("inet", "filter", "forward", "lan-to-vpn-traffic-port")
    remove_rules_by_comment("inet", "filter", "forward", "vpn-to-lan-traffic-port")
    remove_rules_by_comment("ip", "nat", "postrouting", "nat-masquerade-vpn")
    remove_rules_by_comment("inet", "filter", "forward", "outbound-vpn-traffic")

    # Remove the port file
    if PORT_FILE.exists():
        log_message(3, "Removing port number file.")
        try:
            run_command(f"sudo rm {PORT_FILE}", check=False) # Use sudo to remove if needed
            log_message(2, "Port number file removed.")
        except Exception as e:
             log_message(1, f"Warning: Failed to remove port file {PORT_FILE}: {e}")
    
    # Clean up auth file if it exists
    auth_file = f"{RAMDISK_MNT}/openvpn_auth.txt"
    if os.path.exists(auth_file):
        try:
            os.unlink(auth_file)
            log_message(3, f"Removed auth file {auth_file}")
        except Exception as e:
            log_message(1, f"Warning: Failed to remove auth file {auth_file}: {e}")

    # No bind mounts to clean up - using shared filesystem access
    log_message(3, "No bind mounts to clean up - using shared filesystem access")

    # Remove tun device in namespace if it exists
    try:
        log_message(3, "Removing tun device in namespace...")
        run_command(f"ip netns exec {VPN_NS} ip link delete tun06", sudo=True, check=False)
        log_message(2, "Removed tun device in namespace.")
    except Exception as e:
        log_message(1, f"Warning: Failed to remove tun device: {e}")

    # Bring down veth pair interfaces if they exist
    try:
        log_message(3, "Bringing down veth interfaces...")
        run_command(f"ip link set {VPN_IF} down", sudo=True, check=False)
        run_command(f"ip netns exec {VPN_NS} ip link set {VPN_PEER_IF} down", sudo=True, check=False)
        log_message(2, "Interfaces brought down.")
    except Exception as e:
        log_message(1, f"Warning: Failed to bring down veth interfaces: {e}")

    # Delete veth pair
    try:
        log_message(3, "Removing veth pair...")
        run_command(f"ip link delete {VPN_IF}", sudo=True, check=False)
        log_message(2, "Removed veth pair.")
    except Exception as e:
        log_message(1, f"Warning: Failed to remove veth pair: {e}")

    # Remove network namespace
    try:
        log_message(3, f"Removing network namespace '{VPN_NS}'...")
        run_command(f"ip netns delete {VPN_NS}", sudo=True, check=False)
        log_message(2, f"Removed network namespace '{VPN_NS}'.")
    except Exception as e:
        log_message(1, f"Warning: Failed to remove network namespace: {e}")

    log_message(0, "Complete deconstruction of services, network configuration, and firewall rules completed.")


def get_vpn_port():
    """Returns the current VPN port."""
    return vpn_port


def set_vpn_port(port):
    """Sets the VPN port."""
    global vpn_port
    vpn_port = port
