#!/usr/bin/env python3

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
from .config import get_network_config

# --- Configuration ---
RAMDISK_MNT = Path("/mnt/ramdisk")
PORT_FILE = Path("/tmp/port.pid")

# Network configuration
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
    network_config = get_network_config()
    try:
        log_message(3, f"Allowing traffic from {network_config.lan_interface} to {VPN_IF} on port {port}.")
        run_command(f'nft add rule inet filter forward iifname "{LAN_IF}" oifname "{VPN_IF}" tcp dport {port} accept comment "lan-to-vpn-traffic-port"', sudo=True, shell=True)

        log_message(3, f"Allowing return traffic from {VPN_IF} to {network_config.lan_interface} on port {port}.")
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
    network_config = get_network_config()
    try:
        log_message(3, f"Adding rule to allow outbound traffic from {VPN_IF} to {network_config.wan_interface}.")
         # Check if rule exists before adding
        result = run_command("sudo nft list ruleset", capture_output=True, shell=True)
        if f'iifname "{VPN_IF}" oifname "{network_config.wan_interface}" accept comment "outbound-vpn-traffic"' not in result.stdout:
            run_command(f'nft add rule inet filter forward iifname "{VPN_IF}" oifname "{network_config.wan_interface}" accept comment "outbound-vpn-traffic"', sudo=True, shell=True)
            log_message(2, f"Added rule to allow outbound traffic from {VPN_IF} to {network_config.wan_interface}.")
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
    network_config = get_network_config()

    try:
        # Note: The logic of removing/re-adding final drop rule is complex and potentially fragile.
        # Consider alternative approaches if possible (e.g., inserting rule at specific position).
        # For direct translation, we'll replicate the comment-based removal/addition.

        log_message(3, "Temporarily removing final drop rule in input chain (if it exists).")
        remove_rules_by_comment('inet', 'filter', 'input', 'final-drop')

        log_message(3, f"Adding nft rule to allow inbound traffic on port {vpn_port} from {network_config.wan_interface} to host.")
        run_command(f'nft add rule inet filter input iifname "{network_config.wan_interface}" tcp dport {vpn_port} accept comment "inbound-vpn-rule"', sudo=True, shell=True)
        log_message(2, f"Successfully added rule to allow inbound traffic on port {vpn_port}.")

        log_message(3, f"Adding nft rule to forward inbound traffic on port {vpn_port} from {network_config.wan_interface} to {VPN_IF}.")
        run_command(f'nft add rule inet filter forward iifname "{network_config.wan_interface}" oifname "{VPN_IF}" tcp dport {vpn_port} accept comment "wan-to-vpn-traffic-port"', sudo=True, shell=True)
        log_message(2, f"Successfully added forwarding rule from {network_config.wan_interface} to {VPN_IF} on port {vpn_port}.")

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
        log_message(1, "PIA Python integration is required; no shell fallback is available.")
        sys.exit(1)

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
        log_message(1, "The Python PIA integration is required.")
        sys.exit(1)


def disconnect_vpn_python():
    """Disconnect VPN using Python implementation."""
    log_message(3, "Disconnecting VPN using Python implementation...")
    try:
        from .pia.integration import pia_cleanup_vpn
        pia_cleanup_vpn()
    except Exception as e:
        log_message(1, f"PIA Python cleanup failed: {e}")
        raise
    log_message(2, "VPN disconnected successfully.")
    return True


def deconstruct_vpn_and_services():
    """Stops services, removes firewall rules, and performs complete cleanup."""
    log_message(3, "Performing complete deconstruction of services and configurations.")

    # Stop processes
    log_message(3, "Terminating running processes...")
    
    # Disconnect through the sole supported Python PIA implementation.
    disconnect_vpn_python()
    
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
